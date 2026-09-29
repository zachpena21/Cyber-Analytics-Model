#!/usr/bin/env python3
"""Train source-robust always-on nonlinear adapter v2.1.

Adapter v2.1 keeps the v2 feature representation but changes model selection in
response to source-shift regressions observed during development.  Candidate
thresholds must satisfy both the global benign FPR ceiling and the same ceiling
for every sufficiently large benign calibration source.  Candidate model
families are then stress-tested with leave-one-source-out (LOSO) folds chosen by
--holdout-source.  LOSO folds never use the held-out source for fitting or
threshold calibration.

All inputs to this script are development data that have already been inspected.
A fresh disjoint corpus is still required after a candidate is frozen.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import (  # noqa: E402
    build_feature_spec,
    collect_attributes,
    export_forest,
    forest_probability,
    matrix,
    rates,
)
from train_boundary_reviewer_v2 import class_counts, merge_reports  # noqa: E402
from train_boundary_reviewer_v5 import (  # noqa: E402
    source_stratified_split_allow_small,
)


def candidate_configs():
    """Yield deliberately regularized candidates in deterministic order."""
    for family in ("random_forest", "extra_trees"):
        for max_depth in (2, 3, 4, 5, 6):
            for min_leaf in (8, 12, 20, 32):
                yield family, max_depth, min_leaf


def make_classifier(family, max_depth, min_leaf, seed):
    common = dict(
        n_estimators=192,
        max_depth=max_depth,
        min_samples_leaf=min_leaf,
        max_features="sqrt",
        random_state=seed,
        n_jobs=-1,
    )
    if family == "random_forest":
        return RandomForestClassifier(
            class_weight="balanced_subsample",
            **common,
        )
    if family == "extra_trees":
        return ExtraTreesClassifier(
            class_weight="balanced",
            **common,
        )
    raise ValueError(f"unknown family {family!r}")


def probability_summary(values):
    if len(values) == 0:
        return None
    return {
        "min": float(np.min(values)),
        "p10": float(np.quantile(values, 0.10)),
        "p25": float(np.quantile(values, 0.25)),
        "p50": float(np.quantile(values, 0.50)),
        "p75": float(np.quantile(values, 0.75)),
        "p90": float(np.quantile(values, 0.90)),
        "max": float(np.max(values)),
    }


def split_probability_summary(rows, probabilities):
    labels = np.asarray([row["label"] for row in rows], dtype=np.int8)
    return {
        "benign": probability_summary(probabilities[labels == 0]),
        "malicious": probability_summary(probabilities[labels == 1]),
    }


def source_rates(rows, predictions):
    predictions = np.asarray(predictions, dtype=bool)
    grouped = {}
    for index, row in enumerate(rows):
        grouped.setdefault(row["source"], []).append(index)
    result = {}
    for source, indices in sorted(grouped.items()):
        subset_rows = [rows[index] for index in indices]
        result[source] = rates(subset_rows, predictions[indices])
    return result


def threshold_candidates(probabilities):
    values = np.unique(np.asarray(probabilities, dtype=np.float64))
    candidates = [1.0000001]
    for value in values:
        candidates.append(float(value))
        candidates.append(float(np.nextafter(value, np.inf)))
    return sorted(set(candidates))


def choose_source_constrained_threshold(
    rows,
    probabilities,
    max_fpr,
    min_source_benign,
):
    """Maximize TPR subject to global and sufficiently large source FPR caps."""
    labels = np.asarray([row["label"] for row in rows], dtype=np.int8)
    source_names = np.asarray([row["source"] for row in rows], dtype=object)
    benign = labels == 0
    constrained_sources = []
    for source in sorted(set(source_names.tolist())):
        count = int(np.count_nonzero(benign & (source_names == source)))
        if count >= min_source_benign:
            constrained_sources.append((source, count))

    best = None
    for threshold in threshold_candidates(probabilities):
        predictions = probabilities >= threshold
        overall = rates(rows, predictions)
        if overall["fpr"] > max_fpr + 1e-15:
            continue
        per_source = source_rates(rows, predictions)
        violations = []
        for source, count in constrained_sources:
            result = per_source[source]
            if result["fpr"] is not None and result["fpr"] > max_fpr + 1e-15:
                violations.append(
                    {"source": source, "benign": count, "fpr": result["fpr"]}
                )
        if violations:
            continue
        worst_source_fpr = max(
            (per_source[source]["fpr"] for source, _ in constrained_sources),
            default=0.0,
        )
        rank = (
            overall["tpr"],
            -worst_source_fpr,
            -overall["fpr"],
            threshold,
        )
        if best is None or rank > best[0]:
            best = (rank, threshold, overall, per_source, worst_source_fpr)

    if best is None:
        raise ValueError("no threshold satisfied source FPR constraints")
    _, threshold, overall, per_source, worst_source_fpr = best
    return threshold, overall, per_source, worst_source_fpr


def prepare_fold(records, heldout_source, attributes, seed, calibration_fraction):
    heldout_rows = [row for row in records if row["source"] == heldout_source]
    remaining = [row for row in records if row["source"] != heldout_source]
    if not heldout_rows:
        raise ValueError(f"holdout source not present: {heldout_source}")
    fit_rows, calibration_rows, split_counts = source_stratified_split_allow_small(
        remaining,
        seed,
        calibration_fraction,
    )
    if min(class_counts(fit_rows).values()) < 5:
        raise ValueError(f"LOSO fit class too small for {heldout_source}")
    if min(class_counts(calibration_rows).values()) < 5:
        raise ValueError(f"LOSO calibration class too small for {heldout_source}")
    spec = build_feature_spec(fit_rows, attributes)
    return {
        "source": heldout_source,
        "fit_rows": fit_rows,
        "calibration_rows": calibration_rows,
        "heldout_rows": heldout_rows,
        "split_counts": split_counts,
        "spec": spec,
        "fit_features": matrix(fit_rows, attributes, spec),
        "calibration_features": matrix(calibration_rows, attributes, spec),
        "heldout_features": matrix(heldout_rows, attributes, spec),
        "fit_labels": np.asarray([row["label"] for row in fit_rows], dtype=np.int8),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, action="append", type=Path)
    parser.add_argument("--location", required=True, action="append", type=Path)
    parser.add_argument("--holdout-source", action="append", default=[])
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "defender"
            / "defender"
            / "models"
            / "modern_adapter_v2_1_candidate"
        ),
    )
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-tpr", type=float, default=0.95)
    parser.add_argument("--min-source-benign", type=int, default=100)
    parser.add_argument("--calibration-fraction", type=float, default=0.20)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=704)
    args = parser.parse_args()

    if not 0.0 <= args.max_fpr <= 1.0:
        raise SystemExit("--max-fpr must be between zero and one")
    if not 0.0 <= args.min_tpr <= 1.0:
        raise SystemExit("--min-tpr must be between zero and one")
    if args.min_source_benign < 1:
        raise SystemExit("--min-source-benign must be positive")
    if not 0.05 <= args.calibration_fraction <= 0.50:
        raise SystemExit("--calibration-fraction must be between 0.05 and 0.50")
    for path in [*args.report, *args.location]:
        if not path.exists():
            raise SystemExit(f"required input not found: {path}")

    records, source_counts = merge_reports(args.report)
    train_rows, calibration_rows, split_counts = source_stratified_split_allow_small(
        records,
        args.seed,
        args.calibration_fraction,
    )
    print(
        "Adapter v2.1 source-stratified rows: "
        f"train={class_counts(train_rows)}; calibration={class_counts(calibration_rows)}",
        flush=True,
    )

    wanted = {row["sha256"] for row in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    spec = build_feature_spec(train_rows, attributes)
    train_features = matrix(train_rows, attributes, spec)
    calibration_features = matrix(calibration_rows, attributes, spec)
    train_labels = np.asarray([row["label"] for row in train_rows], dtype=np.int8)

    folds = []
    for offset, source in enumerate(args.holdout_source):
        fold = prepare_fold(
            records,
            source,
            attributes,
            args.seed + 1000 + offset,
            args.calibration_fraction,
        )
        folds.append(fold)
        print(
            f"Prepared LOSO {source}: fit={class_counts(fold['fit_rows'])}; "
            f"cal={class_counts(fold['calibration_rows'])}; "
            f"heldout={class_counts(fold['heldout_rows'])}",
            flush=True,
        )

    best = None
    candidate_results = []
    for family, max_depth, min_leaf in candidate_configs():
        classifier = make_classifier(family, max_depth, min_leaf, args.seed)
        classifier.fit(train_features, train_labels)
        calibration_probability = forest_probability(classifier, calibration_features)
        (
            threshold,
            calibration_result,
            calibration_by_source,
            worst_source_fpr,
        ) = choose_source_constrained_threshold(
            calibration_rows,
            calibration_probability,
            args.max_fpr,
            args.min_source_benign,
        )

        loso_results = []
        for offset, fold in enumerate(folds):
            fold_classifier = make_classifier(
                family,
                max_depth,
                min_leaf,
                args.seed + 2000 + offset,
            )
            fold_classifier.fit(fold["fit_features"], fold["fit_labels"])
            fold_cal_probability = forest_probability(
                fold_classifier,
                fold["calibration_features"],
            )
            (
                fold_threshold,
                fold_cal_result,
                fold_cal_by_source,
                fold_worst_source_fpr,
            ) = choose_source_constrained_threshold(
                fold["calibration_rows"],
                fold_cal_probability,
                args.max_fpr,
                args.min_source_benign,
            )
            heldout_probability = forest_probability(
                fold_classifier,
                fold["heldout_features"],
            )
            heldout_result = rates(
                fold["heldout_rows"],
                heldout_probability >= fold_threshold,
            )
            loso_results.append(
                {
                    "source": fold["source"],
                    "threshold": fold_threshold,
                    "calibration": fold_cal_result,
                    "calibration_worst_source_fpr": fold_worst_source_fpr,
                    "calibration_by_source": fold_cal_by_source,
                    "heldout": heldout_result,
                    "heldout_probability": split_probability_summary(
                        fold["heldout_rows"], heldout_probability
                    ),
                }
            )

        if loso_results:
            holdout_tprs = [
                row["heldout"]["tpr"]
                for row in loso_results
                if row["heldout"]["tpr"] is not None
            ]
            holdout_fprs = [
                row["heldout"]["fpr"]
                for row in loso_results
                if row["heldout"]["fpr"] is not None
            ]
            worst_holdout_tpr = min(holdout_tprs) if holdout_tprs else 0.0
            worst_holdout_fpr = max(holdout_fprs) if holdout_fprs else 1.0
            loso_targets_met = all(
                row["heldout"]["tpr"] is not None
                and row["heldout"]["tpr"] >= args.min_tpr
                and row["heldout"]["fpr"] is not None
                and row["heldout"]["fpr"] <= args.max_fpr
                for row in loso_results
            )
        else:
            worst_holdout_tpr = calibration_result["tpr"]
            worst_holdout_fpr = worst_source_fpr
            loso_targets_met = True

        calibration_target_met = calibration_result["tpr"] >= args.min_tpr
        family_rank = 1 if family == "random_forest" else 0
        rank = (
            int(loso_targets_met),
            worst_holdout_tpr,
            -worst_holdout_fpr,
            int(calibration_target_met),
            calibration_result["tpr"],
            -worst_source_fpr,
            -calibration_result["fpr"],
            -max_depth,
            min_leaf,
            family_rank,
        )

        row = {
            "family": family,
            "max_depth": max_depth,
            "min_samples_leaf": min_leaf,
            "threshold": threshold,
            "calibration": calibration_result,
            "calibration_worst_source_fpr": worst_source_fpr,
            "calibration_by_source": calibration_by_source,
            "loso_targets_met": loso_targets_met,
            "worst_holdout_tpr": worst_holdout_tpr,
            "worst_holdout_fpr": worst_holdout_fpr,
            "loso": loso_results,
        }
        candidate_results.append(row)
        print(
            f"candidate {family} depth={max_depth} leaf={min_leaf}: "
            f"cal_tpr={calibration_result['tpr']:.4f} "
            f"cal_fpr={calibration_result['fpr']:.4f} "
            f"worst_source_fpr={worst_source_fpr:.4f} "
            f"loso_tpr={worst_holdout_tpr:.4f} "
            f"loso_fpr={worst_holdout_fpr:.4f} "
            f"loso_targets={loso_targets_met}",
            flush=True,
        )
        if best is None or rank > best[0]:
            best = (
                rank,
                family,
                max_depth,
                min_leaf,
                classifier,
                threshold,
                calibration_result,
                calibration_by_source,
                worst_source_fpr,
                calibration_probability,
                loso_results,
                loso_targets_met,
                worst_holdout_tpr,
                worst_holdout_fpr,
            )

    if best is None:
        raise SystemExit("no adapter v2.1 candidate was trained")

    (
        _rank,
        family,
        max_depth,
        min_leaf,
        classifier,
        threshold,
        calibration_result,
        calibration_by_source,
        worst_source_fpr,
        calibration_probability,
        loso_results,
        loso_targets_met,
        worst_holdout_tpr,
        worst_holdout_fpr,
    ) = best

    training_probability = forest_probability(classifier, train_features)
    training_result = rates(train_rows, training_probability >= threshold)
    training_by_source = source_rates(train_rows, training_probability >= threshold)

    model_payload = {
        "format_version": 1,
        "model_type": "stacked_adapter_v2_forest",
        "threshold": threshold,
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "estimators": export_forest(classifier),
    }

    metadata = {
        "format_version": 1,
        "experiment": "modern_adapter_v2_1",
        "decision_policy": "always_on_stacked_nonlinear_adapter",
        "selection_policy": (
            "hard global and per-source calibration FPR constraints, then prefer "
            "LOSO target feasibility and worst-source robustness"
        ),
        "max_calibration_fpr": args.max_fpr,
        "min_target_tpr": args.min_tpr,
        "min_source_benign": args.min_source_benign,
        "holdout_sources": args.holdout_source,
        "calibration_fraction": args.calibration_fraction,
        "seed": args.seed,
        "feature_count": len(spec["feature_names"]),
        "n_estimators": len(classifier.estimators_),
        "selected": {
            "family": family,
            "max_depth": max_depth,
            "min_samples_leaf": min_leaf,
            "threshold": threshold,
            "training": training_result,
            "training_by_source": training_by_source,
            "calibration": calibration_result,
            "calibration_by_source": calibration_by_source,
            "calibration_worst_source_fpr": worst_source_fpr,
            "loso_targets_met": loso_targets_met,
            "worst_holdout_tpr": worst_holdout_tpr,
            "worst_holdout_fpr": worst_holdout_fpr,
            "loso": loso_results,
            "training_probability": split_probability_summary(
                train_rows, training_probability
            ),
            "calibration_probability": split_probability_summary(
                calibration_rows, calibration_probability
            ),
        },
        "candidate_results": candidate_results,
        "source_counts": source_counts,
        "split_counts": split_counts,
        "parser_failures": failures,
        "unique_samples": class_counts(records),
        "warning": (
            "Development candidate only. LOSO results are model-selection diagnostics "
            "on already-inspected sources, not final validation. Freeze a candidate "
            "before evaluating a new disjoint corpus."
        ),
    }

    split_manifest = {
        "training": [
            {"sha256": row["sha256"], "label": row["label"], "source": row["source"]}
            for row in train_rows
        ],
        "calibration": [
            {"sha256": row["sha256"], "label": row["label"], "source": row["source"]}
            for row in calibration_rows
        ],
        "loso_sources": args.holdout_source,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "model.json").write_text(
        json.dumps(model_payload, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (args.output / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output / "split_manifest.json").write_text(
        json.dumps(split_manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metadata["selected"], indent=2), flush=True)
    print(f"Adapter v2.1 candidate written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
