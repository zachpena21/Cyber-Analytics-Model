#!/usr/bin/env python3
"""Train an always-on nonlinear adapter v2 on accumulated development data.

Adapter v2 is intentionally separate from the frozen production stack.  It
uses the existing legacy/base scores and adapter-v1 score together with the
same compact structural PE features that proved useful in the boundary
reviewer, but it has no routing gate: every sample receives one final v2
probability.  The goal is to test whether an explicitly stacked nonlinear
adapter can replace the increasingly broad reviewer-routing policy.

This script consumes only development reports that have already been inspected.
A new disjoint corpus is still required after a candidate is frozen.
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
    choose_threshold,
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


def candidate_models(seed):
    """Yield compact nonlinear candidates in deterministic order."""
    for family in ("random_forest", "extra_trees"):
        for max_depth in (3, 4, 5, 6, 8):
            for min_leaf in (2, 4, 8, 12):
                common = dict(
                    n_estimators=256,
                    max_depth=max_depth,
                    min_samples_leaf=min_leaf,
                    max_features="sqrt",
                    random_state=seed,
                    n_jobs=-1,
                )
                if family == "random_forest":
                    model = RandomForestClassifier(
                        class_weight="balanced_subsample",
                        **common,
                    )
                else:
                    model = ExtraTreesClassifier(
                        class_weight="balanced",
                        **common,
                    )
                yield family, max_depth, min_leaf, model


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, action="append", type=Path)
    parser.add_argument("--location", required=True, action="append", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "defender"
            / "defender"
            / "models"
            / "modern_adapter_v2_candidate"
        ),
    )
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--calibration-fraction", type=float, default=0.20)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=704)
    args = parser.parse_args()

    if not 0.0 <= args.max_fpr <= 1.0:
        raise SystemExit("--max-fpr must be between zero and one")
    if not 0.05 <= args.calibration_fraction <= 0.50:
        raise SystemExit("--calibration-fraction must be between 0.05 and 0.50")
    for path in [*args.report, *args.location]:
        if not path.exists():
            raise SystemExit(f"required input not found: {path}")

    records, source_counts = merge_reports(args.report)
    train_rows, calibration_rows, split_counts = (
        source_stratified_split_allow_small(
            records,
            args.seed,
            args.calibration_fraction,
        )
    )

    print(
        "Adapter v2 source-stratified rows: "
        f"train={class_counts(train_rows)}; "
        f"calibration={class_counts(calibration_rows)}",
        flush=True,
    )
    for name, rows in (("training", train_rows), ("calibration", calibration_rows)):
        counts = class_counts(rows)
        if min(counts["benign"], counts["malicious"]) < 5:
            raise SystemExit(f"{name} class is too small: {counts}")

    wanted = {row["sha256"] for row in train_rows + calibration_rows}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    # Build categories only from the fitting split.  Calibration-only category
    # values therefore become all-zero one-hot values rather than leaking into
    # the fitted representation.
    spec = build_feature_spec(train_rows, attributes)
    train_features = matrix(train_rows, attributes, spec)
    calibration_features = matrix(calibration_rows, attributes, spec)
    train_labels = np.asarray([row["label"] for row in train_rows], dtype=np.int8)

    best = None
    candidate_results = []
    for family, max_depth, min_leaf, classifier in candidate_models(args.seed):
        classifier.fit(train_features, train_labels)
        calibration_probability = forest_probability(
            classifier,
            calibration_features,
        )
        threshold, calibration_result = choose_threshold(
            calibration_rows,
            calibration_probability,
            args.max_fpr,
        )

        # Prefer recall under the hard FPR ceiling, then lower FPR, then the
        # simpler model.  RF wins exact ties over ExtraTrees to preserve the
        # more conservative split behavior used by the existing reviewer.
        family_rank = 1 if family == "random_forest" else 0
        rank = (
            calibration_result["tpr"],
            -calibration_result["fpr"],
            -max_depth,
            min_leaf,
            family_rank,
            threshold,
        )
        candidate_results.append(
            {
                "family": family,
                "max_depth": max_depth,
                "min_samples_leaf": min_leaf,
                "threshold": threshold,
                "calibration": calibration_result,
            }
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
                calibration_probability,
            )

    if best is None:
        raise SystemExit("no adapter v2 candidate was trained")

    (
        _rank,
        family,
        max_depth,
        min_leaf,
        classifier,
        threshold,
        calibration_result,
        calibration_probability,
    ) = best

    training_probability = forest_probability(classifier, train_features)
    training_result = rates(train_rows, training_probability >= threshold)

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
        "experiment": "modern_adapter_v2",
        "decision_policy": "always_on_stacked_nonlinear_adapter",
        "upstream_features": [
            "legacy benign probability",
            "adapter-v1 probability",
            "legacy raw/adjusted trigger",
            "signature state",
            "structural PE features",
        ],
        "selection_policy": (
            "maximize source-stratified calibration TPR under max FPR, "
            "then lower FPR, then simpler forest"
        ),
        "max_calibration_fpr": args.max_fpr,
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
            "calibration": calibration_result,
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
            "Development candidate only. The reports used here have already "
            "been inspected; freeze a candidate before evaluating a new "
            "disjoint corpus."
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

    print(json.dumps(metadata, indent=2), flush=True)
    print(f"Adapter v2 candidate written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
