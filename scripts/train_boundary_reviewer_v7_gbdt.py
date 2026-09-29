#!/usr/bin/env python3
"""Train a development-only gradient-boosted reviewer using the v6.1 feature set.

This is a model-family feasibility experiment. It keeps the v6.1 source-stratified
split, routing search, source-constrained calibration thresholding, and v9/v10 LOSO
checks, but replaces the shallow random/extra forest reviewer with sklearn's
GradientBoostingClassifier. No runtime integration or final-evaluation claim is made
from this script.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import (  # noqa: E402
    collect_attributes,
    rates,
    whole_split_probabilities,
)
from train_boundary_reviewer_v2 import class_counts, merge_reports  # noqa: E402
from train_boundary_reviewer_v5 import source_stratified_split_allow_small  # noqa: E402
from train_boundary_reviewer_v6_1 import (  # noqa: E402
    DERIVED_FEATURES,
    build_feature_spec,
    matrix,
    prepare_routed,
)
from train_modern_adapter_v2_1 import choose_source_constrained_threshold  # noqa: E402


def route_candidates(values):
    routes = sorted({float(v) for v in values})
    if not routes or any(v < 0.0 or v > 1.0 for v in routes):
        raise ValueError("route candidates must be in [0,1]")
    return routes


def model_configs():
    # Deliberately compact search: enough capacity to test whether boosting changes
    # the bias/variance tradeoff without turning v9/v10 into a hyperparameter target.
    for n_estimators in (64, 128):
        for learning_rate in (0.03, 0.06, 0.10):
            for max_depth in (1, 2, 3):
                for min_samples_leaf in (8, 16):
                    yield {
                        "n_estimators": n_estimators,
                        "learning_rate": learning_rate,
                        "max_depth": max_depth,
                        "min_samples_leaf": min_samples_leaf,
                    }


def make_classifier(config, seed):
    return GradientBoostingClassifier(
        n_estimators=config["n_estimators"],
        learning_rate=config["learning_rate"],
        max_depth=config["max_depth"],
        min_samples_leaf=config["min_samples_leaf"],
        max_features="sqrt",
        subsample=1.0,
        random_state=seed,
    )


def fit_and_score(config, seed, fit_rows, eval_rows, attributes, route_min):
    routed_fit = prepare_routed(fit_rows, route_min)
    routed_eval = prepare_routed(eval_rows, route_min)
    counts = class_counts(routed_fit)
    if counts["benign"] < 10 or counts["malicious"] < 10:
        return None

    spec = build_feature_spec(routed_fit, attributes)
    Xfit = matrix(routed_fit, attributes, spec)
    yfit = np.asarray([row["label"] for row in routed_fit], dtype=np.int8)
    clf = make_classifier(config, seed)
    sample_weight = compute_sample_weight(class_weight="balanced", y=yfit)
    clf.fit(Xfit, yfit, sample_weight=sample_weight)

    if routed_eval:
        probs_routed = clf.predict_proba(matrix(routed_eval, attributes, spec))[:, 1]
    else:
        probs_routed = np.asarray([], dtype=np.float64)
    probs_all = whole_split_probabilities(eval_rows, routed_eval, probs_routed)
    return clf, spec, routed_fit, routed_eval, probs_all


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, action="append", type=Path)
    ap.add_argument("--location", required=True, action="append", type=Path)
    ap.add_argument("--holdout-source", action="append", default=[])
    ap.add_argument("--route-candidate", action="append", default=None)
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--min-tpr", type=float, default=0.95)
    ap.add_argument("--min-source-benign", type=int, default=100)
    ap.add_argument("--calibration-fraction", type=float, default=0.20)
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--seed", type=int, default=704)
    ap.add_argument(
        "--output",
        type=Path,
        default=ROOT / "defender" / "defender" / "models" / "boundary_reviewer_v7_gbdt_candidate",
    )
    args = ap.parse_args()

    routes = route_candidates(args.route_candidate or ["0.15", "0.20", "0.25", "0.30"])
    for path in [*args.report, *args.location]:
        if not path.exists():
            raise SystemExit(f"required input not found: {path}")

    records, source_counts = merge_reports(args.report)
    train_rows, cal_rows, split_counts = source_stratified_split_allow_small(
        records, args.seed, args.calibration_fraction
    )
    print(f"Reviewer v7 GBDT rows: train={class_counts(train_rows)} cal={class_counts(cal_rows)}", flush=True)

    wanted = {row["sha256"] for row in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    folds = []
    for i, source in enumerate(args.holdout_source):
        heldout = [r for r in records if r["source"] == source]
        remaining = [r for r in records if r["source"] != source]
        fit, cal, counts = source_stratified_split_allow_small(
            remaining, args.seed + 1000 + i, args.calibration_fraction
        )
        folds.append((source, fit, cal, heldout, counts))
        print(
            f"LOSO {source}: fit={class_counts(fit)} cal={class_counts(cal)} heldout={class_counts(heldout)}",
            flush=True,
        )

    best = None
    results = []
    for route in routes:
        for config in model_configs():
            fitted = fit_and_score(config, args.seed, train_rows, cal_rows, attributes, route)
            if fitted is None:
                continue
            clf, spec, routed_train, routed_cal, cal_probs = fitted
            try:
                threshold, cal_result, cal_by_source, worst_source_fpr = choose_source_constrained_threshold(
                    cal_rows, cal_probs, args.max_fpr, args.min_source_benign
                )
            except ValueError:
                continue

            loso = []
            for i, (source, fold_fit, fold_cal, heldout, fold_counts) in enumerate(folds):
                fold_fitted = fit_and_score(
                    config,
                    args.seed + 2000 + i,
                    fold_fit,
                    fold_cal,
                    attributes,
                    route,
                )
                if fold_fitted is None:
                    loso.append({"source": source, "invalid": True})
                    continue
                fold_clf, fold_spec, _, _, fold_cal_probs = fold_fitted
                try:
                    fold_threshold, fold_cal_result, fold_cal_by_source, fold_worst = choose_source_constrained_threshold(
                        fold_cal, fold_cal_probs, args.max_fpr, args.min_source_benign
                    )
                except ValueError:
                    loso.append({"source": source, "invalid": True})
                    continue

                routed_holdout = prepare_routed(heldout, route)
                if routed_holdout:
                    hp = fold_clf.predict_proba(matrix(routed_holdout, attributes, fold_spec))[:, 1]
                else:
                    hp = np.asarray([], dtype=np.float64)
                heldout_probs = whole_split_probabilities(heldout, routed_holdout, hp)
                heldout_result = rates(heldout, heldout_probs >= fold_threshold)
                loso.append({
                    "source": source,
                    "threshold": fold_threshold,
                    "calibration": fold_cal_result,
                    "calibration_worst_source_fpr": fold_worst,
                    "heldout": heldout_result,
                    "routed_heldout": class_counts(routed_holdout),
                })

            valid_loso = [x for x in loso if not x.get("invalid")]
            loso_targets = bool(valid_loso) and len(valid_loso) == len(folds) and all(
                x["heldout"]["tpr"] is not None
                and x["heldout"]["tpr"] >= args.min_tpr
                and x["heldout"]["fpr"] is not None
                and x["heldout"]["fpr"] <= args.max_fpr
                for x in valid_loso
            )
            worst_tpr = min(
                (x["heldout"]["tpr"] for x in valid_loso if x["heldout"]["tpr"] is not None),
                default=0.0,
            )
            worst_fpr = max(
                (x["heldout"]["fpr"] for x in valid_loso if x["heldout"]["fpr"] is not None),
                default=1.0,
            )
            cal_target = cal_result["tpr"] >= args.min_tpr

            # Robustness first; then calibration quality; then prefer smaller models.
            rank = (
                int(loso_targets),
                worst_tpr,
                -worst_fpr,
                int(cal_target),
                cal_result["tpr"],
                -worst_source_fpr,
                -cal_result["fpr"],
                -config["max_depth"],
                -config["n_estimators"],
                -config["learning_rate"],
                config["min_samples_leaf"],
                -route,
            )

            row = {
                "route_min": route,
                "family": "gradient_boosting",
                **config,
                "reviewer_threshold": threshold,
                "calibration": cal_result,
                "calibration_worst_source_fpr": worst_source_fpr,
                "calibration_by_source": cal_by_source,
                "loso_targets_met": loso_targets,
                "worst_holdout_tpr": worst_tpr,
                "worst_holdout_fpr": worst_fpr,
                "loso": loso,
                "routed_counts": {
                    "training": class_counts(routed_train),
                    "calibration": class_counts(routed_cal),
                },
            }
            results.append(row)
            print(
                "route={route:.2f} GBDT n={n_estimators} lr={learning_rate:.2f} "
                "depth={max_depth} leaf={min_samples_leaf}: cal_tpr={cal_tpr:.4f} "
                "cal_fpr={cal_fpr:.4f} worst_src_fpr={worst_src:.4f} "
                "loso_tpr={loso_tpr:.4f} loso_fpr={loso_fpr:.4f} targets={targets}".format(
                    route=route,
                    n_estimators=config["n_estimators"],
                    learning_rate=config["learning_rate"],
                    max_depth=config["max_depth"],
                    min_samples_leaf=config["min_samples_leaf"],
                    cal_tpr=cal_result["tpr"],
                    cal_fpr=cal_result["fpr"],
                    worst_src=worst_source_fpr,
                    loso_tpr=worst_tpr,
                    loso_fpr=worst_fpr,
                    targets=loso_targets,
                ),
                flush=True,
            )
            if best is None or rank > best[0]:
                best = (rank, clf, spec, row)

    if best is None:
        raise SystemExit("no reviewer v7 GBDT candidate was trained")

    _, clf, spec, selected = best
    train_routed = prepare_routed(train_rows, selected["route_min"])
    train_probs_routed = clf.predict_proba(matrix(train_routed, attributes, spec))[:, 1]
    train_probs = whole_split_probabilities(train_rows, train_routed, train_probs_routed)
    training_result = rates(train_rows, train_probs >= selected["reviewer_threshold"])

    metadata = {
        "format_version": 1,
        "experiment": "boundary_reviewer_v7_gbdt",
        "warning": "Development model-family feasibility only; no runtime exporter/integration has been implemented.",
        "selection_policy": "v6.1 features plus source-constrained calibration and v9/v10 LOSO robustness, using GradientBoostingClassifier",
        "max_calibration_fpr": args.max_fpr,
        "min_tpr": args.min_tpr,
        "route_candidates": routes,
        "derived_features": list(DERIVED_FEATURES),
        "feature_count": len(spec["feature_names"]),
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "source_reports": source_counts,
        "split_counts": split_counts,
        "parser_failures": failures,
        "training": training_result,
        "selected": selected,
        "all_candidates": results,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("SELECTED")
    print(json.dumps(selected, indent=2, sort_keys=True))
    print("TRAINING")
    print(json.dumps(training_result, indent=2, sort_keys=True))
    print(f"wrote {args.output / 'metadata.json'}")


if __name__ == "__main__":
    main()
