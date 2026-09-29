#!/usr/bin/env python3
"""Train a conservative false-negative rescue layer on top of frozen reviewer v5.

The frozen adapter-v1 + reviewer-v5 policy remains authoritative for malicious
verdicts.  This experiment trains only on samples that frozen reviewer v5 would
classify benign, and may only flip those benign verdicts to malicious.  Model
selection is constrained by the *combined* system FPR, including existing v5
false positives, with per-source benign FPR checks and leave-one-source-out
stress tests for late development generations.

All inputs are development data.  A fresh disjoint corpus is required after any
candidate is frozen.
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
from train_boundary_reviewer_v5 import source_stratified_split_allow_small  # noqa: E402


def exported_probability(payload, features):
    values = []
    for row in features:
        tree_values = []
        for estimator in payload["estimators"]:
            node = 0
            left = estimator["children_left"]
            right = estimator["children_right"]
            feature = estimator["feature"]
            threshold = estimator["threshold"]
            probability = estimator["malware_probability"]
            while left[node] >= 0:
                node = left[node] if row[feature[node]] <= threshold[node] else right[node]
            tree_values.append(float(probability[node]))
        values.append(float(np.mean(tree_values)))
    return np.asarray(values, dtype=np.float64)


def frozen_v5_predictions(rows, attributes, reviewer):
    spec = {
        "feature_names": reviewer["feature_names"],
        "categories": reviewer["categories"],
    }
    features = matrix(rows, attributes, spec)
    reviewer_probability = exported_probability(reviewer, features)
    route_min = float(reviewer["route_min"])
    reviewer_threshold = float(reviewer["reviewer_threshold"])
    adapter_threshold = 0.70
    adapter_probability = np.asarray([row["adapter_probability"] for row in rows])
    routed = adapter_probability >= route_min
    prediction = adapter_probability >= adapter_threshold
    prediction[routed] = reviewer_probability[routed] >= reviewer_threshold
    return prediction, reviewer_probability, routed


def by_source(rows, predictions):
    result = {}
    for source in sorted({row["source"] for row in rows}):
        indices = [i for i, row in enumerate(rows) if row["source"] == source]
        source_rows = [rows[i] for i in indices]
        source_prediction = np.asarray([predictions[i] for i in indices], dtype=bool)
        result[source] = rates(source_rows, source_prediction)
    return result


def choose_rescue_threshold(rows, base_prediction, rescue_probability, eligible, max_fpr, min_source_benign):
    candidates = [1.0000001]
    for value in np.unique(rescue_probability[eligible]):
        candidates.extend((float(value), float(np.nextafter(value, np.inf))))
    best = None
    for threshold in candidates:
        combined = np.asarray(base_prediction, dtype=bool).copy()
        combined |= eligible & (rescue_probability >= threshold)
        result = rates(rows, combined)
        if result["fpr"] > max_fpr:
            continue
        source_result = by_source(rows, combined)
        large = [
            value for value in source_result.values()
            if value["benign"] >= min_source_benign
        ]
        if any(value["fpr"] > max_fpr for value in large):
            continue
        worst_source_fpr = max((value["fpr"] for value in large), default=0.0)
        rank = (result["tpr"], -worst_source_fpr, -result["fpr"], threshold)
        if best is None or rank > best[0]:
            best = (rank, threshold, result, source_result, worst_source_fpr, combined)
    return best


def candidate_models(seed):
    for family in ("random_forest", "extra_trees"):
        for depth in (2, 3, 4, 5):
            for leaf in (4, 8, 12, 20):
                common = dict(
                    n_estimators=192,
                    max_depth=depth,
                    min_samples_leaf=leaf,
                    max_features="sqrt",
                    random_state=seed,
                    n_jobs=-1,
                )
                if family == "random_forest":
                    model = RandomForestClassifier(class_weight="balanced_subsample", **common)
                else:
                    model = ExtraTreesClassifier(class_weight="balanced", **common)
                yield family, depth, leaf, model


def evaluate_holdout(family, depth, leaf, seed, rows, attributes, reviewer, holdout_source, max_fpr, min_source_benign):
    fit_rows = [row for row in rows if row["source"] != holdout_source]
    heldout_rows = [row for row in rows if row["source"] == holdout_source]
    train_rows, calibration_rows, _ = source_stratified_split_allow_small(fit_rows, seed, 0.20)
    wanted_rows = train_rows + calibration_rows + heldout_rows
    spec = build_feature_spec(train_rows, attributes)
    train_features_all = matrix(train_rows, attributes, spec)
    calibration_features_all = matrix(calibration_rows, attributes, spec)
    heldout_features_all = matrix(heldout_rows, attributes, spec)
    train_base, _, _ = frozen_v5_predictions(train_rows, attributes, reviewer)
    calibration_base, _, _ = frozen_v5_predictions(calibration_rows, attributes, reviewer)
    heldout_base, _, _ = frozen_v5_predictions(heldout_rows, attributes, reviewer)
    train_eligible = ~train_base
    calibration_eligible = ~calibration_base
    if class_counts([row for row, keep in zip(train_rows, train_eligible) if keep])["malicious"] < 2:
        return None
    labels = np.asarray([row["label"] for row in train_rows], dtype=np.int8)
    model = (RandomForestClassifier if family == "random_forest" else ExtraTreesClassifier)(
        n_estimators=192,
        max_depth=depth,
        min_samples_leaf=leaf,
        max_features="sqrt",
        class_weight="balanced_subsample" if family == "random_forest" else "balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(train_features_all[train_eligible], labels[train_eligible])
    calibration_probability = forest_probability(model, calibration_features_all)
    chosen = choose_rescue_threshold(
        calibration_rows, calibration_base, calibration_probability, calibration_eligible,
        max_fpr, min_source_benign,
    )
    if chosen is None:
        return None
    threshold = chosen[1]
    heldout_probability = forest_probability(model, heldout_features_all)
    heldout_combined = np.asarray(heldout_base, dtype=bool) | ((~heldout_base) & (heldout_probability >= threshold))
    return {
        "source": holdout_source,
        "threshold": threshold,
        "calibration": chosen[2],
        "heldout": rates(heldout_rows, heldout_combined),
        "heldout_by_source": by_source(heldout_rows, heldout_combined),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, action="append", type=Path)
    parser.add_argument("--location", required=True, action="append", type=Path)
    parser.add_argument("--reviewer-model", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "defender" / "defender" / "models" / "fn_rescue_v1_candidate")
    parser.add_argument("--holdout-source", action="append", default=[])
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-target-tpr", type=float, default=0.95)
    parser.add_argument("--min-source-benign", type=int, default=100)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=704)
    args = parser.parse_args()

    for path in [*args.report, *args.location, args.reviewer_model]:
        if not path.exists():
            raise SystemExit(f"required input not found: {path}")
    reviewer = json.loads(args.reviewer_model.read_text(encoding="utf-8"))
    records, source_counts = merge_reports(args.report)
    wanted = {row["sha256"] for row in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)
    train_rows, calibration_rows, split_counts = source_stratified_split_allow_small(records, args.seed, 0.20)

    spec = build_feature_spec(train_rows, attributes)
    train_features_all = matrix(train_rows, attributes, spec)
    calibration_features_all = matrix(calibration_rows, attributes, spec)
    train_base, _, _ = frozen_v5_predictions(train_rows, attributes, reviewer)
    calibration_base, _, _ = frozen_v5_predictions(calibration_rows, attributes, reviewer)
    train_eligible = ~train_base
    calibration_eligible = ~calibration_base
    train_labels = np.asarray([row["label"] for row in train_rows], dtype=np.int8)

    print("Frozen v5 training:", rates(train_rows, train_base), flush=True)
    print("Frozen v5 calibration:", rates(calibration_rows, calibration_base), flush=True)
    print("Rescue-eligible training:", class_counts([row for row, keep in zip(train_rows, train_eligible) if keep]), flush=True)

    best = None
    candidate_results = []
    for family, depth, leaf, model in candidate_models(args.seed):
        model.fit(train_features_all[train_eligible], train_labels[train_eligible])
        calibration_probability = forest_probability(model, calibration_features_all)
        chosen = choose_rescue_threshold(
            calibration_rows, calibration_base, calibration_probability, calibration_eligible,
            args.max_fpr, args.min_source_benign,
        )
        if chosen is None:
            continue
        _, threshold, calibration_result, calibration_by_source, worst_source_fpr, _ = chosen
        loso = []
        for source in args.holdout_source:
            fold = evaluate_holdout(
                family, depth, leaf, args.seed, records, attributes, reviewer, source,
                args.max_fpr, args.min_source_benign,
            )
            if fold is not None:
                loso.append(fold)
        loso_targets_met = bool(loso) and all(
            fold["heldout"]["fpr"] <= args.max_fpr and fold["heldout"]["tpr"] >= args.min_target_tpr
            for fold in loso
        )
        worst_holdout_tpr = min((fold["heldout"]["tpr"] for fold in loso), default=0.0)
        worst_holdout_fpr = max((fold["heldout"]["fpr"] for fold in loso), default=1.0)
        rank = (
            int(loso_targets_met), worst_holdout_tpr, -worst_holdout_fpr,
            calibration_result["tpr"], -worst_source_fpr, -calibration_result["fpr"],
            -depth, leaf, int(family == "random_forest"), threshold,
        )
        entry = {
            "family": family, "max_depth": depth, "min_samples_leaf": leaf,
            "threshold": threshold, "calibration": calibration_result,
            "calibration_by_source": calibration_by_source,
            "calibration_worst_source_fpr": worst_source_fpr,
            "loso_targets_met": loso_targets_met,
            "worst_holdout_tpr": worst_holdout_tpr,
            "worst_holdout_fpr": worst_holdout_fpr,
            "loso": loso,
        }
        candidate_results.append(entry)
        print(f"candidate {family} depth={depth} leaf={leaf}: cal={calibration_result} loso_tpr={worst_holdout_tpr:.3f} loso_fpr={worst_holdout_fpr:.4f}", flush=True)
        if best is None or rank > best[0]:
            best = (rank, model, entry)

    if best is None:
        raise SystemExit("no feasible rescue candidate")
    _, classifier, selected = best
    selected["training_base"] = rates(train_rows, train_base)
    selected["calibration_base"] = rates(calibration_rows, calibration_base)

    payload = {
        "format_version": 1,
        "model_type": "reviewer_v5_fn_rescue_forest",
        "threshold": selected["threshold"],
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "estimators": export_forest(classifier),
    }
    metadata = {
        "format_version": 1,
        "experiment": "reviewer_v5_fn_rescue_v1",
        "decision_policy": "frozen reviewer-v5 verdict OR rescue on v5-benign samples only",
        "max_combined_fpr": args.max_fpr,
        "min_target_tpr": args.min_target_tpr,
        "holdout_sources": args.holdout_source,
        "selected": selected,
        "candidate_results": candidate_results,
        "source_counts": source_counts,
        "split_counts": split_counts,
        "parser_failures": failures,
        "unique_samples": class_counts(records),
        "warning": "Development candidate only; freeze before fresh disjoint evaluation.",
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "model.json").write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2), flush=True)
    print(f"FN rescue candidate written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
