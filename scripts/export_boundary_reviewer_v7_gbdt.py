#!/usr/bin/env python3
"""Re-fit and export the selected reviewer-v7 GBDT with runtime parity checks."""

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
from sklearn.utils.class_weight import compute_sample_weight

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import collect_attributes  # noqa: E402
from train_boundary_reviewer_v2 import merge_reports  # noqa: E402
from train_boundary_reviewer_v5 import source_stratified_split_allow_small  # noqa: E402
from train_boundary_reviewer_v6_1 import build_feature_spec, matrix, prepare_routed  # noqa: E402
from train_boundary_reviewer_v7_gbdt import make_classifier  # noqa: E402


def export_tree(estimator):
    tree = estimator.tree_
    return {
        "children_left": tree.children_left.astype(int).tolist(),
        "children_right": tree.children_right.astype(int).tolist(),
        "feature": tree.feature.astype(int).tolist(),
        "threshold": tree.threshold.astype(float).tolist(),
        "raw_value": tree.value[:, 0, 0].astype(float).tolist(),
    }


def exported_tree_value(tree, vector):
    node = 0
    while tree["children_left"][node] >= 0:
        feature = tree["feature"][node]
        node = (
            tree["children_left"][node]
            if vector[feature] <= tree["threshold"][node]
            else tree["children_right"][node]
        )
    return float(tree["raw_value"][node])


def sigmoid(raw):
    if raw >= 0.0:
        z = math.exp(-raw)
        return 1.0 / (1.0 + z)
    z = math.exp(raw)
    return z / (1.0 + z)


def exported_probabilities(payload, X):
    out = []
    for vector in X:
        raw = payload["initial_raw_score"] + payload["learning_rate"] * sum(
            exported_tree_value(tree, vector) for tree in payload["estimators"]
        )
        out.append(sigmoid(raw))
    return np.asarray(out, dtype=np.float64)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, action="append", type=Path)
    ap.add_argument("--location", required=True, action="append", type=Path)
    ap.add_argument("--metadata", required=True, type=Path)
    ap.add_argument("--calibration-fraction", type=float, default=0.20)
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--seed", type=int, default=704)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    selected = metadata["selected"]
    config = {
        "n_estimators": int(selected["n_estimators"]),
        "learning_rate": float(selected["learning_rate"]),
        "max_depth": int(selected["max_depth"]),
        "min_samples_leaf": int(selected["min_samples_leaf"]),
    }
    route_min = float(selected["route_min"])
    reviewer_threshold = float(selected["reviewer_threshold"])

    records, _ = merge_reports(args.report)
    train_rows, cal_rows, _ = source_stratified_split_allow_small(
        records, args.seed, args.calibration_fraction
    )
    wanted = {row["sha256"] for row in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)
    if failures:
        raise SystemExit(f"parser failures prevent deterministic export: {failures}")

    routed_train = prepare_routed(train_rows, route_min)
    spec = build_feature_spec(routed_train, attributes)
    Xtrain = matrix(routed_train, attributes, spec)
    ytrain = np.asarray([row["label"] for row in routed_train], dtype=np.int8)

    clf = make_classifier(config, args.seed)
    sample_weight = compute_sample_weight(class_weight="balanced", y=ytrain)
    clf.fit(Xtrain, ytrain, sample_weight=sample_weight)

    initial_raw = float(
        clf._raw_predict_init(
            np.zeros((1, len(spec["feature_names"])), dtype=np.float64)
        )[0, 0]
    )
    payload = {
        "format_version": 6,
        "model_type": "gradient_boosting",
        "route_min": route_min,
        "reviewer_threshold": reviewer_threshold,
        "learning_rate": float(clf.learning_rate),
        "initial_raw_score": initial_raw,
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "derived_features": metadata["derived_features"],
        "estimators": [export_tree(stage[0]) for stage in clf.estimators_],
    }

    # Exact numerical parity check against sklearn on both routed train and routed cal.
    routed_cal = prepare_routed(cal_rows, route_min)
    for name, rows in (("train", routed_train), ("calibration", routed_cal)):
        if not rows:
            continue
        X = matrix(rows, attributes, spec)
        sklearn_probs = clf.predict_proba(X)[:, 1]
        exported_probs = exported_probabilities(payload, X)
        max_abs = float(np.max(np.abs(sklearn_probs - exported_probs)))
        print(f"{name} runtime parity max_abs_error={max_abs:.12g}")
        if max_abs > 1e-10:
            raise SystemExit(f"exported GBDT parity failed on {name}: {max_abs}")

    args.output.mkdir(parents=True, exist_ok=True)
    path = args.output / "model.json"
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    print(
        f"exported {len(payload['estimators'])} GBDT stages, "
        f"features={len(payload['feature_names'])}, route={route_min:.6f}, "
        f"threshold={reviewer_threshold:.6f}"
    )
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
