#!/usr/bin/env python3
"""Inspect exact v10 LOSO misses for the selected reviewer-v6.1 configuration.

Development diagnostic only. Re-fits the v10 leave-one-source-out fold using the
same deterministic split/seed/configuration as train_boundary_reviewer_v6_1.py,
then writes exact malware outcomes, feature vectors, highest-scoring benign rows,
and nearest benign neighbors in standardized feature space.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import collect_attributes, forest_probability, whole_split_probabilities  # noqa: E402
from train_boundary_reviewer_v2 import merge_reports  # noqa: E402
from train_boundary_reviewer_v5 import source_stratified_split_allow_small  # noqa: E402
from train_boundary_reviewer_v6_1 import fit_and_score, matrix, prepare_routed  # noqa: E402
from train_modern_adapter_v2_1 import choose_source_constrained_threshold  # noqa: E402


def finite(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if np.isfinite(x) else None


def robust_neighbor_index(X_benign, feature_names):
    """Return median/IQR scaling for stable nearest-neighbor comparisons."""
    median = np.median(X_benign, axis=0)
    q25 = np.percentile(X_benign, 25, axis=0)
    q75 = np.percentile(X_benign, 75, axis=0)
    scale = q75 - q25
    # Fall back to standard deviation for features with zero IQR; ignore constants.
    std = np.std(X_benign, axis=0)
    scale = np.where(scale > 1e-12, scale, std)
    active = scale > 1e-12
    scale = np.where(active, scale, 1.0)
    return median, scale, active, [feature_names[i] for i in np.flatnonzero(active)]


def nearest_benign(miss_row, miss_vec, benign_rows, benign_X, median, scale, active, feature_names, k):
    if not benign_rows:
        return []
    z_miss = (miss_vec - median) / scale
    z_benign = (benign_X - median) / scale
    delta = z_benign[:, active] - z_miss[active]
    distance = np.sqrt(np.mean(delta * delta, axis=1))
    order = np.argsort(distance)[:k]
    neighbors = []
    for idx in order:
        contribution = (z_benign[idx, active] - z_miss[active]) ** 2
        active_indices = np.flatnonzero(active)
        top = np.argsort(contribution)[::-1][:8]
        differentiators = [
            {
                "feature": feature_names[int(active_indices[j])],
                "miss_value": finite(miss_vec[int(active_indices[j])]),
                "benign_value": finite(benign_X[idx, int(active_indices[j])]),
                "squared_standardized_difference": float(contribution[j]),
            }
            for j in top
            if contribution[j] > 0
        ]
        row = benign_rows[int(idx)]
        neighbors.append({
            "sha256": row["sha256"],
            "decision_probability": row["decision_probability"],
            "adapter_probability": row["adapter_probability"],
            "reviewer_probability": row["reviewer_probability"],
            "distance": float(distance[idx]),
            "top_differentiating_features": differentiators,
        })
    return neighbors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, action="append", type=Path)
    ap.add_argument("--location", required=True, action="append", type=Path)
    ap.add_argument("--source", default="reviewer-v5-v10-diagnostic")
    ap.add_argument("--route-min", type=float, default=0.20)
    ap.add_argument("--family", default="random_forest", choices=["random_forest", "extra_trees"])
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--leaf", type=int, default=4)
    ap.add_argument("--seed", type=int, default=704)
    ap.add_argument("--fold-index", type=int, default=1,
                    help="v10 is fold index 1 when v9 then v10 are the configured holdouts")
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--min-source-benign", type=int, default=100)
    ap.add_argument("--calibration-fraction", type=float, default=0.20)
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--top-benign", type=int, default=40)
    ap.add_argument("--nearest-benign", type=int, default=10)
    ap.add_argument("--output", type=Path,
                    default=ROOT / "validation-data" / "reviewer-v6-1-v10-loso-analysis.json")
    args = ap.parse_args()

    for p in [*args.report, *args.location]:
        if not p.exists():
            raise SystemExit(f"required input not found: {p}")

    records, _ = merge_reports(args.report)
    heldout = [r for r in records if r["source"] == args.source]
    remaining = [r for r in records if r["source"] != args.source]
    if not heldout:
        raise SystemExit(f"source not present: {args.source}")

    fold_seed = args.seed + 1000 + args.fold_index
    fit_rows, cal_rows, _ = source_stratified_split_allow_small(
        remaining, fold_seed, args.calibration_fraction
    )

    wanted = {r["sha256"] for r in records}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    fitted = fit_and_score(
        args.family, args.depth, args.leaf, args.seed + 2000 + args.fold_index,
        fit_rows, cal_rows, attributes, args.route_min
    )
    if fitted is None:
        raise SystemExit("selected fold could not be fit")
    clf, spec, _, _, cal_probs = fitted
    threshold, cal_result, _, worst_source_fpr = choose_source_constrained_threshold(
        cal_rows, cal_probs, args.max_fpr, args.min_source_benign
    )

    routed_holdout = prepare_routed(heldout, args.route_min)
    routed_sha = {r["sha256"] for r in routed_holdout}
    routed_probs = (
        forest_probability(clf, matrix(routed_holdout, attributes, spec))
        if routed_holdout else np.asarray([], dtype=np.float64)
    )
    routed_prob_by_sha = {
        row["sha256"]: float(prob)
        for row, prob in zip(routed_holdout, routed_probs)
    }
    all_probs = whole_split_probabilities(heldout, routed_holdout, routed_probs)

    feature_names = spec["feature_names"]
    X_holdout = matrix(heldout, attributes, spec)

    rows = []
    vector_by_sha = {}
    for idx, (row, probability) in enumerate(zip(heldout, all_probs)):
        vec = X_holdout[idx]
        vector_by_sha[row["sha256"]] = vec
        feature_values = {name: finite(vec[j]) for j, name in enumerate(feature_names)}
        routed = row["sha256"] in routed_sha
        pred = bool(probability >= threshold)
        rows.append({
            "sha256": row["sha256"],
            "label": int(row["label"]),
            "adapter_probability": finite(row.get("adapter_probability")),
            "benign_probability": finite(row.get("benign_probability")),
            "base_trigger_raw": row.get("base_trigger_raw"),
            "base_trigger_adjusted": row.get("base_trigger_adjusted"),
            "signature_checked": row.get("signature_checked"),
            "signature_verified": row.get("signature_verified"),
            "routed": routed,
            "reviewer_probability": routed_prob_by_sha.get(row["sha256"], 0.0),
            "decision_probability": float(probability),
            "predicted_malicious": pred,
            "false_negative": bool(int(row["label"]) == 1 and not pred),
            "false_positive": bool(int(row["label"]) == 0 and pred),
            "features": feature_values,
        })

    malware = [r for r in rows if r["label"] == 1]
    malware.sort(key=lambda r: (r["predicted_malicious"], r["decision_probability"]))
    benign = [r for r in rows if r["label"] == 0]
    benign.sort(key=lambda r: r["decision_probability"], reverse=True)
    missed = [r for r in malware if r["false_negative"]]
    caught = [r for r in malware if not r["false_negative"]]

    benign_X = np.asarray([vector_by_sha[r["sha256"]] for r in benign], dtype=np.float64)
    median, scale, active, active_names = robust_neighbor_index(benign_X, feature_names)
    for miss in missed:
        miss["nearest_benign_neighbors"] = nearest_benign(
            miss,
            vector_by_sha[miss["sha256"]],
            benign,
            benign_X,
            median,
            scale,
            active,
            feature_names,
            args.nearest_benign,
        )

    def feature_summary(group):
        if not group:
            return {}
        out = {}
        for name in feature_names:
            vals = [r["features"].get(name) for r in group]
            vals = [v for v in vals if v is not None]
            if vals:
                a = np.asarray(vals, dtype=np.float64)
                out[name] = {
                    "min": float(np.min(a)),
                    "median": float(np.median(a)),
                    "max": float(np.max(a)),
                    "mean": float(np.mean(a)),
                }
        return out

    output = {
        "warning": "Development diagnostic only; v10 has already been inspected/tuned against.",
        "config": {
            "source": args.source,
            "route_min": args.route_min,
            "family": args.family,
            "depth": args.depth,
            "leaf": args.leaf,
            "fold_seed": fold_seed,
            "classifier_seed": args.seed + 2000 + args.fold_index,
            "reviewer_threshold": threshold,
            "feature_count": len(feature_names),
            "nearest_benign_metric": "RMS Euclidean distance after benign median/IQR scaling; std fallback for zero-IQR features",
            "nearest_benign_active_feature_count": int(active.sum()),
        },
        "calibration": cal_result,
        "calibration_worst_source_fpr": worst_source_fpr,
        "parser_failures": failures,
        "counts": {
            "heldout": len(heldout),
            "malware": len(malware),
            "benign": len(benign),
            "routed_malware": sum(1 for r in malware if r["routed"]),
            "false_negatives": len(missed),
            "false_positives": sum(1 for r in benign if r["false_positive"]),
        },
        "feature_names": feature_names,
        "neighbor_active_features": active_names,
        "missed_malware": missed,
        "caught_malware": caught,
        "top_benign_by_decision_probability": benign[: args.top_benign],
        "feature_summary": {
            "missed_malware": feature_summary(missed),
            "caught_malware": feature_summary(caught),
            "top_benign": feature_summary(benign[: args.top_benign]),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output["config"], indent=2, sort_keys=True))
    print(json.dumps(output["counts"], indent=2, sort_keys=True))
    print("missed malware:")
    for r in missed:
        nearest = r.get("nearest_benign_neighbors", [])
        nearest_text = f" nearest_benign_distance={nearest[0]['distance']:.4f}" if nearest else ""
        print(
            r["sha256"],
            f"adapter={r['adapter_probability']}",
            f"routed={r['routed']}",
            f"reviewer={r['reviewer_probability']:.6f}",
            f"threshold={threshold:.6f}",
            nearest_text,
        )
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
