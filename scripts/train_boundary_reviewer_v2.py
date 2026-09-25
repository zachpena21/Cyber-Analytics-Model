#!/usr/bin/env python3
"""Retrain the boundary reviewer across multiple disjoint corpus generations."""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import (  # noqa: E402
    build_feature_spec,
    choose_threshold,
    collect_attributes,
    export_forest,
    forest_probability,
    matrix,
    parse_report,
    rates,
    whole_split_probabilities,
)


def merge_reports(paths):
    records = {}
    source_counts = {}
    for path in paths:
        source = Path(path).stem
        parsed = parse_report(path)
        added = 0
        duplicates = 0
        for digest, row in parsed.items():
            previous = records.get(digest)
            if previous is not None:
                comparable = {key: value for key, value in previous.items() if key != "source"}
                if comparable != row:
                    raise ValueError(
                        f"label or score conflict for {digest} between reports"
                    )
                duplicates += 1
                continue
            record = dict(row)
            record["source"] = source
            records[digest] = record
            added += 1
        source_counts[source] = {
            "rows": len(parsed),
            "unique_added": added,
            "duplicates_skipped": duplicates,
        }
    return list(records.values()), source_counts


def source_stratified_split(records, seed, calibration_fraction):
    grouped = defaultdict(list)
    for row in records:
        grouped[(row["source"], row["label"])].append(row)

    train = []
    calibration = []
    split_counts = {}
    for group_index, key in enumerate(sorted(grouped)):
        rows = sorted(grouped[key], key=lambda row: row["sha256"])
        if len(rows) < 5:
            raise ValueError(
                f"source/class group {key} is too small: {len(rows)}"
            )
        rng = np.random.RandomState(seed + group_index)
        order = np.arange(len(rows))
        rng.shuffle(order)
        calibration_count = max(1, int(round(len(rows) * calibration_fraction)))
        calibration_indices = set(order[:calibration_count].tolist())
        group_train = [row for i, row in enumerate(rows) if i not in calibration_indices]
        group_calibration = [row for i, row in enumerate(rows) if i in calibration_indices]
        train.extend(group_train)
        calibration.extend(group_calibration)
        split_counts[f"{key[0]}:label_{key[1]}"] = {
            "train": len(group_train),
            "calibration": len(group_calibration),
        }

    rng = np.random.RandomState(seed)
    rng.shuffle(train)
    rng.shuffle(calibration)
    return train, calibration, split_counts


def class_counts(rows):
    return {
        "count": len(rows),
        "benign": sum(row["label"] == 0 for row in rows),
        "malicious": sum(row["label"] == 1 for row in rows),
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
            / "boundary_reviewer_v2_candidate"
        ),
    )
    parser.add_argument("--route-min", type=float, default=0.50)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--calibration-fraction", type=float, default=0.20)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=704)
    args = parser.parse_args()

    if not 0.0 <= args.route_min <= 1.0:
        raise SystemExit("--route-min must be between zero and one")
    if not 0.0 <= args.max_fpr <= 1.0:
        raise SystemExit("--max-fpr must be between zero and one")
    if not 0.05 <= args.calibration_fraction <= 0.50:
        raise SystemExit("--calibration-fraction must be between 0.05 and 0.50")
    for path in [*args.report, *args.location]:
        if not path.exists():
            raise SystemExit(f"required input not found: {path}")

    records, source_counts = merge_reports(args.report)
    train_rows, calibration_rows, split_counts = source_stratified_split(
        records, args.seed, args.calibration_fraction
    )
    routed_train = [
        row for row in train_rows if row["adapter_probability"] >= args.route_min
    ]
    routed_calibration = [
        row
        for row in calibration_rows
        if row["adapter_probability"] >= args.route_min
    ]
    print(
        "Source-stratified rows: "
        f"train={class_counts(train_rows)} routed={class_counts(routed_train)}; "
        f"calibration={class_counts(calibration_rows)} "
        f"routed={class_counts(routed_calibration)}",
        flush=True,
    )
    for name, rows in (
        ("training", routed_train),
        ("calibration", routed_calibration),
    ):
        counts = class_counts(rows)
        if min(counts["benign"], counts["malicious"]) < 10:
            raise SystemExit(f"{name} routed class is too small: {counts}")

    wanted = {row["sha256"] for row in routed_train + routed_calibration}
    attributes, failures = collect_attributes(
        args.location, wanted, args.max_bytes
    )
    spec = build_feature_spec(routed_train, attributes)
    train_features = matrix(routed_train, attributes, spec)
    calibration_features = matrix(routed_calibration, attributes, spec)
    train_labels = np.asarray(
        [row["label"] for row in routed_train], dtype=np.int8
    )

    best = None
    for max_depth in (2, 3, 4, 5, 6):
        for min_leaf in (2, 4, 6, 10):
            classifier = RandomForestClassifier(
                n_estimators=192,
                max_depth=max_depth,
                min_samples_leaf=min_leaf,
                max_features="sqrt",
                class_weight="balanced_subsample",
                random_state=args.seed,
                n_jobs=-1,
            )
            classifier.fit(train_features, train_labels)
            routed_probability = forest_probability(
                classifier, calibration_features
            )
            probabilities = whole_split_probabilities(
                calibration_rows, routed_calibration, routed_probability
            )
            threshold, result = choose_threshold(
                calibration_rows, probabilities, args.max_fpr
            )
            rank = (
                result["tpr"],
                -result["fpr"],
                -max_depth,
                min_leaf,
                threshold,
            )
            if best is None or rank > best[0]:
                best = (
                    rank,
                    classifier,
                    threshold,
                    result,
                    max_depth,
                    min_leaf,
                )

    (
        _rank,
        classifier,
        threshold,
        calibration_result,
        max_depth,
        min_leaf,
    ) = best
    train_probability = whole_split_probabilities(
        train_rows,
        routed_train,
        forest_probability(classifier, train_features),
    )
    train_result = rates(train_rows, train_probability >= threshold)
    adapter_calibration = rates(
        calibration_rows,
        [row["adapter_probability"] >= 0.70 for row in calibration_rows],
    )

    args.output.mkdir(parents=True, exist_ok=True)
    model = {
        "format_version": 1,
        "route_min": args.route_min,
        "reviewer_threshold": threshold,
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "estimators": export_forest(classifier),
    }
    metadata = {
        "warning": (
            "Candidate trained after the 2026-09-25 distribution-shift batch. "
            "Do not enable by default until evaluated on later disjoint data."
        ),
        "format_version": 2,
        "seed": args.seed,
        "route_min": args.route_min,
        "reviewer_threshold": threshold,
        "max_calibration_fpr": args.max_fpr,
        "calibration_fraction_per_source_class": args.calibration_fraction,
        "classifier": "RandomForestClassifier",
        "n_estimators": len(classifier.estimators_),
        "max_depth": max_depth,
        "min_samples_leaf": min_leaf,
        "feature_count": len(spec["feature_names"]),
        "unique_samples": class_counts(records),
        "training": train_result,
        "calibration": calibration_result,
        "adapter_calibration_at_0.70": adapter_calibration,
        "source_reports": source_counts,
        "split_counts": split_counts,
        "routed_counts": {
            "training": class_counts(routed_train),
            "calibration": class_counts(routed_calibration),
        },
        "parser_failures": failures,
    }
    manifest = {
        "training": [row["sha256"] for row in train_rows],
        "calibration": [row["sha256"] for row in calibration_rows],
        "training_routed": [row["sha256"] for row in routed_train],
        "calibration_routed": [row["sha256"] for row in routed_calibration],
    }
    for filename, payload in (
        ("model.json", model),
        ("metadata.json", metadata),
        ("split_manifest.json", manifest),
    ):
        with (args.output / filename).open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(f"Candidate reviewer v2 written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
