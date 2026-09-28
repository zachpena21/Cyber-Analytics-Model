#!/usr/bin/env python3
"""Train reviewer v5 while jointly selecting the adapter routing gate.

This keeps the legacy model and modern adapter frozen. The routing threshold,
reviewer forest hyperparameters, and reviewer decision threshold are selected on
source-stratified calibration data subject to the global FPR ceiling.
"""

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
    rates,
    whole_split_probabilities,
)
from train_boundary_reviewer_v2 import (  # noqa: E402
    class_counts,
    merge_reports,
)


def parse_route_candidates(values):
    candidates = sorted({float(value) for value in values})
    if not candidates or any(value < 0.0 or value > 1.0 for value in candidates):
        raise ValueError("route candidates must be between zero and one")
    return candidates


def source_stratified_split_allow_small(records, seed, calibration_fraction):
    """Source/class split that preserves tiny late-generation groups.

    The older splitter rejects groups smaller than five. That is useful for
    large corpora, but late MalwareBazaar generations can legitimately contain
    only a few fresh disjoint samples. For groups with 2-4 rows we reserve one
    calibration row and keep the rest for training. A singleton stays in
    training so it is not discarded from the development set.
    """
    grouped = defaultdict(list)
    for row in records:
        grouped[(row["source"], row["label"])].append(row)

    train = []
    calibration = []
    split_counts = {}
    for group_index, key in enumerate(sorted(grouped)):
        rows = sorted(grouped[key], key=lambda row: row["sha256"])
        rng = np.random.RandomState(seed + group_index)
        order = np.arange(len(rows))
        rng.shuffle(order)

        if len(rows) == 1:
            calibration_count = 0
        elif len(rows) < 5:
            calibration_count = 1
        else:
            calibration_count = max(
                1, int(round(len(rows) * calibration_fraction))
            )
            calibration_count = min(calibration_count, len(rows) - 1)

        calibration_indices = set(order[:calibration_count].tolist())
        group_train = [
            row for i, row in enumerate(rows) if i not in calibration_indices
        ]
        group_calibration = [
            row for i, row in enumerate(rows) if i in calibration_indices
        ]
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
            / "boundary_reviewer_v5_candidate"
        ),
    )
    parser.add_argument(
        "--route-candidate",
        action="append",
        default=None,
        help="candidate adapter probability routing gate; may be repeated",
    )
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--calibration-fraction", type=float, default=0.20)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=704)
    args = parser.parse_args()

    route_candidates = parse_route_candidates(
        args.route_candidate
        or ["0.20", "0.25", "0.30", "0.35", "0.40", "0.45", "0.50"]
    )
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
            records, args.seed, args.calibration_fraction
        )
    )

    # Extract once for every sample that could be routed by any candidate.
    lowest_route = min(route_candidates)
    extract_rows = [
        row
        for row in train_rows + calibration_rows
        if row["adapter_probability"] >= lowest_route
    ]
    wanted = {row["sha256"] for row in extract_rows}
    attributes, failures = collect_attributes(args.location, wanted, args.max_bytes)

    best = None
    candidate_results = []
    for route_min in route_candidates:
        routed_train = [
            row for row in train_rows if row["adapter_probability"] >= route_min
        ]
        routed_calibration = [
            row
            for row in calibration_rows
            if row["adapter_probability"] >= route_min
        ]
        train_counts = class_counts(routed_train)
        calibration_counts = class_counts(routed_calibration)
        if min(train_counts["benign"], train_counts["malicious"]) < 10:
            continue
        if min(calibration_counts["benign"], calibration_counts["malicious"]) < 5:
            continue

        spec = build_feature_spec(routed_train, attributes)
        train_features = matrix(routed_train, attributes, spec)
        calibration_features = matrix(routed_calibration, attributes, spec)
        train_labels = np.asarray(
            [row["label"] for row in routed_train], dtype=np.int8
        )

        route_best = None
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

                # All candidates considered here already satisfy max_fpr because
                # choose_threshold enforces the ceiling. Prefer calibration TPR
                # first, then preserve malware routing coverage. This prevents a
                # high route gate from winning merely because it avoids reviewing
                # difficult low-adapter malware. Among equal-coverage candidates,
                # prefer lower FPR, then the highest/smallest-scope route gate.
                routed_malware = (
                    train_counts["malicious"]
                    + calibration_counts["malicious"]
                )
                rank = (
                    result["tpr"],
                    routed_malware,
                    -result["fpr"],
                    route_min,
                    -max_depth,
                    min_leaf,
                    threshold,
                )
                if route_best is None or rank > route_best[0]:
                    route_best = (
                        rank,
                        classifier,
                        threshold,
                        result,
                        max_depth,
                        min_leaf,
                        spec,
                        routed_train,
                        routed_calibration,
                        train_features,
                    )

        if route_best is None:
            continue
        (
            rank,
            classifier,
            threshold,
            calibration_result,
            max_depth,
            min_leaf,
            spec,
            routed_train,
            routed_calibration,
            train_features,
        ) = route_best
        candidate_results.append(
            {
                "route_min": route_min,
                "reviewer_threshold": threshold,
                "max_depth": max_depth,
                "min_samples_leaf": min_leaf,
                "calibration": calibration_result,
                "routed_counts": {
                    "training": class_counts(routed_train),
                    "calibration": class_counts(routed_calibration),
                },
            }
        )
        if best is None or rank > best[0]:
            best = (
                rank,
                route_min,
                classifier,
                threshold,
                calibration_result,
                max_depth,
                min_leaf,
                spec,
                routed_train,
                routed_calibration,
                train_features,
            )

    if best is None:
        raise SystemExit("no route candidate had enough routed samples")

    (
        _rank,
        route_min,
        classifier,
        threshold,
        calibration_result,
        max_depth,
        min_leaf,
        spec,
        routed_train,
        routed_calibration,
        train_features,
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
        "route_min": route_min,
        "reviewer_threshold": threshold,
        "feature_names": spec["feature_names"],
        "categories": spec["categories"],
        "estimators": export_forest(classifier),
    }
    metadata = {
        "warning": (
            "Development candidate with jointly calibrated routing gate. "
            "Freeze before evaluation on a later disjoint corpus."
        ),
        "format_version": 3,
        "seed": args.seed,
        "selection_policy": (
            "maximize calibration TPR under max FPR, then malware routing "
            "coverage, then lower calibration FPR, then higher route gate"
        ),
        "route_min": route_min,
        "route_candidates": route_candidates,
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
        "route_candidate_results": candidate_results,
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
    print(f"Candidate reviewer v5 written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
