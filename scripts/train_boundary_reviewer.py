#!/usr/bin/env python3
"""Train a compact second-stage reviewer for adapter scores at or above 0.50.

This script consumes production score reports plus the original PE collections.
It never extracts archived malware to disk.  The reviewer is deliberately kept
separate from production until a later, disjoint evaluation shows an improvement.
"""

import argparse
import csv
import hashlib
import json
import math
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier


ROOT = Path(__file__).resolve().parents[1]
DEFENDER_ROOT = ROOT / "defender"
sys.path.insert(0, str(DEFENDER_ROOT))

from defender.models.attribute_extractor import PEAttributeExtractor  # noqa: E402
from defender.models.nfs_model import NeedForSpeedModel  # noqa: E402
from test import file_bytes_generator  # noqa: E402


SCORE_FEATURES = (
    "benign_probability",
    "adapter_probability",
    "base_trigger_raw",
    "base_trigger_adjusted",
    "signature_checked",
    "signature_verified",
)
EXTRA_NUMERIC = (
    "string_paths",
    "string_urls",
    "string_registry",
    "string_MZ",
)
TEXT_FIELDS = tuple(NeedForSpeedModel.TEXTUAL_ATTRIBUTES)
CATEGORICAL_FIELDS = tuple(NeedForSpeedModel.CATEGORICAL_ATTRIBUTES)


def parse_bool(value):
    if value is None or value == "":
        return 0.0
    if isinstance(value, bool):
        return float(value)
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return 1.0
    if normalized in {"0", "false", "no", "off", "none", "null"}:
        return 0.0
    raise ValueError(f"invalid boolean value {value!r}")


def parse_report(path):
    required = {
        "sha256",
        "label",
        "benign_probability",
        "adapter_probability",
        "base_trigger_raw",
        "base_trigger_adjusted",
        "signature_checked",
        "signature_verified",
    }
    records = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"{path} is missing columns: {', '.join(sorted(missing))}"
            )
        for row in reader:
            digest = row["sha256"].strip().casefold()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"invalid SHA-256 in {path}: {digest!r}")
            label = int(row["label"])
            if label not in (0, 1):
                raise ValueError(f"invalid label for {digest}: {label}")
            parsed = {
                "sha256": digest,
                "label": label,
                "benign_probability": float(row["benign_probability"]),
                "adapter_probability": float(row["adapter_probability"]),
                "base_trigger_raw": parse_bool(row["base_trigger_raw"]),
                "base_trigger_adjusted": parse_bool(
                    row["base_trigger_adjusted"]
                ),
                "signature_checked": parse_bool(row["signature_checked"]),
                "signature_verified": parse_bool(row["signature_verified"]),
            }
            if not all(
                math.isfinite(parsed[name]) for name in SCORE_FEATURES[:2]
            ):
                raise ValueError(f"non-finite score for {digest}")
            previous = records.get(digest)
            if previous is not None and previous != parsed:
                raise ValueError(f"conflicting rows for {digest} in {path}")
            records[digest] = parsed
    return records


def verify_report_overlap(training, calibration):
    overlap = set(training) & set(calibration)
    for digest in overlap:
        left = training[digest]
        right = calibration[digest]
        if left != right:
            raise ValueError(
                f"score or label mismatch for repeated sample {digest}"
            )
        if left["label"] == 0:
            raise ValueError(
                "benign train/calibration leakage detected for " + digest
            )


def split_records(training, calibration, route_min, seed):
    verify_report_overlap(training, calibration)
    malware = sorted(
        digest for digest, row in training.items() if row["label"] == 1
    )
    if len(malware) < 10:
        raise ValueError(f"need at least 10 malware samples; found {len(malware)}")
    if set(malware) - set(calibration):
        raise ValueError("calibration report does not contain all malware hashes")

    rng = np.random.RandomState(seed)
    malware = np.asarray(malware, dtype=object)
    rng.shuffle(malware)
    cut = max(1, int(len(malware) * 0.80))
    train_malware = set(malware[:cut])
    calibration_malware = set(malware[cut:])

    train_rows = [
        row
        for digest, row in training.items()
        if row["label"] == 0 or digest in train_malware
    ]
    calibration_rows = [
        row
        for digest, row in calibration.items()
        if row["label"] == 0 or digest in calibration_malware
    ]
    routed_train = [
        row for row in train_rows if row["adapter_probability"] >= route_min
    ]
    routed_calibration = [
        row
        for row in calibration_rows
        if row["adapter_probability"] >= route_min
    ]
    return train_rows, calibration_rows, routed_train, routed_calibration


def byte_entropy(bytez):
    if not bytez:
        return 0.0
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0].astype(np.float64) / len(bytez)
    return float(-(probabilities * np.log2(probabilities)).sum())


def collect_attributes(locations, wanted, max_bytes):
    collected = {}
    failures = []
    for location in locations:
        for name, bytez in file_bytes_generator(
            str(location), max_bytes, return_filename=True
        ):
            digest = hashlib.sha256(bytez).hexdigest()
            if digest not in wanted or digest in collected:
                continue
            try:
                attributes = PEAttributeExtractor(bytez).extract()
                attributes["byte_size"] = len(bytez)
                attributes["byte_entropy"] = byte_entropy(bytez)
                collected[digest] = attributes
            except Exception as error:
                failures.append(
                    {
                        "sha256": digest,
                        "name": name,
                        "error": type(error).__name__,
                    }
                )
            if len(collected) and len(collected) % 25 == 0:
                print(
                    f"Extracted reviewer features: {len(collected)}/{len(wanted)}",
                    flush=True,
                )
    missing = sorted(wanted - set(collected))
    if missing:
        preview = ", ".join(missing[:5])
        raise ValueError(
            f"could not find/extract {len(missing)} routed samples; first: {preview}"
        )
    return collected, failures


def finite_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def tokens(value):
    return [item for item in str(value or "").split() if item]


def build_feature_spec(train_rows, attributes):
    categories = {}
    for field in CATEGORICAL_FIELDS:
        categories[field] = sorted(
            {
                str(attributes[row["sha256"]].get(field, ""))
                for row in train_rows
            }
        )

    names = list(SCORE_FEATURES)
    names.extend(NeedForSpeedModel.NUMERICAL_ATTRIBUTES)
    names.extend(EXTRA_NUMERIC)
    names.extend(("byte_size", "byte_entropy"))
    for field in TEXT_FIELDS:
        names.extend(
            (
                f"{field}_token_count",
                f"{field}_unique_count",
                f"{field}_character_count",
            )
        )
    for field in CATEGORICAL_FIELDS:
        names.extend(f"{field}={value}" for value in categories[field])
    return {"feature_names": names, "categories": categories}


def vectorize(row, attributes, spec):
    values = [finite_number(row[name]) for name in SCORE_FEATURES]
    values.extend(
        finite_number(attributes.get(name))
        for name in NeedForSpeedModel.NUMERICAL_ATTRIBUTES
    )
    values.extend(finite_number(attributes.get(name)) for name in EXTRA_NUMERIC)
    values.extend(
        (
            finite_number(attributes.get("byte_size")),
            finite_number(attributes.get("byte_entropy")),
        )
    )
    for field in TEXT_FIELDS:
        field_tokens = tokens(attributes.get(field))
        values.extend(
            (
                float(len(field_tokens)),
                float(len(set(field_tokens))),
                float(len(str(attributes.get(field, "") or ""))),
            )
        )
    for field in CATEGORICAL_FIELDS:
        actual = str(attributes.get(field, ""))
        values.extend(float(actual == value) for value in spec["categories"][field])
    return values


def matrix(rows, attributes, spec):
    return np.asarray(
        [vectorize(row, attributes[row["sha256"]], spec) for row in rows],
        dtype=np.float64,
    )


def rates(rows, predictions):
    labels = np.asarray([row["label"] for row in rows], dtype=np.int8)
    predictions = np.asarray(predictions, dtype=bool)
    benign = labels == 0
    malicious = labels == 1
    return {
        "count": int(len(rows)),
        "benign": int(benign.sum()),
        "malicious": int(malicious.sum()),
        "fp": int((predictions & benign).sum()),
        "fn": int(((~predictions) & malicious).sum()),
        "fpr": float(predictions[benign].mean()) if benign.any() else None,
        "fnr": float((~predictions[malicious]).mean()) if malicious.any() else None,
        "tpr": float(predictions[malicious].mean()) if malicious.any() else None,
    }


def whole_split_probabilities(rows, routed_rows, routed_probabilities):
    by_hash = {
        row["sha256"]: float(probability)
        for row, probability in zip(routed_rows, routed_probabilities)
    }
    return np.asarray(
        [by_hash.get(row["sha256"], 0.0) for row in rows], dtype=np.float64
    )


def choose_threshold(rows, probabilities, max_fpr):
    candidates = [1.0000001]
    for value in np.unique(probabilities):
        candidates.extend((float(value), float(np.nextafter(value, np.inf))))
    best = None
    for threshold in candidates:
        result = rates(rows, probabilities >= threshold)
        if result["fpr"] <= max_fpr:
            rank = (result["tpr"], -result["fpr"], threshold)
            if best is None or rank > best[0]:
                best = (rank, threshold, result)
    return best[1], best[2]


def forest_probability(classifier, features):
    return classifier.predict_proba(features)[:, 1]


def export_forest(classifier):
    estimators = []
    for estimator in classifier.estimators_:
        tree = estimator.tree_
        leaf_probability = []
        for node in range(tree.node_count):
            counts = tree.value[node][0]
            total = float(counts.sum())
            leaf_probability.append(float(counts[1] / total) if total else 0.0)
        estimators.append(
            {
                "children_left": tree.children_left.astype(int).tolist(),
                "children_right": tree.children_right.astype(int).tolist(),
                "feature": tree.feature.astype(int).tolist(),
                "threshold": tree.threshold.astype(float).tolist(),
                "malware_probability": leaf_probability,
            }
        )
    return estimators


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--training-report", required=True, type=Path)
    parser.add_argument("--calibration-report", required=True, type=Path)
    parser.add_argument("--malicious", required=True, type=Path)
    parser.add_argument(
        "--training-benign", required=True, action="append", type=Path
    )
    parser.add_argument(
        "--calibration-benign", required=True, action="append", type=Path
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFENDER_ROOT / "defender" / "models" / "boundary_reviewer_candidate",
    )
    parser.add_argument("--route-min", type=float, default=0.50)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=704)
    args = parser.parse_args()
    if not 0.0 <= args.route_min <= 1.0:
        raise SystemExit("--route-min must be between zero and one")
    if not 0.0 <= args.max_fpr <= 1.0:
        raise SystemExit("--max-fpr must be between zero and one")

    training = parse_report(args.training_report)
    calibration = parse_report(args.calibration_report)
    (
        train_rows,
        calibration_rows,
        routed_train,
        routed_calibration,
    ) = split_records(training, calibration, args.route_min, args.seed)
    print(
        "Source-aware rows: "
        f"train={len(train_rows)} (routed={len(routed_train)}), "
        f"calibration={len(calibration_rows)} "
        f"(routed={len(routed_calibration)})",
        flush=True,
    )
    for split_name, rows in (
        ("training", routed_train),
        ("calibration", routed_calibration),
    ):
        class_counts = np.bincount(
            np.asarray([row["label"] for row in rows], dtype=np.int8),
            minlength=2,
        )
        if min(class_counts) < 5:
            raise SystemExit(
                f"{split_name} routed set is too small: "
                f"benign={class_counts[0]} malware={class_counts[1]}"
            )

    wanted = {row["sha256"] for row in routed_train + routed_calibration}
    locations = [args.malicious, *args.training_benign, *args.calibration_benign]
    attributes, failures = collect_attributes(locations, wanted, args.max_bytes)
    spec = build_feature_spec(routed_train, attributes)
    train_features = matrix(routed_train, attributes, spec)
    calibration_features = matrix(routed_calibration, attributes, spec)
    train_labels = np.asarray(
        [row["label"] for row in routed_train], dtype=np.int8
    )

    best = None
    for max_depth in (2, 3, 4):
        for min_leaf in (2, 4, 6):
            classifier = RandomForestClassifier(
                n_estimators=128,
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
    train_routed_probability = forest_probability(classifier, train_features)
    train_probability = whole_split_probabilities(
        train_rows, routed_train, train_routed_probability
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
            "Candidate only. Do not enable until a later disjoint evaluation "
            "improves the frozen adapter while preserving at least 95% TPR."
        ),
        "format_version": 1,
        "seed": args.seed,
        "route_min": args.route_min,
        "reviewer_threshold": threshold,
        "max_calibration_fpr": args.max_fpr,
        "classifier": "RandomForestClassifier",
        "n_estimators": len(classifier.estimators_),
        "max_depth": max_depth,
        "min_samples_leaf": min_leaf,
        "feature_count": len(spec["feature_names"]),
        "training": train_result,
        "calibration": calibration_result,
        "adapter_calibration_at_0.70": adapter_calibration,
        "split_counts": {
            "training": len(train_rows),
            "training_routed": len(routed_train),
            "calibration": len(calibration_rows),
            "calibration_routed": len(routed_calibration),
        },
        "parser_failures": failures,
    }
    split_manifest = {
        "training": [row["sha256"] for row in train_rows],
        "calibration": [row["sha256"] for row in calibration_rows],
        "training_routed": [row["sha256"] for row in routed_train],
        "calibration_routed": [row["sha256"] for row in routed_calibration],
    }
    for filename, payload in (
        ("model.json", model),
        ("metadata.json", metadata),
        ("split_manifest.json", split_manifest),
    ):
        with (args.output / filename).open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(f"Candidate reviewer written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
