#!/usr/bin/env python3
"""Evaluate an exported boundary reviewer without enabling it in the API."""

import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from train_boundary_reviewer import (  # noqa: E402
    collect_attributes,
    matrix,
    parse_report,
    rates,
    whole_split_probabilities,
)


def load_model(path):
    with Path(path).open(encoding="utf-8") as stream:
        model = json.load(stream)
    required = {
        "format_version",
        "route_min",
        "reviewer_threshold",
        "feature_names",
        "categories",
        "estimators",
    }
    missing = required - set(model)
    if missing:
        raise ValueError(
            f"reviewer model is missing keys: {', '.join(sorted(missing))}"
        )
    if model["format_version"] != 1:
        raise ValueError(
            f"unsupported reviewer format {model['format_version']!r}"
        )
    if not model["estimators"]:
        raise ValueError("reviewer forest has no estimators")
    return model


def tree_probability(tree, vector):
    node = 0
    while tree["children_left"][node] >= 0:
        feature = tree["feature"][node]
        node = (
            tree["children_left"][node]
            if vector[feature] <= tree["threshold"][node]
            else tree["children_right"][node]
        )
    return float(tree["malware_probability"][node])


def forest_probabilities(model, features):
    output = np.empty(features.shape[0], dtype=np.float64)
    for row_index, vector in enumerate(features):
        output[row_index] = np.mean(
            [
                tree_probability(estimator, vector)
                for estimator in model["estimators"]
            ]
        )
    return output


def report_rows(path):
    parsed = parse_report(path)
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        raw = {row["sha256"].strip().casefold(): row for row in csv.DictReader(stream)}
    for digest, row in parsed.items():
        source = raw[digest]
        row["current_prediction"] = int(source["current_prediction"])
        row["adapter_threshold"] = float(source["adapter_threshold"])
    return list(parsed.values())


def validate_report(rows):
    labels = {row["label"] for row in rows}
    if labels != {0, 1}:
        raise ValueError("evaluation report must contain both classes")
    thresholds = {row["adapter_threshold"] for row in rows}
    if len(thresholds) != 1:
        raise ValueError("adapter threshold changed within the score report")
    mismatches = [
        row["sha256"]
        for row in rows
        if row["current_prediction"]
        != int(row["adapter_probability"] >= row["adapter_threshold"])
    ]
    if mismatches:
        raise ValueError(
            f"score report has {len(mismatches)} adapter/verdict mismatches"
        )


def confidence_interval_wilson(successes, total, z=1.959963984540054):
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * np.sqrt(
            proportion * (1.0 - proportion) / total
            + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return [float(max(0.0, center - margin)), float(min(1.0, center + margin))]


def add_intervals(result):
    result = dict(result)
    result["fpr_wilson_95"] = confidence_interval_wilson(
        result["fp"], result["benign"]
    )
    result["tpr_wilson_95"] = confidence_interval_wilson(
        result["malicious"] - result["fn"], result["malicious"]
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--malicious", required=True, type=Path)
    parser.add_argument("--benign", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    args = parser.parse_args()

    model = load_model(args.model)
    rows = report_rows(args.report)
    validate_report(rows)
    route_min = float(model["route_min"])
    routed = [
        row for row in rows if row["adapter_probability"] >= route_min
    ]
    wanted = {row["sha256"] for row in routed}
    attributes, failures = collect_attributes(
        [args.malicious, args.benign], wanted, args.max_bytes
    )
    spec = {
        "categories": model["categories"],
        "feature_names": model["feature_names"],
    }
    features = matrix(routed, attributes, spec)
    if features.shape[1] != len(model["feature_names"]):
        raise ValueError(
            "runtime feature count does not match the exported reviewer"
        )
    routed_probability = forest_probabilities(model, features)
    reviewer_probability = whole_split_probabilities(
        rows, routed, routed_probability
    )
    reviewer_prediction = (
        reviewer_probability >= float(model["reviewer_threshold"])
    )
    adapter_prediction = np.asarray(
        [row["current_prediction"] for row in rows], dtype=bool
    )
    reviewer_result = add_intervals(rates(rows, reviewer_prediction))
    adapter_result = add_intervals(rates(rows, adapter_prediction))

    changes = []
    for index, row in enumerate(rows):
        if reviewer_prediction[index] == adapter_prediction[index]:
            continue
        changes.append(
            {
                "sha256": row["sha256"],
                "label": row["label"],
                "adapter_probability": row["adapter_probability"],
                "adapter_prediction": int(adapter_prediction[index]),
                "reviewer_probability": float(reviewer_probability[index]),
                "reviewer_prediction": int(reviewer_prediction[index]),
            }
        )

    output = {
        "warning": (
            "Diagnostic result on previously inspected development data. "
            "Freeze the selected model and use a later disjoint final test."
        ),
        "model": str(args.model),
        "report": str(args.report),
        "route_min": route_min,
        "reviewer_threshold": float(model["reviewer_threshold"]),
        "feature_count": len(model["feature_names"]),
        "estimator_count": len(model["estimators"]),
        "routed": {
            "count": len(routed),
            "benign": sum(row["label"] == 0 for row in routed),
            "malicious": sum(row["label"] == 1 for row in routed),
        },
        "adapter": adapter_result,
        "reviewer": reviewer_result,
        "changed_verdicts": len(changes),
        "parser_failures": failures,
    }
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = Path(f"{args.output_prefix}.json")
    csv_path = Path(f"{args.output_prefix}-changes.csv")
    with json_path.open("w", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2, sort_keys=True)
        stream.write("\n")
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        fieldnames = (
            "sha256",
            "label",
            "adapter_probability",
            "adapter_prediction",
            "reviewer_probability",
            "reviewer_prediction",
        )
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(changes)
    print(json.dumps(output, indent=2, sort_keys=True))
    print(f"Changed verdicts written to {csv_path}", flush=True)


if __name__ == "__main__":
    main()
