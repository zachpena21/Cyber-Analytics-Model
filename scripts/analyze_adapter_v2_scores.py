#!/usr/bin/env python3
"""Audit adapter-v2 production scores on labeled PE corpora."""

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import requests

ROOT = Path(__file__).resolve().parents[1]
DEFENDER_ROOT = ROOT / "defender"
sys.path.insert(0, str(DEFENDER_ROOT))

from test import file_bytes_generator  # noqa: E402


def rates(labels, predictions):
    labels = np.asarray(labels, dtype=np.int8)
    predictions = np.asarray(predictions, dtype=bool)
    benign = labels == 0
    malicious = labels == 1
    return {
        "count": int(len(labels)),
        "benign": int(benign.sum()),
        "malicious": int(malicious.sum()),
        "fp": int((predictions & benign).sum()),
        "fn": int(((~predictions) & malicious).sum()),
        "fpr": float(predictions[benign].mean()) if benign.any() else None,
        "fnr": float((~predictions[malicious]).mean()) if malicious.any() else None,
        "tpr": float(predictions[malicious].mean()) if malicious.any() else None,
    }


def quantiles(values):
    points = (0.0, 0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99, 1.0)
    return {
        f"p{int(point * 100):02d}": float(np.quantile(values, point))
        for point in points
    }


def threshold_rows(labels, probabilities):
    candidates = [1.0000001]
    for value in np.unique(probabilities):
        candidates.extend((float(value), float(np.nextafter(value, np.inf))))
    return [
        {"threshold": threshold, **rates(labels, probabilities >= threshold)}
        for threshold in candidates
    ]


def choose(rows, max_fpr, min_tpr):
    under = [row for row in rows if row["fpr"] <= max_fpr]
    best = max(under, key=lambda row: (row["tpr"], -row["fpr"], row["threshold"]))
    both = [row for row in under if row["tpr"] >= min_tpr]
    strictest = None
    if both:
        strictest = min(
            both,
            key=lambda row: (row["fpr"], -row["threshold"], -row["tpr"]),
        )
    return best, strictest


def collect(location, label, source, args, seen):
    endpoint = args.service_url.rstrip("/") + "/diagnostics/score"
    records = []
    skipped = []
    for name, bytez in file_bytes_generator(
        str(location), args.max_bytes, return_filename=True
    ):
        digest = hashlib.sha256(bytez).hexdigest()
        if digest in seen:
            if seen[digest] != label:
                raise ValueError(f"SHA-256 {digest} appears in both classes")
            continue
        response = requests.post(
            endpoint,
            data=bytez,
            headers={"Content-Type": "application/octet-stream"},
            timeout=args.api_timeout,
        )
        if response.status_code == 404:
            raise RuntimeError("score endpoint is disabled")
        response.raise_for_status()
        details = response.json()
        if details.get("error"):
            skipped.append({"sha256": digest, "name": name, "error": details["error"]})
            continue
        probability = details.get("adapter_v2_probability")
        threshold = details.get("adapter_v2_threshold")
        if probability is None or threshold is None:
            raise ValueError("service did not return adapter-v2 scores")
        seen[digest] = label
        records.append(
            {
                "sha256": digest,
                "label": label,
                "source": source,
                "benign_probability": float(details["benign_probability"]),
                "adapter_probability": float(details["adapter_probability"]),
                "adapter_v2_probability": float(probability),
                "adapter_v2_threshold": float(threshold),
                "base_trigger_raw": int(details["base_trigger_raw"]),
                "base_trigger_adjusted": int(details["base_trigger_adjusted"]),
                "signature_checked": bool(details["signature_checked"]),
                "signature_verified": details["signature_verified"],
                "current_prediction": int(details["result"]),
            }
        )
        if len(records) % 25 == 0:
            print(f"Scored {source}: {len(records)}", flush=True)
    return records, skipped


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--malicious", required=True, type=Path)
    parser.add_argument("--benign", required=True, type=Path)
    parser.add_argument("--service-url", required=True)
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument("--max-bytes", type=int, default=2**21)
    parser.add_argument("--api-timeout", type=float, default=10.0)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-tpr", type=float, default=0.95)
    args = parser.parse_args()

    info_response = requests.get(args.service_url.rstrip("/") + "/model", timeout=args.api_timeout)
    info_response.raise_for_status()
    info = info_response.json()
    if not info.get("modern_adapter_v2"):
        raise SystemExit("service does not have adapter v2 enabled")
    if not info.get("score_endpoint_enabled"):
        raise SystemExit("service score endpoint is disabled")

    seen = {}
    malware, malware_skipped = collect(args.malicious, 1, "malicious_adapter_v2_audit", args, seen)
    benign, benign_skipped = collect(args.benign, 0, "benign_adapter_v2_audit", args, seen)
    records = malware + benign
    if not malware or not benign:
        raise SystemExit(f"need both classes; malware={len(malware)} benign={len(benign)}")

    thresholds = {row["adapter_v2_threshold"] for row in records}
    if len(thresholds) != 1:
        raise SystemExit("adapter-v2 threshold changed during audit")
    threshold = thresholds.pop()
    labels = np.asarray([row["label"] for row in records], dtype=np.int8)
    probability = np.asarray([row["adapter_v2_probability"] for row in records], dtype=np.float64)
    service_prediction = np.asarray([row["current_prediction"] for row in records], dtype=bool)
    expected = probability >= threshold
    mismatch_count = int(np.count_nonzero(service_prediction != expected))

    rows = threshold_rows(labels, probability)
    best, strictest = choose(rows, args.max_fpr, args.min_tpr)
    false_positives = sorted(
        [row for row in records if row["label"] == 0 and row["current_prediction"] == 1],
        key=lambda row: row["adapter_v2_probability"],
        reverse=True,
    )
    false_negatives = sorted(
        [row for row in records if row["label"] == 1 and row["current_prediction"] == 0],
        key=lambda row: row["adapter_v2_probability"],
    )

    csv_path = Path(f"{args.output_prefix}.csv")
    json_path = Path(f"{args.output_prefix}.json")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(records[0].keys())
    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    report = {
        "warning": "Development audit only; do not treat selected thresholds as final validation.",
        "service_model": info,
        "max_bytes": args.max_bytes,
        "sample_counts": {
            "malicious": len(malware),
            "benign": len(benign),
            "service_skipped": len(malware_skipped) + len(benign_skipped),
        },
        "current_threshold": threshold,
        "current_rates": rates(labels, service_prediction),
        "service_threshold_prediction_mismatches": mismatch_count,
        "score_quantiles": {
            "benign": quantiles(probability[labels == 0]),
            "malicious": quantiles(probability[labels == 1]),
        },
        "diagnostic_candidates": {
            "best_recall_under_fpr_ceiling": best,
            "strictest_meeting_both_targets": strictest,
            "both_targets_feasible_on_audit_batch": strictest is not None,
        },
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "skipped": {"malicious": malware_skipped, "benign": benign_skipped},
    }
    with json_path.open("w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Scores written to {csv_path}")
    print(f"Summary written to {json_path}")


if __name__ == "__main__":
    main()
