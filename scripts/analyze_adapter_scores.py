#!/usr/bin/env python3
"""Audit adapter scores on labeled PE corpora without extracting malware."""

import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse

from train_modern_adapter import collect, load_feature_pipeline, rates, score_base


ROOT = Path(__file__).resolve().parents[1]
DEFENDER_ROOT = ROOT / "defender"


def load_adapter(adapter_dir):
    with (adapter_dir / "metadata.json").open() as stream:
        metadata = json.load(stream)
    coefficients = np.load(adapter_dir / "coefficients.npy").reshape(-1)
    intercept_values = np.load(adapter_dir / "intercept.npy").reshape(-1)
    if intercept_values.size != 1:
        raise ValueError("adapter intercept must contain exactly one value")
    if coefficients.shape != (int(metadata["feature_count"]),):
        raise ValueError("adapter coefficient shape does not match metadata")
    if not np.isfinite(coefficients).all() or not np.isfinite(intercept_values).all():
        raise ValueError("adapter parameters contain non-finite values")
    return metadata, coefficients, float(intercept_values[0])


def adapter_probabilities(features, coefficients, intercept):
    logits = np.asarray(features @ coefficients).reshape(-1) + intercept
    logits = np.clip(logits, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-logits))


def threshold_rows(labels, probabilities):
    candidates = [1.0000001]
    for value in np.unique(probabilities):
        candidates.append(float(value))
        candidates.append(float(np.nextafter(value, np.inf)))
    rows = []
    for threshold in candidates:
        result = rates(labels, probabilities >= threshold)
        rows.append({"threshold": float(threshold), **result})
    return rows


def choose_diagnostics(rows, max_fpr, min_tpr):
    under_fpr = [row for row in rows if row["fpr"] <= max_fpr]
    best_recall = max(
        under_fpr,
        key=lambda row: (row["tpr"], -row["fpr"], row["threshold"]),
    )
    meets_both = [row for row in under_fpr if row["tpr"] >= min_tpr]
    strictest = None
    if meets_both:
        strictest = min(
            meets_both,
            key=lambda row: (row["fpr"], -row["threshold"], -row["tpr"]),
        )
    return best_recall, strictest


def quantiles(values):
    points = (0.0, 0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99, 1.0)
    return {
        f"p{int(point * 100):02d}": float(np.quantile(values, point))
        for point in points
    }


def main():
    parser = argparse.ArgumentParser(
        description="Report adapter score distributions and threshold tradeoffs."
    )
    parser.add_argument("--malicious", required=True, type=Path)
    parser.add_argument("--benign", required=True, type=Path)
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=DEFENDER_ROOT / "defender" / "models" / "compact",
    )
    parser.add_argument(
        "--adapter-dir",
        type=Path,
        default=DEFENDER_ROOT / "defender" / "models" / "modern_adapter",
    )
    parser.add_argument(
        "--output-prefix",
        type=Path,
        default=ROOT / "validation-data" / "adapter-score-analysis",
    )
    parser.add_argument("--base-url", help="frozen legacy API when compact arrays are absent")
    parser.add_argument("--api-timeout", type=float, default=10.0)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-tpr", type=float, default=0.95)
    args = parser.parse_args()

    if not 0.0 <= args.max_fpr <= 1.0:
        raise SystemExit("--max-fpr must be between zero and one")
    if not 0.0 <= args.min_tpr <= 1.0:
        raise SystemExit("--min-tpr must be between zero and one")

    try:
        pipeline, base = load_feature_pipeline(args.model_dir)
        metadata, coefficients, intercept = load_adapter(args.adapter_dir)
    except (FileNotFoundError, KeyError, ValueError) as error:
        raise SystemExit(str(error))
    if base is None and not args.base_url:
        raise SystemExit(
            "compact arrays are absent; pass --base-url for the frozen legacy API"
        )
    remote_url = args.base_url if base is None else None

    seen = {}
    malware, malware_skipped = collect(
        args.malicious,
        1,
        args.max_bytes,
        seen,
        remote_url,
        args.api_timeout,
        "malicious_score_audit",
    )
    benign, benign_skipped = collect(
        args.benign,
        0,
        args.max_bytes,
        seen,
        remote_url,
        args.api_timeout,
        "benign_score_audit",
    )
    records = malware + benign
    if not malware or not benign:
        raise SystemExit(
            f"need both classes after parsing; malware={len(malware)} benign={len(benign)}"
        )
    print(
        f"Usable unique samples: malware={len(malware)} benign={len(benign)}; "
        f"parser-skipped={len(malware_skipped) + len(benign_skipped)}",
        flush=True,
    )

    frame = pd.DataFrame([record["attributes"] for record in records])
    features = pipeline._extract_features(frame).tocsr()
    expected_base_features = int(metadata["base_feature_count"])
    if features.shape[1] != expected_base_features:
        raise SystemExit(
            "feature pipeline output does not match adapter metadata: "
            f"{features.shape[1]} != {expected_base_features}"
        )

    if base is not None:
        base_malware = score_base(base, features)
        base_trigger = (
            (1.0 - base_malware) < float(metadata["base_benign_threshold"])
        )
        base_source = "local_compact_model"
    else:
        base_trigger = np.asarray(
            [record["base_trigger"] for record in records], dtype=bool
        )
        base_source = args.base_url

    stacked = sparse.hstack(
        (
            features,
            sparse.csr_matrix(base_trigger.astype(np.float64).reshape(-1, 1)),
        ),
        format="csr",
    )
    if stacked.shape[1] != coefficients.size:
        raise SystemExit(
            "stacked feature count does not match adapter coefficients: "
            f"{stacked.shape[1]} != {coefficients.size}"
        )

    labels = np.asarray([record["label"] for record in records], dtype=np.int8)
    probabilities = adapter_probabilities(stacked, coefficients, intercept)
    current_threshold = float(metadata["adapter_threshold"])
    current = rates(labels, probabilities >= current_threshold)
    rows = threshold_rows(labels, probabilities)
    best_recall, strictest = choose_diagnostics(rows, args.max_fpr, args.min_tpr)

    csv_path = Path(f"{args.output_prefix}.csv")
    json_path = Path(f"{args.output_prefix}.json")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "sha256",
                "label",
                "source",
                "base_trigger",
                "adapter_probability",
                "current_prediction",
            ),
        )
        writer.writeheader()
        for record, trigger, probability in zip(records, base_trigger, probabilities):
            writer.writerow(
                {
                    "sha256": record["sha256"],
                    "label": int(record["label"]),
                    "source": record["source"],
                    "base_trigger": int(trigger),
                    "adapter_probability": float(probability),
                    "current_prediction": int(probability >= current_threshold),
                }
            )

    malicious_scores = probabilities[labels == 1]
    benign_scores = probabilities[labels == 0]
    report = {
        "warning": (
            "Diagnostic thresholds were selected on this audit batch. Do not report "
            "them as final performance; validate any change on new disjoint data."
        ),
        "sample_counts": {
            "malicious": len(malware),
            "benign": len(benign),
            "parser_skipped": len(malware_skipped) + len(benign_skipped),
        },
        "skipped": {
            "malicious": malware_skipped,
            "benign": benign_skipped,
        },
        "base_source": base_source,
        "targets": {"max_fpr": args.max_fpr, "min_tpr": args.min_tpr},
        "current_threshold": current_threshold,
        "current_rates": current,
        "diagnostic_candidates": {
            "best_recall_under_fpr_ceiling": best_recall,
            "strictest_meeting_both_targets": strictest,
            "both_targets_feasible_on_audit_batch": strictest is not None,
        },
        "score_quantiles": {
            "malicious": quantiles(malicious_scores),
            "benign": quantiles(benign_scores),
        },
    }
    with json_path.open("w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")

    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Per-sample scores written to {csv_path}")
    print(f"Summary written to {json_path}")


if __name__ == "__main__":
    main()
