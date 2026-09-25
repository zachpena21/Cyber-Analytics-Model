#!/usr/bin/env python3
"""Audit adapter scores on labeled PE corpora without extracting malware."""

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import requests
from scipy import sparse

from train_modern_adapter import (
    collect,
    file_bytes_generator,
    load_feature_pipeline,
    rates,
    score_base,
)


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

def boundary_density(labels, probabilities, threshold):
    result = {}
    for width in (0.05, 0.10, 0.20):
        selected = np.abs(probabilities - threshold) <= width
        result[f"plus_or_minus_{width:.2f}"] = {
            "count": int(selected.sum()),
            "fraction": float(selected.mean()),
            "benign": int(((labels == 0) & selected).sum()),
            "malicious": int(((labels == 1) & selected).sum()),
        }
    return result


def collect_service_scores(
    location,
    label,
    max_bytes,
    seen,
    service_url,
    timeout,
    source,
):
    records = []
    skipped = []
    endpoint = service_url.rstrip("/") + "/diagnostics/score"
    for name, bytez in file_bytes_generator(
        str(location), max_bytes, return_filename=True
    ):
        digest = hashlib.sha256(bytez).hexdigest()
        previous = seen.get(digest)
        if previous is not None:
            if previous != label:
                raise ValueError(f"SHA-256 {digest} appears in both classes")
            continue
        response = requests.post(
            endpoint,
            data=bytez,
            headers={"Content-Type": "application/octet-stream"},
            timeout=timeout,
        )
        if response.status_code == 404:
            raise RuntimeError(
                "production score endpoint is disabled; restart the service "
                "with DF_ENABLE_SCORE_ENDPOINT=1"
            )
        response.raise_for_status()
        details = response.json()
        if details.get("error"):
            skipped.append(
                {"sha256": digest, "error": details["error"], "name": name}
            )
            continue
        probability = details.get("adapter_probability")
        if probability is None or not np.isfinite(float(probability)):
            raise ValueError(
                f"service returned invalid adapter probability for {digest}"
            )
        if details.get("result") not in (0, 1):
            raise ValueError(f"service returned invalid result for {digest}")
        seen[digest] = label
        records.append(
            {
                "sha256": digest,
                "label": label,
                "source": source,
                "benign_probability": float(details["benign_probability"]),
                "adapter_probability": float(probability),
                "adapter_threshold": float(details["adapter_threshold"]),
                "base_trigger_raw": int(details["base_trigger_raw"]),
                "base_trigger_adjusted": int(
                    details["base_trigger_adjusted"]
                ),
                "signature_checked": bool(details["signature_checked"]),
                "signature_verified": details["signature_verified"],
                "reviewer_routed": bool(details.get("reviewer_routed", False)),
                "reviewer_probability": details.get("reviewer_probability"),
                "reviewer_threshold": details.get("reviewer_threshold"),
                "current_prediction": int(details["result"]),
            }
        )
        if len(records) % 25 == 0:
            print(
                f"Scored {source}: {len(records)} samples",
                flush=True,
            )
    return records, skipped


def run_service_audit(args):
    model_response = requests.get(
        args.service_url.rstrip("/") + "/model",
        timeout=args.api_timeout,
    )
    model_response.raise_for_status()
    model_info = model_response.json()
    if not model_info.get("modern_adapter"):
        raise SystemExit("service does not have the modern adapter enabled")
    if not model_info.get("score_endpoint_enabled"):
        raise SystemExit(
            "production score endpoint is disabled; restart the service "
            "with DF_ENABLE_SCORE_ENDPOINT=1"
        )
    current_threshold = float(model_info["adapter_threshold"])

    seen = {}
    malware, malware_skipped = collect_service_scores(
        args.malicious,
        1,
        args.max_bytes,
        seen,
        args.service_url,
        args.api_timeout,
        "malicious_production_score_audit",
    )
    benign, benign_skipped = collect_service_scores(
        args.benign,
        0,
        args.max_bytes,
        seen,
        args.service_url,
        args.api_timeout,
        "benign_production_score_audit",
    )
    records = malware + benign
    if not malware or not benign:
        raise SystemExit(
            f"need both classes after scoring; malware={len(malware)} "
            f"benign={len(benign)}"
        )
    thresholds = {record["adapter_threshold"] for record in records}
    if thresholds != {current_threshold}:
        raise SystemExit(
            "service adapter threshold changed during score collection"
        )

    labels = np.asarray([record["label"] for record in records], dtype=np.int8)
    probabilities = np.asarray(
        [record["adapter_probability"] for record in records],
        dtype=np.float64,
    )
    service_predictions = np.asarray(
        [record["current_prediction"] for record in records],
        dtype=bool,
    )
    threshold_predictions = probabilities >= current_threshold
    mismatch_count = int(
        np.count_nonzero(service_predictions != threshold_predictions)
    )
    current = rates(labels, service_predictions)
    rows = threshold_rows(labels, probabilities)
    best_recall, strictest = choose_diagnostics(
        rows, args.max_fpr, args.min_tpr
    )
    reviewer_diagnostics = None
    if model_info.get("boundary_reviewer"):
        route_min = float(model_info["reviewer_route_min"])
        reviewer_threshold = float(model_info["reviewer_threshold"])
        reviewer_probability = np.asarray(
            [
                float(record["reviewer_probability"])
                if record["reviewer_probability"] is not None
                else 0.0
                for record in records
            ],
            dtype=np.float64,
        )
        routed = np.asarray(
            [record["reviewer_routed"] for record in records], dtype=bool
        )
        expected_routed = probabilities >= route_min
        if not np.array_equal(routed, expected_routed):
            raise SystemExit("service reviewer routing does not match route_min")
        if any(
            record["reviewer_threshold"] != reviewer_threshold
            for record in records
        ):
            raise SystemExit("service reviewer threshold changed during audit")
        reviewer_predictions = reviewer_probability >= reviewer_threshold
        reviewer_mismatches = int(
            np.count_nonzero(service_predictions != reviewer_predictions)
        )
        reviewer_rows = threshold_rows(labels, reviewer_probability)
        reviewer_best, reviewer_strictest = choose_diagnostics(
            reviewer_rows, args.max_fpr, args.min_tpr
        )
        reviewer_diagnostics = {
            "route_min": route_min,
            "current_threshold": reviewer_threshold,
            "current_rates": rates(labels, reviewer_predictions),
            "service_prediction_mismatches": reviewer_mismatches,
            "routed": {
                "count": int(routed.sum()),
                "malicious": int(((labels == 1) & routed).sum()),
                "benign": int(((labels == 0) & routed).sum()),
            },
            "diagnostic_candidates": {
                "best_recall_under_fpr_ceiling": reviewer_best,
                "strictest_meeting_both_targets": reviewer_strictest,
                "both_targets_feasible_on_audit_batch": (
                    reviewer_strictest is not None
                ),
            },
            "routed_score_quantiles": {
                "malicious": quantiles(
                    reviewer_probability[(labels == 1) & routed]
                ),
                "benign": quantiles(
                    reviewer_probability[(labels == 0) & routed]
                ),
            },
        }

    csv_path = Path(f"{args.output_prefix}.csv")
    json_path = Path(f"{args.output_prefix}.json")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "sha256",
        "label",
        "source",
        "benign_probability",
        "adapter_probability",
        "adapter_threshold",
        "base_trigger_raw",
        "base_trigger_adjusted",
        "signature_checked",
        "signature_verified",
        "reviewer_routed",
        "reviewer_probability",
        "reviewer_threshold",
        "current_prediction",
    )
    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    report = {
        "warning": (
            "Thresholds selected on this audit batch are development results. "
            "Validate a frozen model on new disjoint data."
        ),
        "score_source": "production_diagnostic_endpoint",
        "service_url": args.service_url,
        "service_model": model_info,
        "sample_counts": {
            "malicious": len(malware),
            "benign": len(benign),
            "service_skipped": len(malware_skipped) + len(benign_skipped),
        },
        "skipped": {
            "malicious": malware_skipped,
            "benign": benign_skipped,
        },
        "targets": {"max_fpr": args.max_fpr, "min_tpr": args.min_tpr},
        "current_threshold": current_threshold,
        "current_rates": current,
        "service_threshold_prediction_mismatches": mismatch_count,
        "boundary_density": boundary_density(
            labels, probabilities, current_threshold
        ),
        "diagnostic_candidates": {
            "best_recall_under_fpr_ceiling": best_recall,
            "strictest_meeting_both_targets": strictest,
            "both_targets_feasible_on_audit_batch": strictest is not None,
        },
        "score_quantiles": {
            "malicious": quantiles(probabilities[labels == 1]),
            "benign": quantiles(probabilities[labels == 0]),
        },
        "reviewer_diagnostics": reviewer_diagnostics,
    }
    with json_path.open("w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Per-sample production scores written to {csv_path}")
    print(f"Summary written to {json_path}")


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
    parser.add_argument(
        "--base-url",
        help="frozen legacy API when compact arrays are absent",
    )
    parser.add_argument(
        "--service-url",
        help=(
            "adapted production service with its gated diagnostic endpoint "
            "enabled; bypasses VM-side feature extraction"
        ),
    )
    parser.add_argument("--api-timeout", type=float, default=10.0)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--min-tpr", type=float, default=0.95)
    args = parser.parse_args()

    if not 0.0 <= args.max_fpr <= 1.0:
        raise SystemExit("--max-fpr must be between zero and one")
    if not 0.0 <= args.min_tpr <= 1.0:
        raise SystemExit("--min-tpr must be between zero and one")
    if args.service_url:
        try:
            run_service_audit(args)
        except (requests.RequestException, ValueError, RuntimeError) as error:
            raise SystemExit(str(error))
        return

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
            f"need both classes after parsing; malware={len(malware)} "
            f"benign={len(benign)}"
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
