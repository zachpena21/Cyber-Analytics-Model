#!/usr/bin/env python3
"""Train a compact recent-sample adapter without extracting malware to disk."""

import argparse
import gzip
import hashlib
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import requests
from scipy import sparse
from sklearn.linear_model import SGDClassifier


ROOT = Path(__file__).resolve().parents[1]
DEFENDER_ROOT = ROOT / "defender"
sys.path.insert(0, str(DEFENDER_ROOT))

from defender.models.attribute_extractor import PEAttributeExtractor  # noqa: E402
from defender.models.compact_model import CompactNeedForSpeedModel  # noqa: E402
from test import file_bytes_generator  # noqa: E402


def remote_verdict(base_url, bytez, timeout):
    response = requests.post(
        base_url,
        data=bytez,
        headers={"Content-Type": "application/octet-stream"},
        timeout=timeout,
    )
    response.raise_for_status()
    result = response.json().get("result")
    if result not in (0, 1):
        raise ValueError(f"base API returned invalid result {result!r}")
    return bool(result)


def collect(
    location,
    label,
    max_bytes,
    seen,
    base_url=None,
    timeout=10,
    source="unspecified",
):
    records = []
    skipped = []
    for name, bytez in file_bytes_generator(
        str(location), max_bytes, return_filename=True
    ):
        digest = hashlib.sha256(bytez).hexdigest()
        previous = seen.get(digest)
        if previous is not None:
            if previous != label:
                raise ValueError(
                    f"SHA-256 {digest} appears in both classes"
                )
            continue
        try:
            attributes = PEAttributeExtractor(bytez).extract()
            base_trigger = (
                remote_verdict(base_url, bytez, timeout)
                if base_url is not None
                else None
            )
        except Exception as error:
            skipped.append(
                {"sha256": digest, "error": type(error).__name__}
            )
            continue
        seen[digest] = label
        records.append(
            {
                "sha256": digest,
                "label": label,
                "source": source,
                "attributes": attributes,
                "base_trigger": base_trigger,
            }
        )
    return records, skipped


def three_way_split(labels, seed):
    rng = np.random.RandomState(seed)
    splits = {"train": [], "calibration": [], "test": []}
    for label in (0, 1):
        indices = np.flatnonzero(labels == label)
        if len(indices) < 10:
            raise ValueError(
                f"need at least 10 samples for class {label}; found {len(indices)}"
            )
        rng.shuffle(indices)
        train_end = max(1, int(len(indices) * 0.60))
        calibration_end = max(train_end + 1, int(len(indices) * 0.80))
        splits["train"].extend(indices[:train_end])
        splits["calibration"].extend(indices[train_end:calibration_end])
        splits["test"].extend(indices[calibration_end:])
    for values in splits.values():
        rng.shuffle(values)
    return {key: np.asarray(value, dtype=np.int64) for key, value in splits.items()}


def source_aware_split(records, seed):
    """Keep the newest benign corpus out of adapter fitting.

    Malware is split 80/20 between fitting and calibration because a separate
    external malware corpus is retained for final evaluation. All older benign
    samples are used for fitting, while the explicitly supplied validation
    corpus is split equally between threshold calibration and an untouched
    within-run benign check. A later benign corpus is still required for final
    external evaluation.
    """
    rng = np.random.RandomState(seed)
    malware = np.asarray(
        [i for i, record in enumerate(records) if record["label"] == 1],
        dtype=np.int64,
    )
    benign_train = np.asarray(
        [
            i
            for i, record in enumerate(records)
            if record["label"] == 0 and record["source"] == "benign_training"
        ],
        dtype=np.int64,
    )
    benign_validation = np.asarray(
        [
            i
            for i, record in enumerate(records)
            if record["label"] == 0 and record["source"] == "benign_validation"
        ],
        dtype=np.int64,
    )
    if len(malware) < 10:
        raise ValueError(f"need at least 10 malware samples; found {len(malware)}")
    if len(benign_train) < 10:
        raise ValueError(
            f"need at least 10 training benign samples; found {len(benign_train)}"
        )
    if len(benign_validation) < 20:
        raise ValueError(
            "need at least 20 validation benign samples; "
            f"found {len(benign_validation)}"
        )

    rng.shuffle(malware)
    rng.shuffle(benign_train)
    rng.shuffle(benign_validation)
    malware_train_end = max(1, int(len(malware) * 0.80))
    benign_midpoint = len(benign_validation) // 2
    splits = {
        "train": np.concatenate((malware[:malware_train_end], benign_train)),
        "calibration": np.concatenate(
            (
                malware[malware_train_end:],
                benign_validation[:benign_midpoint],
            )
        ),
        "test": np.concatenate(
            (
                benign_validation[benign_midpoint:],
            )
        ),
    }
    for values in splits.values():
        rng.shuffle(values)
    return splits


def rates(labels, predictions):
    malicious = labels == 1
    benign = labels == 0
    return {
        "count": int(len(labels)),
        "malicious": int(malicious.sum()),
        "benign": int(benign.sum()),
        "fpr": float(predictions[benign].mean()) if benign.any() else None,
        "fnr": float((~predictions[malicious]).mean()) if malicious.any() else None,
        "tpr": float(predictions[malicious].mean()) if malicious.any() else None,
    }


def choose_threshold(labels, probabilities, max_fpr):
    # A value above one represents an all-benign decision and guarantees that
    # the constrained search always has a feasible baseline.
    candidates = [1.0000001]
    for value in np.unique(probabilities):
        candidates.append(float(value))
        candidates.append(float(np.nextafter(value, np.inf)))
    best = None
    for threshold in candidates:
        predictions = probabilities >= threshold
        result = rates(labels, predictions)
        if result["fpr"] <= max_fpr:
            rank = (result["tpr"], -result["fpr"], threshold)
            if best is None or rank > best[0]:
                best = (rank, threshold, result)
    return best[1], best[2]


def score_base(model, features):
    probabilities = np.empty(features.shape[0], dtype=np.float64)
    for index in range(features.shape[0]):
        row = features.getrow(index).toarray().reshape(-1)
        probabilities[index] = model._row_probability(row)
        if (index + 1) % 25 == 0 or index + 1 == features.shape[0]:
            print(
                f"Scored legacy model: {index + 1}/{features.shape[0]}",
                flush=True,
            )
    return probabilities


def adapter_probabilities(classifier, features):
    logits = np.clip(classifier.decision_function(features), -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-logits))


def make_legacy_pipeline_compatible(pipeline):
    """Fill attributes added after the pipeline's sklearn 0.24 release."""
    encoder = pipeline.categorical_extractor
    compatibility = {
        "_infrequent_enabled": False,
        "sparse_output": getattr(encoder, "sparse", True),
        "feature_name_combiner": "concat",
        "_drop_idx_after_grouping": None,
    }
    for name, value in compatibility.items():
        if not hasattr(encoder, name):
            setattr(encoder, name, value)
    if (
        not hasattr(encoder, "_n_features_outs")
        and hasattr(encoder, "_compute_n_features_outs")
    ):
        encoder._n_features_outs = encoder._compute_n_features_outs()

    scaler = pipeline.feature_scaler
    if not hasattr(scaler, "clip"):
        scaler.clip = False
    return pipeline


def load_feature_pipeline(model_dir):
    required_arrays = (
        "metadata.json",
        "offsets.npy",
        "children_left.npy",
        "children_right.npy",
        "features.npy",
        "thresholds.npy",
        "malware_probability.npy",
        "feature_pipeline.pkl.gz",
    )
    if all((model_dir / name).is_file() for name in required_arrays):
        model = CompactNeedForSpeedModel(model_dir)
        make_legacy_pipeline_compatible(model.pipeline)
        return model.pipeline, model

    pipeline_path = model_dir / "feature_pipeline.pkl.gz"
    if not pipeline_path.is_file():
        raise FileNotFoundError(
            f"feature pipeline not found at {pipeline_path}"
        )
    with gzip.open(pipeline_path, "rb") as stream:
        pipeline = pickle.load(stream)
    return make_legacy_pipeline_compatible(pipeline), None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--malicious", required=True, type=Path)
    parser.add_argument("--benign", required=True, type=Path)
    parser.add_argument(
        "--validation-benign",
        type=Path,
        help=(
            "newer disjoint benign corpus kept out of adapter fitting and split "
            "between threshold calibration and an untouched within-run check"
        ),
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=DEFENDER_ROOT / "defender" / "models" / "compact",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFENDER_ROOT / "defender" / "models" / "modern_adapter",
    )
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--base-benign-threshold", type=float, default=0.510001)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=704)
    parser.add_argument(
        "--base-url",
        help="running frozen baseline API, used when compact arrays are absent",
    )
    parser.add_argument("--api-timeout", type=float, default=10.0)
    args = parser.parse_args()

    if not 0 <= args.max_fpr <= 1:
        raise SystemExit("--max-fpr must be between zero and one")

    try:
        pipeline, base = load_feature_pipeline(args.model_dir)
    except FileNotFoundError as error:
        raise SystemExit(str(error))
    if base is None and not args.base_url:
        raise SystemExit(
            "compact arrays are absent; pass --base-url for the running frozen API"
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
        "malicious_development",
    )
    benign, benign_skipped = collect(
        args.benign,
        0,
        args.max_bytes,
        seen,
        remote_url,
        args.api_timeout,
        "benign_training",
    )
    validation_benign = []
    validation_benign_skipped = []
    if args.validation_benign is not None:
        validation_benign, validation_benign_skipped = collect(
            args.validation_benign,
            0,
            args.max_bytes,
            seen,
            remote_url,
            args.api_timeout,
            "benign_validation",
        )
    records = malware + benign + validation_benign
    skipped_count = (
        len(malware_skipped)
        + len(benign_skipped)
        + len(validation_benign_skipped)
    )
    print(
        f"Usable unique samples: malware={len(malware)} "
        f"benign-train={len(benign)} "
        f"benign-validation={len(validation_benign)}; "
        f"parser-skipped={skipped_count}",
        flush=True,
    )

    labels = np.asarray([record["label"] for record in records], dtype=np.int8)
    if args.validation_benign is None:
        splits = three_way_split(labels, args.seed)
        split_strategy = "random_stratified_60_20_20"
    else:
        splits = source_aware_split(records, args.seed)
        split_strategy = "source_aware_newest_benign_held_out"
    frame = pd.DataFrame([record["attributes"] for record in records])
    features = pipeline._extract_features(frame).tocsr()
    if base is not None:
        base_malware = score_base(base, features)
        base_trigger = (1.0 - base_malware) < args.base_benign_threshold
        base_source = "local_compact_model"
    else:
        base_trigger = np.asarray(
            [record["base_trigger"] for record in records], dtype=bool
        )
        base_source = args.base_url

    # The baseline verdict is an explicit stacking feature. The adapter is the
    # final decision rather than an OR rule, allowing it to correct legacy
    # false positives as well as recover modern-malware false negatives.
    adapter_features = sparse.hstack(
        (
            features,
            sparse.csr_matrix(base_trigger.astype(np.float64).reshape(-1, 1)),
        ),
        format="csr",
    )

    train = splits["train"]
    calibration = splits["calibration"]
    test = splits["test"]
    best = None
    for alpha in (1e-6, 1e-5, 1e-4, 1e-3):
        classifier = SGDClassifier(
            loss="log_loss",
            penalty="l2",
            alpha=alpha,
            class_weight="balanced",
            max_iter=5000,
            tol=1e-5,
            random_state=args.seed,
        )
        classifier.fit(adapter_features[train], labels[train])
        calibration_probability = adapter_probabilities(
            classifier, adapter_features[calibration]
        )
        threshold, calibration_rates = choose_threshold(
            labels[calibration],
            calibration_probability,
            args.max_fpr,
        )
        rank = (
            calibration_rates["tpr"],
            -calibration_rates["fpr"],
            threshold,
        )
        if best is None or rank > best[0]:
            best = (rank, alpha, classifier, threshold, calibration_rates)

    _rank, alpha, classifier, threshold, calibration_rates = best
    test_probability = adapter_probabilities(
        classifier, adapter_features[test]
    )
    test_predictions = test_probability >= threshold
    test_rates = rates(labels[test], test_predictions)
    legacy_test_rates = rates(labels[test], base_trigger[test])

    args.output.mkdir(parents=True, exist_ok=True)
    np.save(
        args.output / "coefficients.npy",
        classifier.coef_.reshape(-1).astype(np.float64),
    )
    np.save(
        args.output / "intercept.npy",
        classifier.intercept_.astype(np.float64),
    )
    metadata = {
        "format_version": 1,
        "feature_count": int(adapter_features.shape[1]),
        "base_feature_count": int(features.shape[1]),
        "decision_policy": "adapter_with_legacy_verdict_feature",
        "adapter_threshold": threshold,
        "base_benign_threshold": args.base_benign_threshold,
        "max_calibration_fpr": args.max_fpr,
        "alpha": alpha,
        "seed": args.seed,
        "split_strategy": split_strategy,
        "base_source": base_source,
        "sample_counts": {
            "malicious": len(malware),
            "benign": len(benign) + len(validation_benign),
            "benign_training": len(benign),
            "benign_validation": len(validation_benign),
            "parser_skipped": skipped_count,
        },
        "split_counts": {key: len(value) for key, value in splits.items()},
        "calibration": calibration_rates,
        "holdout_test": test_rates,
        "legacy_holdout_test": legacy_test_rates,
    }
    with (args.output / "metadata.json").open("w") as stream:
        json.dump(metadata, stream, indent=2, sort_keys=True)
        stream.write("\n")
    split_manifest = [
        {
            "sha256": records[index]["sha256"],
            "label": int(labels[index]),
            "source": records[index]["source"],
            "split": split_name,
        }
        for split_name, indices in splits.items()
        for index in indices
    ]
    with (args.output / "split_manifest.json").open("w") as stream:
        json.dump(split_manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")

    print(json.dumps(metadata, indent=2, sort_keys=True))
    print(f"Adapter written to {args.output}")
    if test_rates["fpr"] > args.max_fpr:
        print(
            "WARNING: untouched holdout FPR exceeds the target; do not ship this adapter.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
