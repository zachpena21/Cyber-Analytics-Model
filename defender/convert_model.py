#!/usr/bin/env python3
"""Convert the large sklearn forest into mmap-friendly inference arrays."""

import argparse
import copy
import gzip
import json
import pickle
from pathlib import Path

import numpy as np

# Required because the supplied pickle records __main__.NeedForSpeedModel.
from defender.models.nfs_model import NeedForSpeedModel  # noqa: F401


def allocate(path, dtype, length):
    return np.lib.format.open_memmap(path, mode="w+", dtype=dtype, shape=(length,))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with gzip.open(args.input, "rb") as stream:
        model = pickle.load(stream)

    classifier = model.classifier
    tree_count = len(classifier.estimators_)
    counts = np.asarray(
        [estimator.tree_.node_count for estimator in classifier.estimators_],
        dtype=np.int64,
    )
    offsets = np.concatenate(([0], np.cumsum(counts)))
    np.save(args.output / "offsets.npy", offsets)
    total_nodes = int(offsets[-1])

    children_left = allocate(args.output / "children_left.npy", np.int32, total_nodes)
    children_right = allocate(args.output / "children_right.npy", np.int32, total_nodes)
    features = allocate(args.output / "features.npy", np.int32, total_nodes)
    thresholds = allocate(args.output / "thresholds.npy", np.float64, total_nodes)
    malware_probability = allocate(
        args.output / "malware_probability.npy", np.float32, total_nodes
    )

    malware_index = int(np.flatnonzero(classifier.classes_ == 1)[0])
    for tree_index, estimator in enumerate(classifier.estimators_):
        tree = estimator.tree_
        start, stop = int(offsets[tree_index]), int(offsets[tree_index + 1])
        left = tree.children_left.astype(np.int32, copy=False)
        right = tree.children_right.astype(np.int32, copy=False)
        # Child indices are local to each sklearn tree; make them global.
        children_left[start:stop] = np.where(left == -1, -1, left + start)
        children_right[start:stop] = np.where(right == -1, -1, right + start)
        features[start:stop] = tree.feature.astype(np.int32, copy=False)
        thresholds[start:stop] = tree.threshold
        values = tree.value[:, 0, :]
        totals = values.sum(axis=1)
        malware_probability[start:stop] = np.divide(
            values[:, malware_index],
            totals,
            out=np.zeros(tree.node_count, dtype=np.float64),
            where=totals != 0,
        ).astype(np.float32)

    for array in (
        children_left,
        children_right,
        features,
        thresholds,
        malware_probability,
    ):
        array.flush()

    pipeline = copy.copy(model)
    pipeline.classifier = None
    with gzip.open(args.output / "feature_pipeline.pkl.gz", "wb", compresslevel=6) as stream:
        pickle.dump(pipeline, stream, protocol=4)

    metadata = {
        "tree_count": tree_count,
        "node_count": total_nodes,
        "feature_count": int(
            getattr(classifier, "n_features_in_", classifier.n_features_)
        ),
        "threshold_dtype": "float64",
        "probability_dtype": "float32",
    }
    with (args.output / "metadata.json").open("w") as stream:
        json.dump(metadata, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(metadata, sort_keys=True))


if __name__ == "__main__":
    main()
