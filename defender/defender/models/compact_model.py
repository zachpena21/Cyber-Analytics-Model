"""Memory-efficient exact tree traversal for the supplied random forest."""

import gzip
import json
import pickle
from pathlib import Path

import numpy as np


class CompactNeedForSpeedModel:
    classifier_name = "CompactRandomForestClassifier"

    def __init__(self, model_dir):
        model_dir = Path(model_dir)
        with gzip.open(model_dir / "feature_pipeline.pkl.gz", "rb") as stream:
            self.pipeline = pickle.load(stream)
        with (model_dir / "metadata.json").open() as stream:
            self.metadata = json.load(stream)

        self.offsets = np.load(model_dir / "offsets.npy", mmap_mode="r")
        self.children_left = np.load(model_dir / "children_left.npy", mmap_mode="r")
        self.children_right = np.load(model_dir / "children_right.npy", mmap_mode="r")
        self.features = np.load(model_dir / "features.npy", mmap_mode="r")
        self.thresholds = np.load(model_dir / "thresholds.npy", mmap_mode="r")
        self.malware_probability = np.load(
            model_dir / "malware_probability.npy", mmap_mode="r"
        )

    def _row_probability(self, row):
        total = 0.0
        for start in self.offsets[:-1]:
            start = int(start)
            node = start
            while self.children_left[node] != -1:
                feature = self.features[node]
                node = (
                    self.children_left[node]
                    if row[feature] <= self.thresholds[node]
                    else self.children_right[node]
                )
            total += float(self.malware_probability[node])
        return total / self.metadata["tree_count"]

    def predict_proba(self, data):
        features = self.pipeline._extract_features(data)
        dense = features.toarray() if hasattr(features, "toarray") else np.asarray(features)
        probabilities = np.empty((dense.shape[0], 2), dtype=np.float64)
        for index, row in enumerate(dense):
            malware = self._row_probability(row)
            probabilities[index] = (1.0 - malware, malware)
        return probabilities

    def predict_threshold(self, data, threshold=0.8):
        probabilities = self.predict_proba(data)
        return [int(benign < threshold) for benign in probabilities[:, 0]]
