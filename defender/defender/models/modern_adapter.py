"""Small linear adapter for recent samples on top of the legacy forest."""

import json
from pathlib import Path

import numpy as np
from scipy import sparse

from defender.models.compact_model import CompactNeedForSpeedModel


class ModernAdapterModel:
    """Expose legacy and modern-model probabilities without changing the API."""

    classifier_name = "CompactRandomForest+LinearModernAdapter"

    def __init__(self, model_dir, adapter_dir):
        self.base = CompactNeedForSpeedModel(model_dir)
        adapter_dir = Path(adapter_dir)
        with (adapter_dir / "metadata.json").open() as stream:
            self.adapter_metadata = json.load(stream)
        self.coefficients = np.load(
            adapter_dir / "coefficients.npy", mmap_mode="r"
        )
        self.intercept = float(np.load(adapter_dir / "intercept.npy")[0])
        self.adapter_threshold = float(
            self.adapter_metadata["adapter_threshold"]
        )

        expected = int(self.adapter_metadata["feature_count"])
        if self.coefficients.shape != (expected,):
            raise ValueError(
                "adapter coefficient shape does not match its metadata"
            )

    @property
    def metadata(self):
        return self.base.metadata

    def extract_base_components(self, data):
        """Return legacy benign probabilities and reusable PE features."""
        features = self.base.pipeline._extract_features(data)
        dense = (
            features.toarray()
            if hasattr(features, "toarray")
            else np.asarray(features)
        )

        base_malware = np.empty(dense.shape[0], dtype=np.float64)
        for index, row in enumerate(dense):
            base_malware[index] = self.base._row_probability(row)
        return 1.0 - base_malware, features

    def score_adapter(self, features, base_trigger):
        """Score using the policy-adjusted legacy verdict feature."""
        base_trigger = np.asarray(base_trigger, dtype=np.float64).reshape(-1)
        if features.shape[0] != base_trigger.size:
            raise ValueError("base verdict count does not match feature rows")
        adapter_features = sparse.hstack(
            (
                features,
                sparse.csr_matrix(base_trigger.reshape(-1, 1)),
            ),
            format="csr",
        )
        logits = np.asarray(adapter_features @ self.coefficients).reshape(-1)
        logits = np.clip(logits + self.intercept, -40.0, 40.0)
        return 1.0 / (1.0 + np.exp(-logits))

    def predict_components(self, data):
        """Score with the raw legacy verdict without policy context."""
        benign, features = self.extract_base_components(data)
        base_trigger = benign < float(
            self.adapter_metadata["base_benign_threshold"]
        )
        return benign, self.score_adapter(features, base_trigger)

    def predict_proba(self, data):
        """Return legacy probabilities for callers that do not know the adapter."""
        benign, _adapter = self.predict_components(data)
        return np.column_stack((benign, 1.0 - benign))
