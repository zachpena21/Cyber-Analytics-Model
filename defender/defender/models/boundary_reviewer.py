"""Version-independent runtime for the exported boundary-reviewer forest."""

import base64
import gzip
import json
import math
from pathlib import Path

import numpy as np

from defender.models.nfs_model import NeedForSpeedModel


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


def _finite_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _tokens(value):
    return [item for item in str(value or "").split() if item]


def _byte_entropy(bytez):
    if not bytez:
        return 0.0
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0].astype(np.float64) / len(bytez)
    return float(-(probabilities * np.log2(probabilities)).sum())


class BoundaryReviewer:
    """Evaluate a shallow exported forest without loading sklearn objects."""

    def __init__(self, model_path):
        model_path = Path(model_path)
        if model_path.is_file():
            with model_path.open(encoding="utf-8") as stream:
                payload = json.load(stream)
        else:
            # Large reviewer exports can be stored as a gzip-compressed,
            # base64-encoded sequence of text chunks. This keeps the repository
            # transport text-only while reconstructing the exact JSON payload at
            # startup. Normal model.json files remain the preferred/default path.
            parts = sorted(
                model_path.parent.glob(model_path.name + ".gz.b64.part-*")
            )
            if not parts:
                raise FileNotFoundError(model_path)
            encoded = "".join(
                part.read_text(encoding="ascii").strip() for part in parts
            )
            payload = json.loads(
                gzip.decompress(base64.b64decode(encoded)).decode("utf-8")
            )
        self._load(payload)

    def _load(self, payload):
        required = {
            "format_version",
            "route_min",
            "reviewer_threshold",
            "feature_names",
            "categories",
            "estimators",
        }
        missing = required - set(payload)
        if missing:
            raise ValueError(
                "reviewer model is missing keys: "
                + ", ".join(sorted(missing))
            )
        if payload["format_version"] != 1:
            raise ValueError(
                f"unsupported reviewer format {payload['format_version']!r}"
            )
        self.route_min = float(payload["route_min"])
        self.threshold = float(payload["reviewer_threshold"])
        if not 0.0 <= self.route_min <= 1.0:
            raise ValueError("reviewer route_min must be between zero and one")
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("reviewer threshold must be between zero and one")
        self.feature_names = tuple(payload["feature_names"])
        self.categories = payload["categories"]
        self.estimators = tuple(payload["estimators"])
        if not self.estimators:
            raise ValueError("reviewer forest has no estimators")
        expected_names = self._expected_feature_names()
        if self.feature_names != expected_names:
            raise ValueError("reviewer feature order does not match runtime")
        self._validate_estimators()

    def _expected_feature_names(self):
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
            if field not in self.categories:
                raise ValueError(f"reviewer categories missing {field}")
            names.extend(
                f"{field}={value}" for value in self.categories[field]
            )
        return tuple(names)

    def _validate_estimators(self):
        for estimator in self.estimators:
            required = (
                "children_left",
                "children_right",
                "feature",
                "threshold",
                "malware_probability",
            )
            if any(name not in estimator for name in required):
                raise ValueError("reviewer estimator is missing an array")
            size = len(estimator["feature"])
            if size == 0 or any(len(estimator[name]) != size for name in required):
                raise ValueError("reviewer estimator arrays have different sizes")
            for node in range(size):
                left = int(estimator["children_left"][node])
                right = int(estimator["children_right"][node])
                feature = int(estimator["feature"][node])
                probability = float(estimator["malware_probability"][node])
                threshold = float(estimator["threshold"][node])
                if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
                    raise ValueError("reviewer contains invalid leaf probability")
                if not math.isfinite(threshold):
                    raise ValueError("reviewer contains non-finite threshold")
                if left < 0:
                    if right >= 0:
                        raise ValueError("reviewer leaf has inconsistent children")
                elif not (
                    0 <= left < size
                    and 0 <= right < size
                    and 0 <= feature < len(self.feature_names)
                ):
                    raise ValueError("reviewer contains invalid node index")

    def _vectorize(self, attributes, bytez, components):
        values = [_finite_number(components[name]) for name in SCORE_FEATURES]
        values.extend(
            _finite_number(attributes.get(name))
            for name in NeedForSpeedModel.NUMERICAL_ATTRIBUTES
        )
        values.extend(
            _finite_number(attributes.get(name)) for name in EXTRA_NUMERIC
        )
        values.extend((float(len(bytez)), _byte_entropy(bytez)))
        for field in TEXT_FIELDS:
            field_tokens = _tokens(attributes.get(field))
            values.extend(
                (
                    float(len(field_tokens)),
                    float(len(set(field_tokens))),
                    float(len(str(attributes.get(field, "") or ""))),
                )
            )
        for field in CATEGORICAL_FIELDS:
            actual = str(attributes.get(field, ""))
            values.extend(
                float(actual == value) for value in self.categories[field]
            )
        if len(values) != len(self.feature_names):
            raise ValueError("reviewer runtime feature count changed")
        return values

    @staticmethod
    def _tree_probability(estimator, vector):
        node = 0
        while estimator["children_left"][node] >= 0:
            feature = estimator["feature"][node]
            node = (
                estimator["children_left"][node]
                if vector[feature] <= estimator["threshold"][node]
                else estimator["children_right"][node]
            )
        return float(estimator["malware_probability"][node])

    def score(self, attributes, bytez, **components):
        vector = self._vectorize(attributes, bytez, components)
        return float(
            np.mean(
                [
                    self._tree_probability(estimator, vector)
                    for estimator in self.estimators
                ]
            )
        )
