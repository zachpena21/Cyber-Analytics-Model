"""Version-aware runtime for exported boundary-reviewer models."""

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
DERIVED_FEATURES = (
    "code_to_file_ratio",
    "virtual_to_file_ratio",
    "imports_per_section",
    "exports_per_section",
    "section_density",
    "has_exports",
    "large_export_table",
    "amd64_pe32plus",
    "amd64_pe32plus_many_sections",
    "modern_amd64_linker",
)
IMPORT_LIBRARIES = ("ntoskrnl.exe", "hal.dll", "ndis.sys", "wdfldr.sys", "ks.sys")
IMPORT_FEATURES = tuple("import_library=" + name for name in IMPORT_LIBRARIES) + (
    "kernel_driver_import_count",
)
BUILD_FEATURES = (
    "linker_major_equals_2", "coff_symbols_present", "debug_directory_absent",
    "linker2_with_symbols", "linker2_symbols_no_debug_with_tls",
)


def _build_values(attributes):
    linker2 = float(_finite_number(attributes.get("major_linker_version")) == 2)
    symbols = float(_finite_number(attributes.get("symbols")) > 0)
    no_debug = float(_finite_number(attributes.get("has_debug")) == 0)
    tls = float(_finite_number(attributes.get("has_tls")) > 0)
    return (linker2, symbols, no_debug, linker2 * symbols,
            linker2 * symbols * no_debug * tls)


def _import_values(attributes):
    """Fixed ordinary-import identities; no filenames or labels are used."""
    libraries = {token.replace("\\", "/").rsplit("/", 1)[-1].casefold()
                 for token in _tokens(attributes.get("libraries"))}
    flags = [float(name in libraries) for name in IMPORT_LIBRARIES]
    return tuple(flags + [sum(flags)])


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


def _safe_ratio(numerator, denominator):
    numerator = _finite_number(numerator)
    denominator = _finite_number(denominator)
    if denominator <= 0.0:
        return 0.0
    value = numerator / denominator
    return value if math.isfinite(value) else 0.0


def _derived_values(attributes, byte_size):
    virtual_size = _finite_number(attributes.get("virtual_size"))
    sizeof_code = _finite_number(attributes.get("sizeof_code"))
    imports = _finite_number(attributes.get("imports"))
    exports = _finite_number(attributes.get("exports"))
    sections = _finite_number(attributes.get("numberof_sections"))
    linker_major = _finite_number(attributes.get("major_linker_version"))
    machine = str(attributes.get("machine", ""))
    magic = str(attributes.get("magic", ""))
    amd64 = float(machine == "MACHINE_TYPES.AMD64")
    pe32plus = float(magic == "PE32_PLUS")
    amd64_pe32plus = amd64 * pe32plus
    return (
        _safe_ratio(sizeof_code, byte_size),
        _safe_ratio(virtual_size, byte_size),
        _safe_ratio(imports, sections),
        _safe_ratio(exports, sections),
        _safe_ratio(byte_size, sections),
        float(exports > 0.0),
        float(exports >= 32.0),
        amd64_pe32plus,
        float(amd64_pe32plus == 1.0 and sections >= 6.0),
        float(amd64 == 1.0 and 12.0 <= linker_major <= 14.0),
    )


class BoundaryReviewer:
    """Evaluate exported shallow-forest or gradient-boosted reviewers."""

    def __init__(self, model_path):
        model_path = Path(model_path)
        with model_path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
        self._load(payload)

    def _load(self, payload):
        required = {
            "format_version",
            "route_min",
            "reviewer_threshold",
            "feature_names",
            "categories",
        }
        missing = required - set(payload)
        if missing:
            raise ValueError(
                "reviewer model is missing keys: " + ", ".join(sorted(missing))
            )
        self.format_version = int(payload["format_version"])
        if self.format_version not in {1, 5, 6, 7, 8, 9}:
            raise ValueError(f"unsupported reviewer format {self.format_version!r}")
        self.input_dtype = "float32" if self.format_version in {7, 8, 9} else "float64"
        if self.format_version in {7, 8, 9} and payload.get("input_dtype") != "float32":
            raise ValueError(f"format {self.format_version} reviewer requires float32 input_dtype")

        self.route_min = float(payload["route_min"])
        self.threshold = float(payload["reviewer_threshold"])
        if not 0.0 <= self.route_min <= 1.0:
            raise ValueError("reviewer route_min must be between zero and one")
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("reviewer threshold must be between zero and one")

        self.feature_names = tuple(payload["feature_names"])
        self.categories = payload["categories"]
        self.derived_features = tuple(payload.get("derived_features", ()))
        if self.format_version in {5, 6, 7, 8, 9} and self.derived_features != DERIVED_FEATURES:
            raise ValueError("reviewer derived feature order does not match runtime")
        if self.format_version == 1 and self.derived_features:
            raise ValueError("legacy reviewer unexpectedly contains derived features")
        self.import_features = tuple(payload.get("import_features", ()))
        if self.format_version in {8, 9}:
            if self.import_features != IMPORT_FEATURES:
                raise ValueError("reviewer import feature order does not match runtime")
        elif self.import_features:
            raise ValueError("legacy reviewer unexpectedly contains import features")
        self.build_features = tuple(payload.get("build_features", ()))
        if self.format_version == 9:
            if self.build_features != BUILD_FEATURES:
                raise ValueError("reviewer build feature order does not match runtime")
        elif self.build_features:
            raise ValueError("legacy reviewer unexpectedly contains build features")

        expected_names = self._expected_feature_names()
        if self.feature_names != expected_names:
            raise ValueError("reviewer feature order does not match runtime")

        self.model_type = payload.get("model_type", "forest")
        if self.format_version in {1, 5}:
            if self.model_type != "forest":
                raise ValueError("forest reviewer payload has wrong model_type")
            self.estimators = tuple(payload.get("estimators", ()))
            if not self.estimators:
                raise ValueError("reviewer forest has no estimators")
            self._validate_estimators(self.estimators, leaf_name="malware_probability")
        else:
            if self.model_type != "gradient_boosting":
                raise ValueError("gradient boosted reviewer has wrong model_type")
            self.learning_rate = float(payload["learning_rate"])
            self.initial_raw_score = float(payload["initial_raw_score"])
            if not math.isfinite(self.learning_rate) or self.learning_rate <= 0.0:
                raise ValueError("invalid gradient boosting learning rate")
            if not math.isfinite(self.initial_raw_score):
                raise ValueError("invalid gradient boosting initial score")
            self.estimators = tuple(payload.get("estimators", ()))
            if not self.estimators:
                raise ValueError("gradient boosted reviewer has no estimators")
            self._validate_estimators(self.estimators, leaf_name="raw_value")

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
        if self.derived_features:
            names.extend(self.derived_features)
        for field in CATEGORICAL_FIELDS:
            if field not in self.categories:
                raise ValueError(f"reviewer categories missing {field}")
            names.extend(f"{field}={value}" for value in self.categories[field])
        names.extend(getattr(self, "import_features", ()))
        names.extend(getattr(self, "build_features", ()))
        return tuple(names)

    def _validate_estimators(self, estimators, leaf_name):
        for estimator in estimators:
            required = (
                "children_left",
                "children_right",
                "feature",
                "threshold",
                leaf_name,
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
                threshold = float(estimator["threshold"][node])
                leaf_value = float(estimator[leaf_name][node])
                if not math.isfinite(threshold) or not math.isfinite(leaf_value):
                    raise ValueError("reviewer contains non-finite tree value")
                if leaf_name == "malware_probability" and not 0.0 <= leaf_value <= 1.0:
                    raise ValueError("reviewer contains invalid leaf probability")
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
        values.extend(_finite_number(attributes.get(name)) for name in EXTRA_NUMERIC)
        byte_size = float(len(bytez))
        values.extend((byte_size, _byte_entropy(bytez)))
        for field in TEXT_FIELDS:
            field_tokens = _tokens(attributes.get(field))
            values.extend(
                (
                    float(len(field_tokens)),
                    float(len(set(field_tokens))),
                    float(len(str(attributes.get(field, "") or ""))),
                )
            )
        if self.derived_features:
            values.extend(_derived_values(attributes, byte_size))
        for field in CATEGORICAL_FIELDS:
            actual = str(attributes.get(field, ""))
            values.extend(float(actual == value) for value in self.categories[field])
        if self.import_features:
            values.extend(_import_values(attributes))
        if self.build_features:
            values.extend(_build_values(attributes))
        if len(values) != len(self.feature_names):
            raise ValueError("reviewer runtime feature count changed")
        return values

    @staticmethod
    def _tree_leaf(estimator, vector, leaf_name):
        node = 0
        while estimator["children_left"][node] >= 0:
            feature = estimator["feature"][node]
            node = (
                estimator["children_left"][node]
                if vector[feature] <= estimator["threshold"][node]
                else estimator["children_right"][node]
            )
        return float(estimator[leaf_name][node])

    def score(self, attributes, bytez, **components):
        vector = self._vectorize(attributes, bytez, components)
        if self.input_dtype == "float32":
            # sklearn converts tree inputs to float32 before comparing them
            # against double-precision split thresholds. Legacy formats retain
            # their original traversal behavior for historical score parity.
            vector = np.asarray(vector, dtype=np.float32).tolist()
        if self.model_type == "forest":
            return float(
                np.mean(
                    [
                        self._tree_leaf(estimator, vector, "malware_probability")
                        for estimator in self.estimators
                    ]
                )
            )

        raw = self.initial_raw_score + self.learning_rate * sum(
            self._tree_leaf(estimator, vector, "raw_value")
            for estimator in self.estimators
        )
        if raw >= 0.0:
            z = math.exp(-raw)
            return 1.0 / (1.0 + z)
        z = math.exp(raw)
        return z / (1.0 + z)
