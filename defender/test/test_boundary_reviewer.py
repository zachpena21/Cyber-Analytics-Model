import math
import unittest
from pathlib import Path

from defender.models.boundary_reviewer import BoundaryReviewer, DERIVED_FEATURES
from defender.models.nfs_model import NeedForSpeedModel


class BoundaryReviewerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model_path = (
            Path(__file__).resolve().parents[1]
            / "defender"
            / "models"
            / "boundary_reviewer"
            / "model.json"
        )
        cls.reviewer = BoundaryReviewer(model_path)

    def test_exported_model_loads_with_expected_shape(self):
        self.assertEqual(len(self.reviewer.estimators), 128)
        self.assertEqual(len(self.reviewer.feature_names), 53)
        self.assertEqual(self.reviewer.route_min, 0.5)
        self.assertAlmostEqual(self.reviewer.threshold, 0.6831506122881276)

    def test_score_is_finite_probability(self):
        attributes = {
            name: 0.0 for name in NeedForSpeedModel.NUMERICAL_ATTRIBUTES
        }
        attributes.update(
            machine="MACHINE_TYPES.I386",
            magic="PE32",
            string_paths=0,
            string_urls=0,
            string_registry=0,
            string_MZ=1,
            libraries="",
            functions="",
            exports_list="",
            dll_characteristics_list="",
            characteristics_list="",
        )
        probability = self.reviewer.score(
            attributes,
            b"MZ",
            benign_probability=0.5,
            adapter_probability=0.7,
            base_trigger_raw=1,
            base_trigger_adjusted=1,
            signature_checked=False,
            signature_verified=None,
        )
        self.assertTrue(math.isfinite(probability))
        self.assertGreaterEqual(probability, 0.0)
        self.assertLessEqual(probability, 1.0)


class ReviewerPrecisionTests(unittest.TestCase):
    def make_reviewer(self, version):
        reviewer = BoundaryReviewer.__new__(BoundaryReviewer)
        reviewer.categories = dict(machine=["MACHINE_TYPES.AMD64"], magic=["PE32_PLUS"])
        reviewer.derived_features = DERIVED_FEATURES
        payload = dict(format_version=version, route_min=.15, reviewer_threshold=.5,
                       feature_names=list(reviewer._expected_feature_names()),
                       categories=reviewer.categories, derived_features=list(DERIVED_FEATURES),
                       model_type="gradient_boosting", learning_rate=1., initial_raw_score=0.,
                       estimators=[dict(children_left=[1, -1, -1], children_right=[2, -1, -1],
                                        feature=[0, -2, -2], threshold=[.5, -2., -2.],
                                        raw_value=[0., -2., 2.])])
        if version == 7:
            payload["input_dtype"] = "float32"
        reviewer._load(payload)
        return reviewer, payload

    def test_new_format_rounds_inputs_before_tree_comparison(self):
        components = dict(benign_probability=.50000001, adapter_probability=.7,
                          base_trigger_raw=0, base_trigger_adjusted=0,
                          signature_checked=0, signature_verified=0)
        modern, _ = self.make_reviewer(7)
        legacy, _ = self.make_reviewer(6)
        self.assertAlmostEqual(modern.score({}, b"MZ", **components), 1. / (1. + math.exp(2.)))
        self.assertAlmostEqual(legacy.score({}, b"MZ", **components), 1. / (1. + math.exp(-2.)))

    def test_new_format_requires_explicit_precision(self):
        reviewer, payload = self.make_reviewer(7)
        payload.pop("input_dtype")
        with self.assertRaisesRegex(ValueError, "requires float32"):
            reviewer._load(payload)


if __name__ == "__main__":
    unittest.main()
