import math
import unittest
from pathlib import Path

from defender.models.boundary_reviewer import BoundaryReviewer
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


if __name__ == "__main__":
    unittest.main()
