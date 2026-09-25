import unittest
from unittest.mock import patch

import numpy as np

from defender.apps import create_app


class FakeModel:
    def __init__(self, benign_probability=0.25):
        self.benign_probability = benign_probability

    def predict_proba(self, _frame):
        return np.array(
            [[self.benign_probability, 1.0 - self.benign_probability]]
        )


class FakeExtractor:
    def __init__(self, _bytez):
        pass

    def extract(self):
        return {"feature": 1}


class FakeAdaptedModel(FakeModel):
    adapter_threshold = 0.8

    def __init__(self, benign_probability, adapter_probability):
        super().__init__(benign_probability)
        self.adapter_probability = adapter_probability

    def predict_components(self, _frame):
        return (
            np.array([self.benign_probability]),
            np.array([self.adapter_probability]),
        )


class FakePolicyAwareAdaptedModel:
    adapter_threshold = 0.8

    def __init__(self, benign_probability=0.51):
        self.benign_probability = benign_probability
        self.base_trigger = None

    def extract_base_components(self, _frame):
        return np.array([self.benign_probability]), np.array([[1.0]])

    def score_adapter(self, _features, base_trigger):
        self.base_trigger = bool(base_trigger[0])
        return np.array([0.9 if self.base_trigger else 0.1])


class FakeReviewer:
    route_min = 0.5
    threshold = 0.6

    def __init__(self, probability):
        self.probability = probability
        self.calls = 0

    def score(self, _attributes, _bytez, **_components):
        self.calls += 1
        return self.probability


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(FakeModel(), 0.75)
        self.client = self.app.test_client()

    def test_rejects_wrong_content_type(self):
        response = self.client.post("/", data=b"MZ", content_type="text/plain")
        self.assertEqual(response.status_code, 400)

    def test_rejects_empty_body(self):
        response = self.client.post(
            "/", data=b"", content_type="application/octet-stream"
        )
        self.assertEqual(response.status_code, 400)

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_returns_integer_result(self):
        response = self.client.post(
            "/", data=b"MZsample", content_type="application/octet-stream"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"result": 1})

    @patch("defender.apps.has_verified_microsoft_signature", return_value=True)
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_verified_microsoft_borderline_score_is_benign(
        self, signature_check
    ):
        app = create_app(FakeModel(0.51), 0.510001)
        response = app.test_client().post(
            "/", data=b"MZsigned", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 0})
        signature_check.assert_called_once_with(b"MZsigned")

    @patch("defender.apps.has_verified_microsoft_signature", return_value=False)
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_untrusted_borderline_score_remains_malicious(self, signature_check):
        app = create_app(FakeModel(0.51), 0.510001)
        response = app.test_client().post(
            "/", data=b"MZunsigned", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})
        signature_check.assert_called_once_with(b"MZunsigned")

    @patch("defender.apps.has_verified_microsoft_signature")
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_override_is_not_used_outside_exact_score_band(self, signature_check):
        app = create_app(FakeModel(0.50), 0.510001)
        response = app.test_client().post(
            "/", data=b"MZsample", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})
        signature_check.assert_not_called()

    @patch("defender.apps.PEAttributeExtractor", side_effect=ValueError("bad PE"))
    def test_parser_failure_fails_closed(self, _extractor):
        response = self.client.post(
            "/", data=b"MZbroken", content_type="application/octet-stream"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"result": 1})

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_adapter_can_detect_legacy_false_negative(self):
        app = create_app(FakeAdaptedModel(0.9, 0.9), 0.510001)
        response = app.test_client().post(
            "/", data=b"MZmodern", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_adapter_can_suppress_legacy_false_positive(self):
        app = create_app(FakeAdaptedModel(0.1, 0.1), 0.510001)
        response = app.test_client().post(
            "/", data=b"MZmodern", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 0})

    @patch("defender.apps.has_verified_microsoft_signature")
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_signature_rule_cannot_override_adapter(self, signature_check):
        app = create_app(FakeAdaptedModel(0.51, 0.9), 0.510001)
        response = app.test_client().post(
            "/", data=b"MZmodern", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})
        signature_check.assert_not_called()



    @patch("defender.apps.has_verified_microsoft_signature", return_value=True)
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_signature_adjusts_legacy_feature_before_adapter(
        self, signature_check
    ):
        model = FakePolicyAwareAdaptedModel()
        app = create_app(model, 0.510001)
        response = app.test_client().post(
            "/", data=b"MZsigned", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 0})
        self.assertFalse(model.base_trigger)
        signature_check.assert_called_once_with(b"MZsigned")

    @patch("defender.apps.has_verified_microsoft_signature", return_value=False)
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_untrusted_legacy_feature_remains_triggered(self, signature_check):
        model = FakePolicyAwareAdaptedModel()
        app = create_app(model, 0.510001)
        response = app.test_client().post(
            "/", data=b"MZunsigned", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})
        self.assertTrue(model.base_trigger)
        signature_check.assert_called_once_with(b"MZunsigned")

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_reviewer_can_suppress_adapter_false_positive(self):
        model = FakePolicyAwareAdaptedModel(benign_probability=0.25)
        model.boundary_reviewer = FakeReviewer(0.2)
        app = create_app(model, 0.510001)
        response = app.test_client().post(
            "/", data=b"MZreview", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 0})
        self.assertEqual(model.boundary_reviewer.calls, 1)

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_reviewer_can_promote_adapter_boundary_sample(self):
        model = FakePolicyAwareAdaptedModel(benign_probability=0.9)
        model.boundary_reviewer = FakeReviewer(0.9)
        model.score_adapter = lambda _features, _trigger: np.array([0.6])
        app = create_app(model, 0.510001)
        response = app.test_client().post(
            "/", data=b"MZreview", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})
        self.assertEqual(model.boundary_reviewer.calls, 1)

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_reviewer_is_skipped_below_route_minimum(self):
        model = FakePolicyAwareAdaptedModel(benign_probability=0.9)
        model.boundary_reviewer = FakeReviewer(0.9)
        model.score_adapter = lambda _features, _trigger: np.array([0.4])
        app = create_app(model, 0.510001)
        response = app.test_client().post(
            "/", data=b"MZreview", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 0})
        self.assertEqual(model.boundary_reviewer.calls, 0)

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_reviewer_failure_fails_closed(self):
        model = FakePolicyAwareAdaptedModel(benign_probability=0.25)
        model.boundary_reviewer = FakeReviewer(0.9)
        model.boundary_reviewer.score = lambda *_args, **_kwargs: 1 / 0
        app = create_app(model, 0.510001)
        response = app.test_client().post(
            "/", data=b"MZreview", content_type="application/octet-stream"
        )
        self.assertEqual(response.get_json(), {"result": 1})

    def test_score_endpoint_is_disabled_by_default(self):
        response = self.client.post(
            "/diagnostics/score",
            data=b"MZsample",
            content_type="application/octet-stream",
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json(), {"error": "not found"})

    @patch("defender.apps.has_verified_microsoft_signature", return_value=True)
    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_score_endpoint_returns_exact_adapter_components(
        self, signature_check
    ):
        model = FakePolicyAwareAdaptedModel()
        app = create_app(model, 0.510001)
        app.config["SCORE_ENDPOINT_ENABLED"] = True
        response = app.test_client().post(
            "/diagnostics/score",
            data=b"MZsigned",
            content_type="application/octet-stream",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "result": 0,
                "benign_probability": 0.51,
                "adapter_probability": 0.1,
                "adapter_threshold": 0.8,
                "base_trigger_raw": 1,
                "base_trigger_adjusted": 0,
                "signature_checked": True,
                "signature_verified": True,
            },
        )
        signature_check.assert_called_once_with(b"MZsigned")

    @patch("defender.apps.PEAttributeExtractor", side_effect=ValueError("bad PE"))
    def test_score_endpoint_reports_fail_closed_error(self, _extractor):
        app = create_app(FakeModel(), 0.75)
        app.config["SCORE_ENDPOINT_ENABLED"] = True
        response = app.test_client().post(
            "/diagnostics/score",
            data=b"MZbroken",
            content_type="application/octet-stream",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"result": 1, "error": "classification_failed"},
        )

    @patch("defender.apps.PEAttributeExtractor", FakeExtractor)
    def test_score_endpoint_returns_reviewer_components(self):
        model = FakePolicyAwareAdaptedModel(benign_probability=0.25)
        model.boundary_reviewer = FakeReviewer(0.2)
        app = create_app(model, 0.510001)
        app.config["SCORE_ENDPOINT_ENABLED"] = True
        response = app.test_client().post(
            "/diagnostics/score",
            data=b"MZreview",
            content_type="application/octet-stream",
        )
        details = response.get_json()
        self.assertEqual(details["result"], 0)
        self.assertTrue(details["reviewer_routed"])
        self.assertEqual(details["reviewer_probability"], 0.2)
        self.assertEqual(details["reviewer_threshold"], 0.6)


if __name__ == "__main__":
    unittest.main()
