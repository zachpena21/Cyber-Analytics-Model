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


if __name__ == "__main__":
    unittest.main()
