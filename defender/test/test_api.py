import unittest
from unittest.mock import patch

from defender.apps import create_app


class FakeModel:
    def __init__(self, result=1):
        self.result = result

    def predict_threshold(self, _frame, _threshold):
        return [self.result]


class FakeExtractor:
    def __init__(self, _bytez):
        pass

    def extract(self):
        return {"feature": 1}


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

    @patch("defender.apps.PEAttributeExtractor", side_effect=ValueError("bad PE"))
    def test_parser_failure_fails_closed(self, _extractor):
        response = self.client.post(
            "/", data=b"MZbroken", content_type="application/octet-stream"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"result": 1})


if __name__ == "__main__":
    unittest.main()
