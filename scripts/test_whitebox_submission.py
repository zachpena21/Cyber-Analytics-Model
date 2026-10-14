import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'defender'))
from defender.whitebox_main import verify_reviewer
from defender.reviewer_rescue import POLICY
import check_whitebox_submission_public as public


class SubmissionTests(unittest.TestCase):
    def test_frozen_model_identity_rejects_changed_policy(self):
        path = Path(__file__).resolve().parents[1]/'defender/defender/models/boundary_reviewer_v8_whitebox_t060/model.json'
        raw = path.read_bytes().replace(b'\r\n', b'\n')
        self.assertEqual(verify_reviewer(raw)['reviewer_threshold'], .6)
        changed = json.loads(raw); changed['reviewer_threshold'] = .3
        with self.assertRaises(ValueError):
            verify_reviewer(json.dumps(changed).encode())

    def run_public(self, bad_sample=False, diagnostics=False):
        info = dict(score_endpoint_enabled=diagnostics, reviewer_threshold=.6, reviewer_route_min=.15,
                    reviewer_agreement_rescue=POLICY, threshold=.510001, adapter_threshold=.7)
        samples = [(dict(sha256=str(i), is_malware=i >= 50), bytes([i])) for i in range(100)]
        def request(url, raw=None):
            if url.endswith('/model'):
                return info
            if url.endswith('/diagnostics/score'):
                raise urllib.error.HTTPError(url, 404, 'not found', {}, None)
            if bad_sample and raw[0] == 50:
                return dict(result=1, error='classification_failed')
            return dict(result=int(raw[0] >= 50))
        with patch.object(public, 'request', side_effect=request), patch.object(public, 'load_samples', return_value=samples):
            return public.run(Path('unused.zip'), 'http://local')

    def test_public_api_all_samples_and_disabled_diagnostics(self):
        result = self.run_public()
        self.assertTrue(result['passed'])
        self.assertEqual(result['malware_detected'], 50)
        self.assertEqual(result['benign_correct'], 50)

    def test_fail_closed_response_is_not_counted_as_success(self):
        result = self.run_public(bad_sample=True)
        self.assertFalse(result['passed'])
        self.assertEqual(result['errors'], 1)

    def test_enabled_diagnostics_rejected(self):
        with self.assertRaises(ValueError):
            self.run_public(diagnostics=True)


if __name__ == '__main__':
    unittest.main()
