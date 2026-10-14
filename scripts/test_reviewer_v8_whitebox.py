import copy
import json
from pathlib import Path
import unittest

import prepare_reviewer_v8_whitebox as prep
from serve_reviewer_v8_whitebox import checked_candidate


class WhiteboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (Path(__file__).resolve().parents[1]/'defender/defender/models/boundary_reviewer_v8_final/model.json').read_bytes()

    def test_only_threshold_changes_and_crlf_is_accepted(self):
        before, after = prep.candidate_from_bytes(self.raw.replace(b'\n', b'\r\n'))
        self.assertEqual([k for k in before if before[k] != after[k]], ['reviewer_threshold'])
        self.assertEqual(checked_candidate(self.raw, json.dumps(after).encode()), after)
        after['estimators'][0]['raw_value'][0] += 1
        with self.assertRaises(ValueError):
            checked_candidate(self.raw, json.dumps(after).encode())

    def test_route_and_threshold_boundaries(self):
        self.assertEqual(prep.decision(dict(score=.6, adapter=.15), .6), 1)
        self.assertEqual(prep.decision(dict(score=1., adapter=.149999), .6), 0)
        self.assertEqual(prep.decision(dict(score=.599999, adapter=.99), .6), 0)

    def test_corrupted_baseline_and_incomplete_report_rejected(self):
        with self.assertRaises(ValueError):
            prep.candidate_from_bytes(self.raw + b' ')
        before, _ = prep.candidate_from_bytes(self.raw)
        with self.assertRaises(ValueError):
            prep.ta_rows(dict(complete=False), before)

    def test_paired_rescue_and_false_positive_are_separate(self):
        rows = [dict(sha256='a', label=1, score=.602, adapter=.99, baseline_result=0),
                dict(sha256='b', label=0, score=.62, adapter=.9, baseline_result=0),
                dict(sha256='c', label=0, score=.7, adapter=.1, baseline_result=0)]
        result = prep.compare(rows)
        self.assertEqual(result['candidate']['true_positives'], 1)
        self.assertEqual(result['candidate']['false_positives'], 1)
        self.assertEqual(len(result['changed']), 2)
        rows[0]['baseline_result'] = 1
        with self.assertRaises(ValueError):
            prep.compare(rows)


if __name__ == '__main__':
    unittest.main()
