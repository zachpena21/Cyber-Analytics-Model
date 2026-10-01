"""Self-contained regression checks for v8 diagnostics."""
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np

import reviewer_v8_diagnostics as d
import reviewer_v8_workflow as w
import reviewer_v8_import_experiment as e
import test_reviewer_v8_imports as import_tests


class DiagnosticTests(unittest.TestCase):
    def test_weighted_calibration_matches_workflow_with_ties_and_empty_weights(self):
        rng = np.random.RandomState(37)
        rows = [dict(source='a' if i < 140 else 'b', label=int(i % 8 == 0)) for i in range(280)]
        for scores in (rng.uniform(0, 1, len(rows)), np.round(rng.uniform(0, 1, len(rows)), 1)):
            for _ in range(8):
                weights = rng.randint(0, 4, len(rows))
                expanded = [r for r, n in zip(rows, weights) for _ in range(n)]
                repeated = np.repeat(scores, weights)
                try:
                    expected, _, _ = w.calibrate(expanded, repeated)
                except ValueError:
                    with self.assertRaisesRegex(ValueError, 'No valid bootstrap threshold'):
                        d.weighted_threshold(rows, scores, weights)
                else:
                    self.assertEqual(d.weighted_threshold(rows, scores, weights), expected)
        with self.assertRaisesRegex(ValueError, 'Both classes'):
            d.weighted_threshold([dict(source='a', label=0)], [.5], [1])

    def test_full_diagnostics_on_controlled_import_fixture(self):
        original = e.experiment
        captured = []
        def experiment(rows, cached, frozen, baseline, output):
            metadata = original(rows, cached, frozen, baseline, output)
            report, errors = d.diagnose(rows, cached, frozen, baseline, output,
                                       Path(output).parent / 'diagnostics', repeats=10)
            self.assertEqual(len(report['source_holdouts']), 4)
            expected_errors = sum(f['models']['import_candidate']['heldout']['fp']
                                  + f['models']['import_candidate']['heldout']['fn']
                                  for f in metadata['leave_one_source_out'])
            self.assertEqual(len(errors), expected_errors)
            for fold in report['source_holdouts']:
                for model in fold['models'].values():
                    self.assertEqual(model['repeats'], 10)
                    self.assertLessEqual(model['threshold_quantiles']['min'], model['threshold_quantiles']['max'])
            for error in errors:
                for peer in error['comparisons']['same_class_correct']:
                    self.assertEqual(peer['label'], error['label'])
                    self.assertNotEqual(peer['sha256'], error['sha256'])
                self.assertLessEqual(len(error['comparisons']['same_class_correct']), 5)
            captured.append(True)
            return metadata
        with patch.object(e, 'experiment', experiment):
            import_tests.ReviewerImportTests('test_controlled_experiment_and_holdout_isolation').test_controlled_experiment_and_holdout_isolation()
        self.assertEqual(captured, [True])


if __name__ == '__main__':
    unittest.main()
