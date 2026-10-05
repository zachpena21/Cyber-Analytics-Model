#!/usr/bin/env python3
"""Synthetic checks only; no malware or network access."""
import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
import reviewer_v8_structural_feature_diagnostics as m


def row(label=1, primary=0, old=0, expanded=0, routed=True):
    return dict(label=label, structural_primary_prediction=primary,
                structural_primary_routed=routed, v7_prediction=old,
                v8_import_upper_prediction=expanded, source='synthetic',
                adapter_probability=.8, benign_probability=.5, structural_primary_score=.2,
                v7_score=.1, v8_import_upper_score=.1, bounded_logit_correction=0.)


class DiagnosticsTests(unittest.TestCase):
    def test_gate_and_reference_cohorts(self):
        cases = [
            (row(routed=False), 'malware_gate_miss'),
            (row(old=1, expanded=1), 'malware_miss_both_references_detect'),
            (row(old=1), 'malware_miss_v7_only_detects'),
            (row(expanded=1), 'malware_miss_expanded_only_detects'),
            (row(), 'malware_miss_all_references'),
            (row(primary=1), 'malware_detected'),
            (row(label=0, primary=1), 'benign_false_positive'),
            (row(label=0), 'benign_correct')]
        for record, expected in cases:
            self.assertEqual(m.cohort(record), expected)

    def test_parity_rejects_score_and_decision_changes(self):
        saved = row()
        current = copy.deepcopy(saved)
        current['structural_primary_score'] += 1e-12
        self.assertLess(m.verify_row(saved, current), 1e-9)
        current['structural_primary_score'] += 1e-5
        with self.assertRaises(ValueError):
            m.verify_row(saved, current)
        current = dict(saved, structural_primary_prediction=1)
        with self.assertRaises(ValueError):
            m.verify_row(saved, current)
        current = dict(saved, structural_primary_score=float('nan'))
        with self.assertRaises(ValueError):
            m.verify_row(saved, current)
        current = dict(saved)
        current.pop('source')
        with self.assertRaises(ValueError):
            m.verify_row(saved, current)

    def test_sha_identity_and_label_validation(self):
        record = dict(row(), sha256='a' * 64)
        self.assertEqual(len(m.unique_records([record])), 1)
        for records in ([], [record, record], [dict(record, label=2)],
                        [dict(record, sha256='invalid')]):
            with self.assertRaises(ValueError):
                m.unique_records(records)

    def test_profiles_use_same_label_correct_controls(self):
        names = ['upstream' + str(i) for i in range(6)] + ['size', 'entropy']
        keys = [str(i) * 64 for i in range(1, 5)]
        records = dict(zip(keys, [row(), row(primary=1), row(label=0, primary=1), row(label=0)]))
        features = {key: dict(vector=[0.] * 6 + [float(i), .5], libraries='synthetic.dll')
                    for i, key in enumerate(keys)}
        calls = []
        def profile(X, schema, ids, reference):
            calls.append((ids, reference))
            return dict(features={}, largest_standardized_median_shifts=[])
        v = SimpleNamespace(q=SimpleNamespace(feature_profiles=profile),
                            d=SimpleNamespace(distribution=lambda values: dict(count=len(values))))
        report, errors = m.analyze(v, records, features, names)
        self.assertEqual(sum(c['count'] for c in report['cohorts'].values()), 4)
        self.assertEqual(len(errors), 2)
        self.assertCountEqual(calls, [([0], [1]), ([2], [3])])
        self.assertEqual(report['cohorts']['malware_miss_all_references']['reference_count'], 1)
        features[keys[1]]['vector'] = features[keys[0]]['vector'][:]
        report, _ = m.analyze(v, records, features, names)
        self.assertEqual(len(report['repeated_exact_inputs_containing_errors']), 1)
        self.assertEqual(set(report['repeated_exact_inputs_containing_errors'][0]['samples']), set(keys[:2]))

    def test_discovery_requires_matching_completed_evaluation(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'freeze-manifest.json').write_text('{}')
            sources = root / 'sources.json'
            sources.write_text('[]')
            good = root / 'reviewer-v8-structural-evaluation-good'
            bad = root / 'reviewer-v8-structural-evaluation-bad'
            for path, source_digest in ((good, m.digest(sources)), (bad, 'wrong')):
                path.mkdir()
                (path / 'evaluation-manifest.json').write_text(json.dumps(dict(
                    complete=True, freeze_manifest_sha256=m.digest(bundle / 'freeze-manifest.json'),
                    sources_sha256=source_digest)))
                (path / 'comparison-summary.json').write_text('{"complete": true}')
            self.assertEqual(m.find_evaluation(root, bundle, sources), good)
            (good / 'comparison-summary.json').write_text('{"complete": false}')
            with self.assertRaises(ValueError):
                m.find_evaluation(root, bundle, sources)


if __name__ == '__main__':
    unittest.main()
