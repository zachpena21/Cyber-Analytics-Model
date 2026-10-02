"""Separate grouping panels, alias isolation, diverse calibration and control export."""
from collections import Counter
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_grouping_controls as c
from test_reviewer_v8_grouped_experiment import NAMES, entry, pool


class GroupingControlTests(unittest.TestCase):
    def test_panels_do_not_union_coarse_templates_with_software_cohorts(self):
        keys = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
        entries = {sha: entry(sha, label=0, group=i) for i, sha in enumerate(keys)}
        # A/B share software. B/C share a coarse template but differ in runtime
        # structural entropy. C/D share a different software family.
        entries[keys[0]]['record']['source'] = 'portablegit-one'
        entries[keys[1]]['record']['source'] = 'portablegit-two'
        entries[keys[2]]['feature_vector'] = list(entries[keys[1]]['feature_vector'])
        entries[keys[2]]['feature_vector'][NAMES.index('byte_entropy')] += .1
        for sha in keys[2:]:
            entries[sha]['provenance'] = {'provenance': {'package': 'numpy'}}
        old = c.g.make_groups(entries, NAMES)
        self.assertEqual(len(set(old.values())), 1)
        provenance = c.mode_groups(entries, NAMES, 'provenance')
        self.assertEqual(provenance[keys[0]], provenance[keys[1]])
        self.assertEqual(provenance[keys[2]], provenance[keys[3]])
        self.assertNotEqual(provenance[keys[1]], provenance[keys[2]])
        template = c.mode_groups(entries, NAMES, 'template')
        self.assertEqual(template[keys[1]], template[keys[2]])
        self.assertNotEqual(template[keys[0]], template[keys[1]])
        # An exact representation alias remains linked in both panels even
        # if labels/provenance differ. No score is part of the fingerprint.
        entries[keys[2]]['feature_vector'] = list(entries[keys[1]]['feature_vector'])
        entries[keys[2]]['record']['label'] = 1
        for mode in c.MODES:
            groups = c.mode_groups(entries, NAMES, mode)
            self.assertEqual(groups[keys[1]], groups[keys[2]])

    def test_feature_profile_distinguishes_vectors_from_shared_scores(self):
        entries = pool(groups=1, size=2); keys = sorted(entries)
        profile = c.feature_profile(keys, entries, NAMES)
        self.assertEqual(profile['count'], 4)
        self.assertEqual(profile['structural_float32_unique'], 2)
        self.assertEqual(profile['structural_plus_import_representation_unique'], 2)
        self.assertIn('byte_entropy', profile['variable_structural_features'])
        self.assertEqual(profile['constant_structural_features']['numberof_sections'], 10.)
        self.assertEqual(profile['zero_section_count'], 0)

    def test_calibration_avoids_single_malware_component_without_using_scores(self):
        rows = []; groups = {}; fingerprints = {}; ids = []
        for fold in range(5):
            for label in (0, 1):
                for i in range(40):
                    sha = hashlib.sha256(f'{fold}:{label}:{i}'.encode()).hexdigest()
                    rows.append(dict(sha256=sha, label=label, adapter_probability=.9))
                    groups[sha] = f'{fold}:{label}:same' if fold == 0 and label == 1 else f'{fold}:{label}:{i // 5}'
                    fingerprints[sha] = groups[sha]; ids.append(fold)
        plan = c.split_plan(rows, groups, fingerprints, np.array(ids))
        for fold in plan:
            self.assertTrue(fold['calibration_diversity']['diverse'])
            self.assertTrue(fold['fit_diversity']['diverse'])
            c.assert_split(rows, groups, [fold[k] for k in ('fit', 'calibration', 'held')])
            self.assertFalse(any(ids[i] == 0 for i in fold['calibration']))
        one_group = {r['sha256']: 'all' for r in rows}
        with self.assertRaisesRegex(ValueError, 'No diverse'):
            c.split_plan(rows, one_group, fingerprints, np.array(ids))

    def test_zero_recall_is_ineligible_even_when_fpr_is_feasible(self):
        policy = dict(feasible=True, threshold=1., overall={'tpr': 0., 'fpr': 0.})
        result = c.assess_policy(policy, {'diverse': True})
        self.assertTrue(result['zero_recall'])
        self.assertFalse(result['eligible_development_policy'])
        self.assertNotIn('zero_recall', policy)

    def test_completed_component_audit_and_two_control_panels(self):
        entries = pool(); config = dict(n_estimators=8, learning_rate=.1, max_depth=2,
                                        min_samples_leaf=2, max_features=None, subsample=1.)
        with tempfile.TemporaryDirectory() as directory, patch.dict(c.g.f.w.CONFIG, config, clear=True), \
                patch.dict(c.g.SKIMMER_CONFIG, config, clear=True), patch('builtins.print'):
            root = Path(directory); previous = root / 'previous'; output = root / 'output'
            c.g.experiment(entries, NAMES, previous, outer_count=3, inner_count=3)
            audit = c.grouping_audit(entries, NAMES, previous, output)
            self.assertTrue(audit['complete']); self.assertEqual(audit['sample_count'], len(entries))
            for mode in c.MODES:
                target = output / mode
                summary = c.control_mode(entries, NAMES, target, mode, outer_count=3)
                self.assertTrue(summary['complete'])
                scores = c.g.f.read(target / 'development-scores.json')
                self.assertEqual(len(scores), len(entries))
                self.assertEqual({r['sha256'] for r in scores}, set(entries))
                manifest = c.g.f.read(target / 'split-manifest.json')
                for fold in manifest['folds']:
                    roles = [set(fold[k]) for k in ('fit', 'calibration', 'held')]
                    self.assertEqual(set.union(*roles), set(entries))
                    self.assertFalse(roles[0] & roles[1] or roles[0] & roles[2] or roles[1] & roles[2])
                    for comparison in fold['other_panel_overlap'].values():
                        self.assertEqual(comparison['representation'], 0)
                for fold in summary['folds']:
                    self.assertLess(fold['export_parity'], 1e-10)
                totals = {k: sum(f['held_calibrated']['overall'][k] for f in summary['folds'])
                          for k in ('count', 'benign', 'malicious', 'fp', 'fn')}
                self.assertTrue(all(totals[k] == summary['pooled']['calibrated']['overall'][k] for k in totals))


if __name__ == '__main__':
    unittest.main()
