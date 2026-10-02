"""Group isolation, true OOF generation, gate constraints, export and complete workflow."""
from argparse import Namespace
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_grouped_experiment as g
from test_reviewer_v8_docker_train import specification


NAMES = specification()['feature_names']


def entry(sha, label=0, group=0, source='historical'):
    a = {k: 0. for k in NAMES}
    a.update(benign_probability=.7 if label == 0 else .2, adapter_probability=.9,
             major_linker_version=2., minor_linker_version=float(40 + group),
             symbols=float(group), has_debug=0., has_tls=1., imports=8., exports=0.,
             numberof_sections=10., byte_size=50000., virtual_size=80000.,
             byte_entropy=4. if label == 0 else 7., string_urls=20. if label == 0 else 0.)
    row = dict(sha256=sha, label=label, source=source, adapter_threshold=.7,
               **{k: a[k] for k in g.f.w.SCORE_FEATURES})
    return dict(record=row, feature_vector=[a[k] for k in NAMES], libraries='KERNEL32.dll msvcrt.dll')


def pool(groups=15, size=12):
    result = {}
    for group in range(groups):
        for label in (0, 1):
            for i in range(size):
                sha = hashlib.sha256(f'{group}:{label}:{i}'.encode()).hexdigest()
                result[sha] = entry(sha, label, group)
    return result


class GroupedExperimentTests(unittest.TestCase):
    def test_label_free_templates_and_software_links_are_transitive(self):
        entries = {k: entry(k, label=i % 2, group=i) for i, k in enumerate(('a', 'b', 'c', 'd'))}
        entries['a']['record']['source'] = 'portablegit-v1'
        entries['b']['record']['source'] = 'portablegit-v2'
        entries['c']['feature_vector'] = list(entries['b']['feature_vector'])
        groups = g.make_groups(entries, NAMES)
        self.assertEqual(groups['a'], groups['b'])
        self.assertEqual(groups['b'], groups['c'])
        self.assertNotEqual(groups['c'], groups['d'])
        entries['c']['record']['label'] = 1 - entries['c']['record']['label']
        self.assertEqual(groups, g.make_groups(entries, NAMES))
        rows = [r['record'] for r in pool().values()]
        gs = g.make_groups(pool(), NAMES)
        folds = g.group_folds(rows, gs, 5)
        reverse = g.group_folds(list(reversed(rows)), gs, 5)
        self.assertEqual(folds.tolist(), list(reversed(reverse.tolist())))
        for group in set(gs.values()):
            self.assertEqual(len({int(folds[i]) for i, r in enumerate(rows) if gs[r['sha256']] == group}), 1)

    def test_oof_predictions_never_use_their_fitting_group(self):
        entries = pool(groups=9, size=1); rows = [e['record'] for e in entries.values()]
        groups = g.make_groups(entries, NAMES)
        X = np.arange(len(rows), dtype=float)[:, None]
        lookup = {i: groups[r['sha256']] for i, r in enumerate(rows)}

        def fitter(fit_X, fit_rows):
            seen = {lookup[int(i)] for i in fit_X[:, 0]}

            class Spy:
                def predict_proba(self, held_X):
                    self_test = {lookup[int(i)] for i in held_X[:, 0]}
                    if seen & self_test:
                        raise AssertionError('Held group used for fitting')
                    return np.c_[np.full(len(held_X), .4), np.full(len(held_X), .6)]
            return Spy()

        with patch('builtins.print'):
            scores, manifests = g.oof_scores(X, rows, groups, count=3, fitter=fitter)
        self.assertTrue(np.all(scores == .6))
        held = [s for fold in manifests for s in fold['held']]
        self.assertEqual(set(held), set(entries)); self.assertEqual(len(held), len(entries))

    def test_calibration_respects_fixed_gate_and_reports_infeasibility(self):
        rows = [dict(label=0, source='benign', adapter_probability=.1),
                dict(label=0, source='benign', adapter_probability=.9),
                dict(label=1, source='malware', adapter_probability=.9)]
        scores = np.array([.99, .3, .8])
        policy = g.calibration(rows, scores, lambda t: g.gated(rows, scores, t))
        self.assertTrue(policy['feasible']); self.assertEqual(policy['overall']['fp'], 0)
        self.assertEqual(policy['overall']['fn'], 0)
        pred = g.skim_predictions(rows, [.99, .9, .2], .5, scores, .6, np.array([False, False, True]))
        self.assertEqual(pred.tolist(), [0, 0, 0])
        # An outside-region false positive cannot be repaired by its skimmer threshold.
        policy = g.calibration(rows, scores, lambda t: np.array([1, 0, 1]))
        self.assertFalse(policy['feasible']); self.assertEqual(policy['overall']['fp'], 1)

    def test_features_are_import_and_structure_only(self):
        sample = entry('a'); sample['libraries'] = 'C:\\Windows\\MSCOREE.DLL api-ms-win-crt-heap-l1-1-0.dll LIBSTDC++-6.DLL'
        values = g.extra_values(sample, NAMES)
        self.assertEqual(values[5], 1); self.assertEqual(values[8], 1); self.assertEqual(values[9], 1)
        changed = copy.deepcopy(sample); changed['record'].update(label=1, source='another')
        changed['provenance'] = {'original_member': 'something-else.exe'}
        self.assertEqual(values, g.extra_values(changed, NAMES))

    def test_cache_label_and_score_provenance_guards(self):
        from test_reviewer_v8_coverage_compare import runtime
        spec7 = specification(); spec8 = specification(8)
        candidates = {n: (runtime(p), p) for n, p in [('v7', spec7), ('v8_import_midpoint', spec8)]}
        sha = 'a' * 64; sample = entry(sha)
        for n, (model, _) in candidates.items():
            flags = list(g.f.t.e._import_values({'libraries': sample['libraries']}))
            score = g.f.c.reviewer_score(model, sample['feature_vector'] + (flags if n != 'v7' else []))
            routed, pred = g.f.c.verdict(score, model, sample['record'], .7)
            sample['record'].update({n + '_score': score, n + '_routed': routed, n + '_prediction': pred})
        g.checked_entry(sha, sample, NAMES, candidates)
        sample['record']['v8_import_midpoint_score'] += .01
        # Earlier import-model V8 scores are not expanded-model V8 scores.
        g.checked_entry(sha, sample, NAMES, candidates, historical=True)
        with self.assertRaisesRegex(ValueError, 'model=v8_import_midpoint'):
            g.checked_entry(sha, sample, NAMES, candidates)
        sample['record']['v7_score'] += .01
        with self.assertRaisesRegex(ValueError, 'reproduce frozen'):
            g.checked_entry(sha, sample, NAMES, candidates, historical=True)

    def test_completed_evaluation_binds_fresh_cache_labels(self):
        from test_reviewer_v8_coverage_compare import runtime
        payloads = {'v7': specification(), 'v8_import_midpoint': specification(8)}
        candidates = {n: (runtime(p), p) for n, p in payloads.items()}

        def scored(sha, label):
            sample = entry(sha, label)
            for name, (model, _) in candidates.items():
                flags = list(g.f.t.e._import_values({'libraries': sample['libraries']}))
                score = g.f.c.reviewer_score(model, sample['feature_vector'] + (flags if name != 'v7' else []))
                routed, pred = g.f.c.verdict(score, model, sample['record'], .7)
                sample['record'].update({name + '_score': score, name + '_prediction': pred, name + '_routed': routed})
            for suffix in ('_score', '_prediction', '_routed'):
                sample['record']['v8_import_upper' + suffix] = sample['record']['v8_import_midpoint' + suffix]
            return sample

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bundle_dir = root / 'bundle'; audit = root / 'audit'; comparison = root / 'evaluation'
            old_sha, fresh_sha = 'a' * 64, 'b' * 64
            old_sample, fresh_sample = scored(old_sha, 0), scored(fresh_sha, 1)
            # Full loader must distinguish historical and fresh cache models.
            old_sample['record']['v8_import_midpoint_score'] += .01
            g.f.w.dump(bundle_dir / 'freeze-manifest.json', {'complete': True})
            cache_path = root / 'old-cache.json'
            g.f.w.dump(cache_path, dict(complete=True, samples={old_sha: old_sample}))
            bundle = dict(inputs={'docker_cache_sha256': g.digest(cache_path)}, exclusions={'development_samples': 1})
            g.f.w.dump(comparison / 'evaluation-manifest.json', dict(complete=True, role='evaluation',
                samples=[dict(sha256=fresh_sha, label=1, source_id='historical')]))
            g.f.w.dump(comparison / 'comparison-scores.json', [fresh_sample['record']])
            g.f.w.dump(audit / 'inputs.json', dict(freeze_manifest_sha256=g.digest(bundle_dir / 'freeze-manifest.json'),
                evaluation_manifest_sha256=g.digest(comparison / 'evaluation-manifest.json'),
                evaluation_scores_sha256=g.digest(comparison / 'comparison-scores.json')))
            g.f.w.dump(audit / 'audit-summary.json', dict(complete=True, sample_count=1))
            g.f.w.dump(audit / 'docker-feature-cache.json', dict(complete=True, samples={fresh_sha: fresh_sample}))
            args = Namespace(bundle=bundle_dir, training_cache=cache_path, fresh_audit=[audit], fresh_comparison=[comparison])
            with patch.object(g.f, 'load_bundle', return_value=(bundle, candidates, {old_sha})):
                entries, names, hashes, converted = g.load_inputs(args)
                self.assertEqual(set(entries), {old_sha, fresh_sha}); self.assertEqual(converted, [fresh_sha])
                self.assertEqual(names, NAMES); self.assertIn(str(cache_path), hashes)
                fresh_sample['record']['label'] = 0
                g.f.w.dump(audit / 'docker-feature-cache.json', dict(complete=True, samples={fresh_sha: fresh_sample}))
                with self.assertRaisesRegex(ValueError, 'label/source'):
                    g.load_inputs(args)

    def test_end_to_end_grouped_training_export_and_oof_manifest(self):
        entries = pool(); config = dict(n_estimators=8, learning_rate=.1, max_depth=2,
                                        min_samples_leaf=2, max_features=None, subsample=1.)
        with tempfile.TemporaryDirectory() as directory, patch.dict(g.f.w.CONFIG, config, clear=True), \
                patch.dict(g.SKIMMER_CONFIG, config, clear=True), patch('builtins.print'):
            output = Path(directory)
            summary = g.experiment(entries, NAMES, output, outer_count=3, inner_count=3)
            self.assertTrue(summary['complete'])
            manifest = g.f.read(output / 'group-manifest.json')
            scores = g.f.read(output / 'development-scores.json')
            self.assertEqual(len(scores), len(entries))
            self.assertEqual({r['sha256'] for r in scores}, set(entries))
            groups = manifest['groups']
            for fold in manifest['folds']:
                fit, cal, held = (set(fold[k]) for k in ('fit', 'calibration', 'held'))
                self.assertFalse(fit & cal or fit & held or cal & held)
                self.assertFalse({groups[k] for k in fit} & {groups[k] for k in held | cal})
                for inner in fold['skimmer_oof']:
                    self.assertTrue(set(inner['fit']) | set(inner['held']) <= fit)
                    self.assertFalse({groups[k] for k in inner['fit']} & {groups[k] for k in inner['held']})
            for fold in summary['folds']:
                for model in fold['models'].values():
                    self.assertLess(model['export_parity'], 1e-10)
            payload = g.f.read(output / 'fold-00/enhanced-model.json')
            self.assertFalse(payload['runtime_supported'])
            self.assertTrue(payload['development_only'])


if __name__ == '__main__':
    unittest.main()
