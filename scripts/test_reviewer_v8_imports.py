"""Run with the project's venv: python scripts/test_reviewer_v8_imports.py."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

import reviewer_v8_import_experiment as e
import reviewer_v8_workflow as w
from defender.models.boundary_reviewer import BoundaryReviewer, IMPORT_FEATURES, _import_values


class ReviewerImportTests(unittest.TestCase):
    def specification(self):
        # Use the actual frozen feature schema, with self-contained test trees.
        reviewer = BoundaryReviewer.__new__(BoundaryReviewer)
        reviewer.categories = dict(machine=["MACHINE_TYPES.AMD64", "MACHINE_TYPES.I386"],
                                   magic=["PE32", "PE32_PLUS"])
        reviewer.derived_features = w.DERIVED_FEATURES
        return dict(format_version=6, model_type="gradient_boosting", route_min=.15,
                    reviewer_threshold=.6312998096487621, learning_rate=.1,
                    initial_raw_score=0., categories=reviewer.categories,
                    derived_features=list(w.DERIVED_FEATURES),
                    feature_names=list(reviewer._expected_feature_names()),
                    estimators=[dict(children_left=[-1], children_right=[-1], feature=[-2],
                                     threshold=[-2.], raw_value=[0.])])

    def test_identity_normalization_and_no_benign_bypass(self):
        attributes = dict(libraries='NTOSKRNL.EXE C:\\Windows\\HAL.dll ndis.sys NDIS.SYS '
                                    '/drivers/WdfLdr.Sys ks.sys similar_ntoskrnl.exe')
        self.assertEqual(_import_values(attributes), (1., 1., 1., 1., 1., 5.))
        self.assertEqual(_import_values({}), (0.,) * 6)
        self.assertEqual(_import_values(dict(libraries='ntoskrnl.exe.evil')), (0.,) * 6)
        frozen = self.specification()
        base = BoundaryReviewer.__new__(BoundaryReviewer); base._load(frozen)
        payload = dict(frozen, format_version=8, input_dtype="float32", import_features=list(IMPORT_FEATURES),
                       feature_names=frozen['feature_names'] + list(IMPORT_FEATURES))
        # Test an actual runtime split on the appended ntoskrnl presence feature.
        payload['estimators'] = [dict(children_left=[1, -1, -1], children_right=[2, -1, -1],
            feature=[len(frozen['feature_names']), -2, -2], threshold=[.5, -2., -2.],
            raw_value=[0., -20., 20.])]
        runtime = BoundaryReviewer.__new__(BoundaryReviewer); runtime._load(payload)
        components = {k: .5 for k in w.SCORE_FEATURES}
        self.assertEqual(runtime._vectorize(attributes, b'MZ', components)[:-6],
                         base._vectorize(attributes, b'MZ', components))
        self.assertGreater(runtime.score(attributes, b'MZ', **components), .8)
        self.assertLess(runtime.score({}, b'MZ', **components), .2)
        damaged = copy.deepcopy(payload); damaged['import_features'].reverse()
        with self.assertRaisesRegex(ValueError, 'import feature order'):
            runtime._load(damaged)
        damaged = copy.deepcopy(payload); damaged['feature_names'].reverse()
        with self.assertRaisesRegex(ValueError, 'feature order'):
            runtime._load(damaged)
        damaged = copy.deepcopy(payload); damaged['format_version'] = 7
        with self.assertRaisesRegex(ValueError, 'unexpectedly contains import'):
            runtime._load(damaged)

    def test_controlled_experiment_and_holdout_isolation(self):
        frozen = self.specification()
        runtime = BoundaryReviewer.__new__(BoundaryReviewer); runtime._load(frozen)
        rng = np.random.RandomState(22)
        rows, cached = [], {}
        for source in (*w.OLD_SOURCES, 'batch-v7', 'batch-v11'):
            for i in range(32):
                sha = hashlib.sha256(f'{source}:{i}'.encode()).hexdigest()
                row = dict(sha256=sha, source=source, label=i % 2,
                           benign_probability=float(rng.uniform(.1, .9)),
                           adapter_probability=float(rng.uniform(.2, .99)),
                           base_trigger_raw=0., base_trigger_adjusted=0., signature_checked=0., signature_verified=0.)
                attrs = dict(libraries='NTOSKRNL.EXE HAL.dll' if i % 4 == 0 else 'KERNEL32.dll',
                             machine='MACHINE_TYPES.AMD64', magic='PE32_PLUS', virtual_size=i * 1000,
                             sizeof_code=i * 10, imports=2, numberof_sections=4)
                vector = runtime._vectorize(attrs, b'MZfixture', row)
                cached[sha] = dict(structural_vector=vector[6:], attributes=attrs)
                rows.append(row)
        augmented = e.augment_cache(cached)
        self.assertEqual(len(cached[rows[0]['sha256']]['structural_vector']), len(frozen['feature_names']) - 6)
        self.assertEqual(len(augmented[rows[0]['sha256']]['structural_vector']), len(frozen['feature_names']))
        old_fit, _ = w.split([r for r in rows if r['source'] in w.OLD_SOURCES])
        frozen = w.export(w.fit(old_fit, cached, .15), frozen, frozen['reviewer_threshold'])
        frozen['format_version'] = 6; frozen.pop('input_dtype')
        with tempfile.TemporaryDirectory() as temp:
            base, out = Path(temp) / 'base', Path(temp) / 'imports'
            w.train(rows, cached, frozen, base, {})
            calls, calibrations = [], []
            original_fit, original_calibrate = w.fit, w.calibrate
            def fitting(group, *args, **kwargs):
                calls.append({r['source'] for r in group})
                return original_fit(group, *args, **kwargs)
            def calibrating(group, *args, **kwargs):
                calibrations.append({r['source'] for r in group})
                return original_calibrate(group, *args, **kwargs)
            with patch.object(w, 'fit', fitting), patch.object(w, 'calibrate', calibrating):
                meta = e.experiment(rows, cached, frozen, base, out)
            self.assertLessEqual(meta['runtime_parity_max_abs_error'], 1e-10)
            for i, source in enumerate(e.SOURCES):
                for sources in calls[2 + i * 2:4 + i * 2] + calibrations[2 + i * 2:4 + i * 2]:
                    self.assertNotIn(source, sources)
            a = json.loads((base / 'split_manifest.json').read_text())
            b = json.loads((out / 'split_manifest.json').read_text())
            self.assertEqual(a['training'], b['training'])
            self.assertEqual(a['calibration'], b['calibration'])
            payload = json.loads((out / 'model.json').read_text())
            modern = BoundaryReviewer(out / 'model.json')
            for row in rows[:32]:
                attrs = cached[row['sha256']]['attributes']
                actual = modern._vectorize(attrs, b'MZfixture', row)
                expected = w.vector(row, augmented[row['sha256']])
                self.assertEqual(actual, expected)
                manual = w.model_probabilities(payload, np.array([expected]))[0]
                self.assertAlmostEqual(modern.score(attrs, b'MZfixture', **{k: row[k] for k in w.SCORE_FEATURES}), manual)
            for fold in meta['leave_one_source_out']:
                for model in fold['models'].values():
                    self.assertIn('heldout_at_original_threshold', model)
                    self.assertEqual(sum(m['count'] for m in model['by_category'].values()), model['heldout']['count'])
            b = json.loads((base / 'split_manifest.json').read_text())
            b['training'].reverse(); w.dump(base / 'split_manifest.json', b)
            train, cal = w.preserved_split(rows)
            with self.assertRaisesRegex(ValueError, 'split differs'):
                e.verify_baseline(rows, cached, frozen, base, train, cal)


if __name__ == '__main__':
    unittest.main()
