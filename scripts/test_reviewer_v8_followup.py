"""Regression tests for independent threshold and build-feature experiments."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np

import reviewer_v8_followup as f
import reviewer_v8_import_experiment as e
import reviewer_v8_workflow as w
import test_reviewer_v8_imports as fixtures
from defender.models.boundary_reviewer import BoundaryReviewer, BUILD_FEATURES, _build_values


class FollowupTests(unittest.TestCase):
    def test_midpoint_preserves_tied_predictions_and_weights(self):
        scores=np.array([0.,.2,.2,.8,.9])
        band=f.midpoint_threshold(scores,.8)
        self.assertAlmostEqual(band['threshold'],.5)
        np.testing.assert_array_equal(scores>=.8,scores>=band['threshold'])
        weighted=f.midpoint_threshold(scores,.8,[1,0,0,1,1])
        self.assertAlmostEqual(weighted['threshold'],.4)
        # Adjacent floats have no representable interior: keep the upper point.
        lo=.5; hi=np.nextafter(lo,np.inf)
        self.assertEqual(f.midpoint_threshold([lo,hi],hi)['threshold'],hi)
        # Zero is excluded safely even when all scores are tied at zero/one.
        self.assertEqual(f.midpoint_threshold([0.,1.],1.)['threshold'],.5)

    def test_build_runtime_order_and_semantics(self):
        attrs=dict(major_linker_version=2,symbols=3,has_debug=0,has_tls=1)
        self.assertEqual(_build_values(attrs),(1.,1.,1.,1.,1.))
        self.assertEqual(_build_values(dict(attrs,has_debug=1)),(1.,1.,0.,1.,0.))
        self.assertEqual(_build_values(dict(attrs,major_linker_version=14)),(0.,1.,1.,0.,0.))
        frozen=fixtures.ReviewerImportTests().specification()
        base=BoundaryReviewer.__new__(BoundaryReviewer);base._load(frozen)
        components={k:.5 for k in w.SCORE_FEATURES}
        row=np.array([base._vectorize(attrs,b'MZ',components)+list(e._import_values(attrs))+list(_build_values(attrs))])
        # Force a split on an appended build feature to exercise export validation.
        from sklearn.ensemble import GradientBoostingClassifier
        X=np.repeat(row,20,axis=0);X[10:,-1]=0
        clf=GradientBoostingClassifier(n_estimators=2,max_depth=1,random_state=1).fit(X,[1]*10+[0]*10)
        payload=f.export_build(clf,frozen,.5)
        runtime=BoundaryReviewer.__new__(BoundaryReviewer);runtime._load(payload)
        self.assertEqual(runtime._vectorize(attrs,b'MZ',components),row[0].tolist())
        self.assertAlmostEqual(runtime.score(attrs,b'MZ',**components),clf.predict_proba(row)[0,1])
        bad=copy.deepcopy(payload);bad['build_features'].reverse()
        with self.assertRaisesRegex(ValueError,'build feature order'):
            runtime._load(bad)
        bad=copy.deepcopy(payload);bad['format_version']=8
        with self.assertRaisesRegex(ValueError,'unexpectedly contains build'):
            runtime._load(bad)

    def test_complete_followup_reproduces_controls_and_splits(self):
        original=e.experiment;calls=[]
        def experiment(rows,cached,frozen,baseline,output):
            meta=original(rows,cached,frozen,baseline,output)
            dest=Path(output).parent/'followup'
            summary=f.evaluate(rows,cached,frozen,baseline,output,dest,repeats=10)
            self.assertTrue(summary['completed']);self.assertEqual(len(summary['leave_one_source_out']),4)
            for model in summary['calibration'].values():
                a,b=model['policies']['upper_endpoint'],model['policies']['interval_midpoint']
                self.assertEqual(a['calibration'],b['calibration'])
                self.assertLessEqual(b['threshold'],a['threshold'])
                self.assertTrue(all(v<=1e-10 for v in model.get('export_parity',{}).values()))
            for fold in summary['leave_one_source_out']:
                self.assertEqual(set(fold['models']),{'baseline','imports','build_categories'})
                self.assertEqual(fold['models']['build_categories']['bootstrap']['repeats'],10)
            traces=json.loads((dest/'tree-path-audit.json').read_text())['errors']
            expected=sum(x['models']['import_candidate']['heldout']['fp']+x['models']['import_candidate']['heldout']['fn']
                         for x in meta['leave_one_source_out'])
            self.assertEqual(len(traces),expected)
            for entry in traces:
                for sample in entry['samples']:
                    for trace in sample['models'].values():
                        self.assertTrue(0<=trace['probability']<=1)
            # Tests feature augmentation leaves the reference cache unchanged.
            self.assertEqual(len(cached[rows[0]['sha256']]['structural_vector']),len(frozen['feature_names'])-6)
            a=json.loads((baseline/'split_manifest.json').read_text());b=json.loads((dest/'split_manifest.json').read_text())
            self.assertEqual(a['training'],b['training']);self.assertEqual(a['calibration'],b['calibration'])
            calls.append(True);return meta
        with patch.object(e,'experiment',experiment):
            fixtures.ReviewerImportTests('test_controlled_experiment_and_holdout_isolation').test_controlled_experiment_and_holdout_isolation()
        self.assertEqual(calls,[True])


if __name__=='__main__':
    unittest.main()
