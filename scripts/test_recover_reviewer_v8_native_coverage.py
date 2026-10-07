#!/usr/bin/env python3
"""Double-threshold parity, recovery selection, scorer restoration and resume."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import recover_reviewer_v8_native_coverage as c
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


class RecoveryTests(unittest.TestCase):
    def test_actual_native_training_and_resume_with_recovery_scorer(self):
        from test_reviewer_v8_native_coverage import NativeTests
        with c.checked_scorer():
            NativeTests('test_full_comparison_class_weights_resume_and_tamper').test_full_comparison_class_weights_resume_and_tamper()

    def test_double_threshold_and_training_order(self):
        threshold=1.+float(np.finfo(np.float32).eps)*.75
        tree=dict(children_left=[1,-1,-1],children_right=[2,-1,-1],feature=[0,-2,-2],
                  threshold=[threshold,-2.,-2.],raw_value=[0.,-2.,3.])
        payload=dict(feature_names=['x'],initial_raw_score=-.13,learning_rate=.1,estimators=[tree]*128)
        X=np.array([[1.],[np.nextafter(np.float32(1.),np.float32(2.))],[threshold]],dtype=np.float64)
        expected=c.n.audit.training_order_scores(payload,X)
        np.testing.assert_array_equal(c.array_scores(payload,X),expected)
        self.assertLess(expected[0],.5);self.assertGreater(expected[1],.5)
        self.assertEqual(expected[1],expected[2])
        self.assertEqual(len(c.array_scores(payload,np.empty((0,1)))),0)
        bad=copy.deepcopy(tree);bad['children_left'][0]=0;bad['children_right'][0]=0
        with self.assertRaisesRegex(ValueError,'terminate'):c.array_scores(dict(payload,estimators=[bad]),X)

    def test_exported_model_full_parity_and_restoration(self):
        entries,features,new=fixture();r=c.n.r;keys=sorted(entries)
        X,schema=r.matrices(entries,NAMES,features)['plus_imports'];rows=[entries[k]['record'] for k in keys]
        config=dict(n_estimators=8,learning_rate=.1,max_depth=3,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(r.g.f.w.CONFIG,config,clear=True):
            clf=r.g.fit_model(X,rows);path=Path(tmp)/'model.json'
            r.g.export_checked(clf,schema,.7,X,path);model=c.n.cache.read(path)
            expected=c.n.audit.training_order_scores(model,X)
            np.testing.assert_array_equal(c.array_scores(model,X),expected)
            np.testing.assert_allclose(c.array_scores(model,X),clf.predict_proba(X)[:,1],atol=1e-12,rtol=0)
            original=c.n.audit.training_order_scores
            with c.checked_scorer():np.testing.assert_array_equal(c.n.audit.training_order_scores(model,X),expected)
            self.assertIs(c.n.audit.training_order_scores,original)
            with self.assertRaisesRegex(RuntimeError,'stop'):
                with c.checked_scorer():raise RuntimeError('stop')
            self.assertIs(c.n.audit.training_order_scores,original)

    def test_most_completed_run_resume_identity_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp,patch('builtins.print'):
            root=Path(tmp);previous=root/'reviewer-v8-native-coverage-old';newer=root/'reviewer-v8-native-coverage-new'
            bound=root/'bound.py';bound.write_text('unchanged')
            for folder,count in ((previous,5),(newer,1)):
                identity=dict(source_run=str(root/'baseline'),native_cache=str(root/'native'),input_sha256={str(bound):c.n.cache.digest(bound)})
                c.n.cache.dump(folder/'inputs.json',identity);c.n.cache.dump(folder/'split-manifest.json',{'groups':{}});c.n.cache.dump(folder/'excluded-sha256.json',[])
                for seed in c.n.s.SEEDS[:count]:
                    path=folder/f'seed-{seed}/saved.json';c.n.cache.dump(path,{'seed':seed})
                    c.n.cache.dump(path.parent/'completion.json',dict(complete=True,seed=seed,artifact_sha256={str(path):c.n.cache.digest(path)}))
            self.assertEqual(c.select_run(root),previous)
            args=SimpleNamespace(root=root,resume=None,structural_bundle=root/'frozen')
            seen=[]
            def resumed(settings):
                seen.append(settings);self.assertEqual(settings.resume,previous)
                self.assertEqual(settings.run,root/'baseline');self.assertEqual(settings.native_cache,root/'native')
                c.n.cache.dump(previous/'native-coverage-summary.json',{'complete':True})
            with patch.object(c.n,'run',side_effect=resumed):c.run(args)
            self.assertEqual(len(seen),1)
            self.assertTrue(c.n.cache.read(next(previous.glob('recovery-*.json')))['complete'])
            with patch.object(c.n,'run',side_effect=AssertionError('Completed run must not rerun')):c.run(args)
            bound.write_text('changed')
            with patch.object(c.n,'run') as run,self.assertRaisesRegex(ValueError,'Input changed'):
                c.run(args)
            run.assert_not_called()


if __name__=='__main__':unittest.main()
