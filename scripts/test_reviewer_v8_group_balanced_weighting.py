#!/usr/bin/env python3
"""Fit-only group masses, fixed seed/split comparison, resume and source integrity."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_group_balanced_weighting as w
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


class WeightTests(unittest.TestCase):
    def test_fit_only_routed_group_and_class_mass(self):
        rows=[dict(sha256=str(i),label=label,adapter_probability=score) for i,(label,score) in enumerate([(0,.9)]*3+[(0,.9),(1,.9),(1,.9),(1,.9),(1,.01)])]
        groups=dict(zip(map(str,range(8)),['a','a','a','b','c','c','d','held-only']))
        ids,weights=w.group_weights(rows,groups)
        self.assertEqual(ids.tolist(),list(range(7)))
        np.testing.assert_allclose(weights[:3],[7/12]*3)
        self.assertAlmostEqual(weights[3],7/4)
        self.assertAlmostEqual(weights[4:6].sum(),7/4);self.assertAlmostEqual(weights[6],7/4)
        self.assertAlmostEqual(weights[:4].sum(),3.5);self.assertAlmostEqual(weights[4:].sum(),3.5)
        groups['unseen-calibration']='a';groups['unseen-held']='b'
        np.testing.assert_array_equal(w.group_weights(rows,groups)[1],weights)
        duplicated=copy.deepcopy(rows[:7]);duplicated.append(dict(rows[0],sha256='new-duplicate'));groups['new-duplicate']='a'
        di,dw=w.group_weights(duplicated,groups)
        # After normalizing total mass, duplicates do not increase their group's share.
        self.assertAlmostEqual(dw[[i for i in di if groups[duplicated[i]['sha256']]=='a']].sum()/dw.sum(),.25)
        with self.assertRaisesRegex(ValueError,'Both routed'):w.group_weights(rows[:4],groups)

    def test_fitter_restored_after_failure(self):
        original=w.r.g.fit_model
        with self.assertRaisesRegex(RuntimeError,'stop'):
            with w.weighted_fitter({},8708):
                self.assertIsNot(w.r.g.fit_model,original);raise RuntimeError('stop')
        self.assertIs(w.r.g.fit_model,original)

    def test_full_fixed_comparison_resume_and_tamper(self):
        entries,features,new=fixture();config=dict(n_estimators=2,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(w.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(tmp);original=root/'original';stability=root/'stability';ensemble=root/'ensemble';out=root/'weights'
            groups,plans,_=w.t.make_plan(entries,NAMES,features,new,original)
            summary=w.t.panel(entries,NAMES,features,new,groups,plans,original);summary['complete']=True
            w.cache.dump(original/'targeted-coverage-summary.json',summary)
            prior=root/'prior/rich-feature-summary.json';target=root/'target/targeted-feature-summary.json'
            w.cache.dump(prior,{});w.cache.dump(target,{})
            w.cache.dump(original/'inputs.json',dict(seed=8704,input_sha256={str(p):w.cache.digest(p) for p in (prior,target,Path(w.t.__file__).resolve())}))
            with patch.object(w.t,'load_inputs',return_value=(entries,NAMES,features,new,{})):
                w.s.run(SimpleNamespace(root=root,run=original,output=stability,resume=None,structural_bundle=root/'frozen'))
                w.e.run(SimpleNamespace(root=root,run=stability,output=ensemble,structural_bundle=root/'frozen'))
            before={str(p):w.cache.digest(p) for d in (original,stability,ensemble) for p in d.rglob('*') if p.is_file()}
            args=SimpleNamespace(root=root,run=ensemble,output=out,resume=None,structural_bundle=root/'frozen')
            with patch.object(w.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(w.importlib.metadata,'version',return_value='different'),self.assertRaisesRegex(ValueError,'dependencies/configuration differ'):
                w.run(args)
            self.assertFalse(out.exists())
            constructor=w.r.g.GradientBoostingClassifier;seen=[]
            def construct(**kwargs):
                clf=constructor(**kwargs);fit=clf.fit
                def checked(X,y,sample_weight):
                    seen.append((kwargs['random_state'],np.asarray(y).copy(),np.asarray(sample_weight).copy()))
                    for label in (0,1):self.assertAlmostEqual(sample_weight[y==label].sum(),len(y)/2)
                    return fit(X,y,sample_weight=sample_weight)
                clf.fit=checked;return clf
            with patch.object(w.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(w.r.g,'GradientBoostingClassifier',side_effect=construct):
                w.run(args)
            self.assertEqual([seed for seed,_,_ in seen],[seed for seed in w.s.SEEDS for _ in range(20)])
            report=w.cache.read(out/'group-balanced-weighting-summary.json');manifest=w.cache.read(out/'split-manifest.json')
            self.assertTrue(report['complete']);self.assertEqual(report['completed_seeds'],list(w.s.SEEDS))
            self.assertFalse(report['seed_selection']);self.assertFalse(report['independent_validation'])
            self.assertEqual(len(report['paired_weighting']),4)
            self.assertEqual(manifest,w.cache.read(ensemble/'split-manifest.json'))
            weights=w.cache.read(out/'fit-weight-manifest.json')
            for fold in weights['folds']:
                for arm,data in fold['arms'].items():
                    plan=next(f for f in manifest['folds'] if f['fold']==fold['fold'])
                    self.assertFalse(set(data['sample_weights'])&set(plan['held']+plan['calibration']))
                    self.assertAlmostEqual(data['class_mass']['0'],data['class_mass']['1'])
            args.resume=out
            with patch.object(w.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(w.r.g,'GradientBoostingClassifier',side_effect=AssertionError('Resume must not fit')):
                w.run(args)
            self.assertEqual(report,w.cache.read(out/'group-balanced-weighting-summary.json'))
            self.assertEqual(before,{str(p):w.cache.digest(p) for d in (original,stability,ensemble) for p in d.rglob('*') if p.is_file()})
            damaged=out/'seed-8708/plus_imports/prior_only/development-scores.json';damaged.write_text(damaged.read_text()+' ')
            with patch.object(w.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),self.assertRaisesRegex(ValueError,'Input changed'):
                w.run(args)


if __name__=='__main__':unittest.main()
