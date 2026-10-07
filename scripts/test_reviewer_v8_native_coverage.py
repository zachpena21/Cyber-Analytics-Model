#!/usr/bin/env python3
"""Preserved roles, cross-fold link rejection, class weights, replay and resume."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_native_coverage as n
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


def additions(entries,features):
    result=copy.deepcopy(entries);extra=copy.deepcopy(features);new=set()
    for i,k in enumerate([k for k in sorted(entries) if entries[k]['record']['label']==0][:6]):
        sha=f'{2000000+i:064x}';result[sha]=copy.deepcopy(entries[k]);result[sha]['record']['sha256']=sha
        extra[sha]=copy.deepcopy(features[k]);new.add(sha)
    return result,extra,new


class NativeTests(unittest.TestCase):
    def test_matching_cache_and_control_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);prior=root/'prior';right=root/'reviewer-v8-targeted-feature-cache-right'
            n.cache.dump(right/'targeted-feature-summary.json',dict(complete=True,prior_cache=str(prior),inventory='reviewer-v8-official-native-1'))
            for name,changes in (('old',dict(inventory='reviewer-v8-targeted-benign-1')),('incomplete',dict(complete=False)),('other',dict(prior_cache=str(root/'other')))):
                doc=dict(complete=True,prior_cache=str(prior),inventory='reviewer-v8-official-native-2');doc.update(changes)
                n.cache.dump(root/('reviewer-v8-targeted-feature-cache-'+name)/'targeted-feature-summary.json',doc)
            self.assertEqual(n.latest_native(root,prior),right)
            sample=dict(sha256='a',reviewer_score=.5,fold=0,label=1,source='s',software_prediction=1,fixed_prediction=0)
            for variant in n.t.VARIANTS:n.cache.dump(root/variant/'prior_only/development-scores.json',[sample])
            refs={variant:{'a':sample} for variant in n.t.VARIANTS}
            self.assertEqual(n.verify_previous(root,refs),0.)
            n.cache.dump(root/'plus_imports/prior_only/development-scores.json',[dict(sample,software_prediction=0)])
            with self.assertRaisesRegex(ValueError,'does not reproduce'):n.verify_previous(root,refs)

    def test_preserved_roles_and_cross_fold_bridge(self):
        entries,features,old_target=fixture();combined,extra,new=additions(entries,features)
        with tempfile.TemporaryDirectory() as tmp:
            n.t.make_plan(entries,NAMES,features,old_target,Path(tmp))
            old=n.cache.read(Path(tmp)/'split-manifest.json')
            manifest,audit=n.extend_manifest(combined,NAMES,extra,new,old)
            self.assertTrue(audit['old_roles_preserved'])
            for before,after in zip(old['folds'],manifest['folds']):
                self.assertEqual(after['prior_fit'],sorted(before['expanded_fit']))
                self.assertEqual(set(after['expanded_fit'])-new,set(before['expanded_fit']))
                self.assertEqual(after['calibration'],before['calibration'])
                self.assertEqual(set(after['held'])-new,set(before['held']))
                self.assertEqual(after['excluded_previous_calibration'],before['excluded_new_calibration'])
                self.assertFalse(set(after['calibration'])&new)
            altered=copy.deepcopy(combined)
            for entry in altered.values():entry['record']['adapter_probability']=.987
            second,_=n.extend_manifest(altered,NAMES,extra,new,old)
            self.assertEqual(manifest,second)  # Both are routed; assignment ignores scores.
            linked=dict(manifest['groups']);a=old['folds'][0]['held'][0];b=old['folds'][1]['held'][0]
            linked[b]=linked[a]
            with patch.object(n.r,'matched_groups',return_value=linked):
                blocked,report=n.extend_manifest(combined,NAMES,extra,new,old)
            self.assertIsNone(blocked);self.assertFalse(report['old_roles_preserved']);self.assertTrue(report['conflicts'])
            novel=dict(manifest['groups'])
            for k in new:novel[k]=min(new)
            with patch.object(n.r,'matched_groups',return_value=novel):
                first,_=n.extend_manifest(combined,NAMES,extra,new,old)
                second,_=n.extend_manifest(dict(reversed(list(combined.items()))),NAMES,extra,new,old)
            self.assertEqual(first,second)
            self.assertEqual(sum(len(f['targeted_held']) for f in first['folds']),len(new))

    def test_full_comparison_class_weights_resume_and_tamper(self):
        entries,features,old_target=fixture();combined,extra,native=additions(entries,features)
        config=dict(n_estimators=2,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(n.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(tmp);source=root/'source';out=root/'output';prior=root/'prior/rich-feature-summary.json'
            n.cache.dump(prior,{})
            n.t.make_plan(entries,NAMES,features,old_target,root/'plan');old=n.cache.read(root/'plan/split-manifest.json')
            plans=n.s.plans_from_manifest(old,entries);models={};references={}
            for seed in n.s.SEEDS:
                folder=root/f'old-{seed}'
                with n.s.training_seed(seed):summary=n.t.panel(entries,NAMES,features,old_target,old['groups'],plans,folder)
                records,allmodels,_,_=n.audit.replay(entries,NAMES,features,old_target,folder,summary,old)
                models[seed]={(v+'/prior_only',f):allmodels[(v+'/targeted_fit_added',f)] for v in n.t.VARIANTS for f in range(5)}
                references[seed]={v:records[v+'/targeted_fit_added'] for v in n.t.VARIANTS}
            allmodels={seed:{(v+'/'+a,f):models[seed][(v+'/prior_only',f)] for v in n.t.VARIANTS for a in n.t.ARMS for f in range(5)} for seed in n.s.SEEDS}
            baseline=n.e.ensemble(entries,NAMES,features,old_target,old,allmodels,{},source)
            before={str(p):n.cache.digest(p) for p in root.rglob('*') if p.is_file()}
            native_input=({k:v for k,v in combined.items() if k not in old_target},NAMES,
                          {k:v for k,v in extra.items() if k not in old_target},native,{})
            loaded=(entries,NAMES,features,old_target,{str(prior):n.cache.digest(prior)},old,{},baseline,{},source)
            args=SimpleNamespace(root=root,run=source,native_cache=root/'native',structural_bundle=root/'frozen',output=out,resume=None,audit_only=False)
            constructor=n.r.g.GradientBoostingClassifier;seen=[]
            def construct(**kwargs):
                clf=constructor(**kwargs);fit=clf.fit
                def checked(X,y,sample_weight):
                    from sklearn.utils.class_weight import compute_sample_weight
                    np.testing.assert_allclose(sample_weight,compute_sample_weight('balanced',y))
                    seen.append(kwargs['random_state']);return fit(X,y,sample_weight=sample_weight)
                clf.fit=checked;return clf
            with patch.object(n.baseline_loader,'load_baseline',return_value=loaded),patch.object(n,'load_previous_models',return_value=(models,references)),patch.object(n.t,'load_inputs',return_value=native_input):
                with patch.object(n.r.g,'GradientBoostingClassifier',side_effect=construct):n.run(args)
                self.assertEqual(seen,[seed for seed in n.s.SEEDS for _ in range(10)])
                report=n.cache.read(out/'native-coverage-summary.json')
                self.assertTrue(report['complete']);self.assertEqual(report['new_fit_count'],50)
                self.assertEqual(report['native_count'],6);self.assertEqual(report['earlier_targeted_count'],12)
                self.assertLessEqual(report['ensemble']['previous_control_max_abs'],1e-9)
                args.resume=out
                with patch.object(n.r.g,'GradientBoostingClassifier',side_effect=AssertionError('Resume must not fit')):n.run(args)
                self.assertEqual(report,n.cache.read(out/'native-coverage-summary.json'))
                self.assertEqual(before,{p:n.cache.digest(p) for p in before})
                damaged=out/'seed-8708/plus_imports/targeted_fit_added/fold-00-model.json'
                damaged.write_text(damaged.read_text()+' ')
                with self.assertRaisesRegex(ValueError,'Input changed'):n.run(args)


if __name__=='__main__':unittest.main()
