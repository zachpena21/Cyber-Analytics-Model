#!/usr/bin/env python3
"""Synthetic checks for leaf collisions, fit-only scaling and calibration isolation."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
import reviewer_v8_rich_blocker_profile as b


def payload():
    return dict(feature_names=['shape','unused'],learning_rate=1.,initial_raw_score=0.,
        development_only=True,estimators=[dict(children_left=[1,-1,3,-1,-1],
        children_right=[2,-1,4,-1,-1],feature=[0,-2,0,-2,-2],
        threshold=[.5,-2,1.5,-2,-2],raw_value=[0,-2,0,2,3])])


class ProfileTests(unittest.TestCase):
    def test_equal_leaves_do_not_imply_equal_features(self):
        model=payload();X=np.array([[1,5],[1,9],[2,5]])
        leaves=b.leaf_matrix(model,X)
        self.assertTrue(np.array_equal(leaves[0],leaves[1]))
        comparison=b.compare(model,X[0],X[1],leaves[0],leaves[1],np.r_[X[0],3],np.r_[X[1],7],
                             ['shape','unused','extra'],np.r_[X[0],3],np.r_[X[1],7])
        self.assertFalse(comparison['same_all_model_features'])
        self.assertEqual(comparison['different_leaf_count'],0)
        self.assertEqual(comparison['differing_feature_count'],2)
        self.assertFalse(next(x for x in comparison['feature_differences'] if x['feature']=='extra')['used_by_model'])
        comparison=b.compare(model,X[0],X[2],leaves[0],leaves[2],X[0],X[2],model['feature_names'],X[0],X[2])
        self.assertEqual(comparison['different_leaf_count'],1)
        self.assertEqual(comparison['largest_tree_contribution_differences'][0]['comparison_minus_benign_raw_contribution'],1.)
        self.assertEqual(comparison['largest_tree_contribution_differences'][0]['benign_path']['steps'][-1]['branch'],'left')

    def test_scaling_is_fixed_from_fit_and_handles_constant_columns(self):
        fit=np.array([[0,3],[1,3],[4,3]],dtype=float);original=fit.copy()
        parameters=b.normalizer(fit)
        result=b.transform(np.array([[1e30,3],[-2,3]]),parameters)
        self.assertTrue(np.isfinite(result).all())
        self.assertLessEqual(abs(result).max(),20)
        self.assertTrue(np.array_equal(fit,original))
        self.assertTrue(np.array_equal(parameters[0],b.normalizer(fit)[0]))

    def test_completed_audit_profiles_only_calibration_without_writes_to_inputs(self):
        entries={};keys=[];X=[];features={};model=payload()
        for i in range(800):
            sha=f'{i:064x}';keys.append(sha);label=int(i>=600)
            row=dict(sha256=sha,label=label,source='fixture',adapter_probability=.8)
            entries[sha]=dict(record=row,libraries='kernel32.dll',original_path=f'/fixture/file-{i}.exe',provenance={'package':'fixture'})
            X.append([1 if (label and i%2==0) or (not label and i%25==0) else 2 if label else 0,i/100])
            features[sha]=dict(byte_size=100,status='synthetic',location=f'/fixture/file-{i}.exe')
        X=np.asarray(X);full=np.c_[X,np.arange(800)%7];schema=model['feature_names'];full_names=schema+['extra']
        folds=[];audits=[]
        for n in range(5):
            fold=dict(fold=n,held=[k for i,k in enumerate(keys) if i%5==n],calibration=[k for i,k in enumerate(keys) if i%5 in ((n+1)%5,(n+2)%5)],fit=[k for i,k in enumerate(keys) if i%5 in ((n+3)%5,(n+4)%5)])
            folds.append(fold);ci=[keys.index(k) for k in fold['calibration']];cr=[entries[k]['record'] for k in fold['calibration']]
            scores=b.a.training_order_scores(model,X[ci]);saved=b.a.s.software_calibration(cr,scores,entries)
            audits.append(dict(fold=n,policies={'software':b.a.audit_policy(cr,scores,entries,'software',saved)}))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);audit=root/'audit';source=root/'run';panel=source/'template';collection=root/'cache';out=root/'out'
            b.cache.dump(audit/'inputs.json',dict(source_run=str(source),input_sha256={},original_input_sha256={}))
            b.cache.dump(audit/'rich-calibration-audit-summary.json',dict(complete=True,held_threshold_search=False,mode='template',variants={'plus_imports':audits}))
            b.cache.dump(source/'inputs.json',dict(rich_cache=str(collection),input_sha256={},converted_acquisition_sha256=[]))
            b.cache.dump(collection/'development-input-cache.json',dict(samples=entries,feature_names=schema))
            b.cache.dump(panel/'split-manifest.json',dict(groups={k:k for k in keys},folds=folds))
            b.cache.dump(panel/'rich-ablation-summary.json',dict(complete=True))
            for n in range(5):b.cache.dump(panel/'plus_imports'/f'fold-{n:02d}-model.json',model)
            original={p:b.cache.digest(p) for p in root.rglob('*.json')}
            args=SimpleNamespace(root=root,audit=audit,output=out,variant=['plus_imports'],neighbors=3)
            with patch.object(b.r,'validate_cache',return_value=(features,{})),patch.object(b.r,'matrices',return_value={'plus_imports':(X,schema),'plus_all':(full,full_names)}),patch.object(b.g,'fit_model',side_effect=AssertionError('Must not fit')):
                b.run(args)
            report=b.cache.read(out/'rich-blocker-profile-summary.json')
            self.assertTrue(report['complete']);self.assertFalse(report['held_samples_profiled'])
            self.assertGreater(report['unique_profiled_samples'],0)
            for f in report['variants']['plus_imports']:
                cal=set(folds[f['fold']]['calibration'])
                for p in f['profiles']:
                    self.assertTrue(set(p['blocker_sha256'])<=cal)
                    for role in ('nearest_missed_calibration_malware','nearest_correct_calibration_benign'):
                        self.assertTrue({x['sha256'] for x in p[role]}<=cal)
            self.assertEqual(original,{p:b.cache.digest(p) for p in original})


if __name__=='__main__':unittest.main()
