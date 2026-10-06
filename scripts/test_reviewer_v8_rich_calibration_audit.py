#!/usr/bin/env python3
"""Synthetic regression tests for calibration replay, caps and audit isolation."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
import reviewer_v8_rich_calibration_audit as a


def fixture():
    rows=[];entries={}
    for i in range(160):
        row=dict(sha256=f'{i:064x}',label=int(i>=120),source='fixture',adapter_probability=.8)
        rows.append(row);entries[row['sha256']]=dict(record=row)
    return rows,entries


class AuditTests(unittest.TestCase):
    def test_grid_matches_both_original_policies_with_gating_and_ties(self):
        rows,entries=fixture()
        scores=np.round(np.random.default_rng(8).uniform(.05,.999,len(rows)),2)
        for i in range(0,len(rows),11):
            rows[i]['adapter_probability']=.1
        with patch.object(a.g,'software_group',return_value='software:fixture'):
            for policy in ('ordinary','software'):
                saved=(a.g.calibration(rows,scores,lambda t:a.g.gated(rows,scores,t)) if policy=='ordinary'
                       else a.s.software_calibration(rows,scores,entries))
                result=a.audit_policy(rows,scores,entries,policy,saved)
                self.assertEqual(result['selected']['threshold'],saved['threshold'])
                self.assertFalse(result['held_alternative_thresholds_evaluated'])

    def test_cap_driver_and_plateau_are_distinguished(self):
        rows,entries=fixture()
        scores=np.r_[np.full(120,.8),np.full(20,.7),np.full(20,.9)]
        saved=a.g.calibration(rows,scores,lambda t:a.g.gated(rows,scores,t))
        result=a.audit_policy(rows,scores,entries,'ordinary',saved)
        self.assertEqual(result['selected']['threshold'],.9)
        self.assertLess(result['lowest_feasible_same_recall']['threshold'],.9)
        self.assertGreater(result['pure_threshold_tiebreak_candidate_count'],1)
        lower=result['next_lower_threshold_increasing_recall']
        self.assertEqual(lower['tp'],40)
        self.assertFalse(lower['feasible'])
        self.assertEqual(result['limiting_sample_details'][0]['new_error_count'],120)
        self.assertTrue(result['limiting_sample_details'][0]['truncated'])
        self.assertEqual(len(result['limiting_sample_details'][0]['new_errors']),100)
        with self.assertRaisesRegex(ValueError,'does not reproduce'):
            a.audit_policy(rows,scores,entries,'ordinary',dict(saved,threshold=.5))

    def test_stage_order_reproduces_sklearn_and_saved_models_end_to_end(self):
        rows,entries=fixture();keys=[x['sha256'] for x in rows]
        X=np.random.default_rng(42).normal(size=(len(rows),3));X[:,0]+=np.array([x['label'] for x in rows])*2
        schema=['a','b','c'];folds=[];groups={k:k for k in keys}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'run';panel=source/'template';collection=root/'cache';out=root/'out'
            a.cache.dump(collection/'development-input-cache.json',dict(samples=entries,feature_names=schema))
            summary=dict(complete=True,mode='template',sample_count=len(rows),variants={})
            records=[];results=[]
            for n in range(5):
                held=[i for i in range(len(rows)) if i%5==n]
                cal=[i for i in range(len(rows)) if i%5 in ((n+1)%5,(n+2)%5)]
                fit=[i for i in range(len(rows)) if i not in held+cal]
                folds.append(dict(fold=n,fit=[keys[i] for i in fit],calibration=[keys[i] for i in cal],held=[keys[i] for i in held]))
                clf=GradientBoostingClassifier(n_estimators=6,max_depth=2,random_state=3).fit(X[fit],np.array([rows[i]['label'] for i in fit]))
                cp=clf.predict_proba(X[cal])[:,1];hp=clf.predict_proba(X[held])[:,1];cr=[rows[i] for i in cal]
                policies=dict(ordinary=a.g.calibration(cr,cp,lambda t:a.g.gated(cr,cp,t)),
                              software=a.s.software_calibration(cr,cp,entries))
                results.append(dict(fold=n,calibration=policies))
                payload=a.g.tree_payload(clf,schema,policies['software']['threshold'])
                self.assertTrue(np.array_equal(a.training_order_scores(payload,X),clf.predict_proba(X)[:,1]))
                a.cache.dump(panel/'structural_control'/f'fold-{n:02d}-model.json',payload)
                for j,i in enumerate(held):
                    records.append(dict(**{k:rows[i][k] for k in ('sha256','label','source')},fold=n,reviewer_score=float(hp[j])))
            summary['variants']['structural_control']=dict(complete=True,features=schema,folds=results)
            a.cache.dump(panel/'rich-ablation-summary.json',summary)
            a.cache.dump(panel/'split-manifest.json',dict(mode='template',groups=groups,folds=folds))
            a.cache.dump(panel/'structural_control'/'development-scores.json',records)
            a.cache.dump(source/'inputs.json',dict(rich_cache=str(collection),converted_acquisition_sha256=[],input_sha256={}))
            args=SimpleNamespace(run=source,root=root,mode='template',variant=['structural_control'],output=out)
            originals={p:a.cache.digest(p) for p in source.rglob('*.json')}
            with patch.object(a.r,'validate_cache',return_value=({},{})),patch.object(a.r,'matrices',return_value={'structural_control':(X,schema)}),patch.object(a.g,'fit_model',side_effect=AssertionError('audit must not fit')):
                a.run(args)
            report=a.cache.read(out/'rich-calibration-audit-summary.json')
            self.assertTrue(report['complete'])
            self.assertEqual(len(report['variants']['structural_control']),5)
            self.assertEqual(originals,{p:a.cache.digest(p) for p in source.rglob('*.json')})


if __name__=='__main__':
    unittest.main()
