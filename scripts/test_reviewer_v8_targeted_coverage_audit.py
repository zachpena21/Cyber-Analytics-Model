#!/usr/bin/env python3
"""Read-only saved-score/tree replay and tamper checks."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_targeted_coverage_audit as a
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


class AuditTests(unittest.TestCase):
    def test_replay_analyze_no_training_or_source_edits_and_tamper(self):
        entries,features,new=fixture();config=dict(n_estimators=4,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(a.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            out=Path(tmp);groups,plans,_=a.t.make_plan(entries,NAMES,features,new,out)
            summary=a.t.panel(entries,NAMES,features,new,groups,plans,out);summary['complete']=True
            manifest=a.cache.read(out/'split-manifest.json')
            hashes={str(p):a.cache.digest(p) for p in out.rglob('*') if p.is_file()}
            with patch.object(a.r.g,'fit_model',side_effect=AssertionError('audit must not fit')):
                records,models,bound,maximum=a.replay(entries,NAMES,features,new,out,summary,manifest)
                result=a.analyze(entries,NAMES,features,new,summary,manifest,records,models)
            self.assertLessEqual(maximum,1e-10);self.assertEqual(len(models),20);self.assertEqual(len(result['folds']),5)
            self.assertEqual(hashes,{str(p):a.cache.digest(p) for p in out.rglob('*') if p.is_file()})
            for fold in result['folds']:
                self.assertEqual(fold['descriptive_threshold_swap']['old_model_old_threshold'],
                    summary['arms']['plus_imports/prior_only']['folds'][fold['fold']]['held']['prior']['software']['sample_metrics'])
            bad=copy.deepcopy(manifest);bad['folds'][0]['calibration'].append(sorted(new)[0])
            with self.assertRaises(ValueError):a.replay(entries,NAMES,features,new,out,summary,bad)
            score_path=out/'plus_imports/prior_only/development-scores.json';scores=a.cache.read(score_path)
            scores[0]['reviewer_score']+=.01;a.cache.dump(score_path,scores)
            with self.assertRaisesRegex(ValueError,'Held score/gate replay'):
                a.replay(entries,NAMES,features,new,out,summary,manifest)

    def test_tree_raw_changes_match_prediction_logits(self):
        entries,features,new=fixture();keys=sorted(entries);X,schema=a.r.matrices(entries,NAMES,features)['plus_imports']
        config=dict(n_estimators=3,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with patch.dict(a.r.g.f.w.CONFIG,config,clear=True):
            ids=[i for i,k in enumerate(keys) if k not in new];allrows=[entries[k]['record'] for k in keys]
            left=a.r.g.fit_model(X[ids],[allrows[i] for i in ids]);right=a.r.g.fit_model(X,allrows)
            before=a.r.g.tree_payload(left,schema,.8);after=a.r.g.tree_payload(right,schema,.8)
            vector=X[0];change=a.tree_changes(before,after,vector)
            bp=a.training_order_scores(before,[vector])[0];ap=a.training_order_scores(after,[vector])[0]
            self.assertAlmostEqual(change['total_raw_change'],float(np.log(ap/(1-ap))-np.log(bp/(1-bp))),places=12)
            self.assertEqual(len(change['largest_contribution_changes']),3)
            for tree in change['largest_contribution_changes']:
                self.assertIn('steps',tree['before_path']);self.assertIn('steps',tree['after_path'])

    def test_float32_values_use_double_threshold_comparisons(self):
        lo=1.;hi=float(np.nextafter(np.float32(lo),np.float32(2.)))
        tree=dict(children_left=[1,-1,-1],children_right=[2,-1,-1],feature=[0,-1,-1],
                  threshold=[lo+(hi-lo)*.75,0.,0.],raw_value=[0.,-1.,1.])
        payload=dict(feature_names=['x'],estimators=[tree],learning_rate=1.,initial_raw_score=0.)
        self.assertEqual(a.traced_path(payload,[hi],0)['leaf'],2)
        self.assertEqual(a.traced_path(payload,[lo],0)['leaf'],1)
        self.assertGreater(a.training_order_scores(payload,[[hi]])[0],.5)

    def test_group_counts_are_representations_not_family_labels(self):
        keys=['a','b','c'];rows=[{'label':1},{'label':1},{'label':0}];groups={'a':'g','b':'g','c':'h'}
        result=a.change_groups(keys,rows,groups,np.array([.99,.98,.9]),np.array([.8,.81,.92]),.95,.951)
        self.assertEqual(result[0]['count'],2);self.assertEqual(result[0]['sha256'],['a','b'])
        self.assertAlmostEqual(result[0]['median_score_change'],-.18)


if __name__=='__main__':unittest.main()
