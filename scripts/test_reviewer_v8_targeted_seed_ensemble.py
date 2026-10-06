#!/usr/bin/env python3
"""Probability averaging, source replay integrity, and no-refit integration."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_targeted_seed_ensemble as e
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


class EnsembleTests(unittest.TestCase):
    def test_all_five_probability_average_not_vote(self):
        values=[[.99,.1],[.49,.2],[.49,.3],[.49,.4],[.49,.5]]
        np.testing.assert_allclose(e.mean_probability(values),[.59,.3])
        with self.assertRaises(ValueError):e.mean_probability(values[:4])
        with self.assertRaises(ValueError):e.mean_probability([[float('nan')]]*5)
        with self.assertRaises(ValueError):e.mean_probability([[1.1]]*5)

    def test_complete_source_replay_no_training_and_tamper_rejection(self):
        entries,features,new=fixture();config=dict(n_estimators=2,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(e.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(tmp);original=root/'original';stability=root/'stability';out=root/'ensemble'
            groups,plans,_=e.t.make_plan(entries,NAMES,features,new,original)
            summary=e.t.panel(entries,NAMES,features,new,groups,plans,original);summary['complete']=True
            e.cache.dump(original/'targeted-coverage-summary.json',summary)
            prior=root/'prior/rich-feature-summary.json';target=root/'target/targeted-feature-summary.json'
            e.cache.dump(prior,{});e.cache.dump(target,{})
            e.cache.dump(original/'inputs.json',dict(seed=8704,input_sha256={str(p):e.cache.digest(p) for p in (prior,target,Path(e.t.__file__).resolve())}))
            with patch.object(e.t,'load_inputs',return_value=(entries,NAMES,features,new,{})):
                e.s.run(SimpleNamespace(root=root,run=original,output=stability,resume=None,structural_bundle=root/'frozen'))
            before={str(p):e.cache.digest(p) for d in (original,stability) for p in d.rglob('*') if p.is_file()}
            args=SimpleNamespace(root=root,run=stability,output=out,structural_bundle=root/'frozen')
            with patch.object(e.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(e.r.g,'fit_model',side_effect=AssertionError('No fitting')):
                e.run(args)
            report=e.cache.read(out/'targeted-seed-ensemble-summary.json')
            self.assertTrue(report['complete']);self.assertFalse(report['training']);self.assertFalse(report['independent_validation'])
            self.assertEqual(report['seeds'],list(e.s.SEEDS));self.assertEqual(report['weights'],[.2]*5)
            self.assertEqual(len(report['arms']),4);self.assertLessEqual(report['saved_seed_replay_max_abs_error'],1e-9)
            manifest=e.cache.read(stability/'split-manifest.json');fold=manifest['folds'][0];tag='plus_imports/targeted_fit_added'
            models=[]
            for seed in e.s.SEEDS:
                location=original if seed==8704 else stability/f'seed-{seed}'
                models.append(e.cache.read(location/tag/f'fold-{fold["fold"]:02d}-model.json'))
            X,_=e.r.matrices(entries,NAMES,features)['plus_imports'];keys=sorted(entries);index={k:i for i,k in enumerate(keys)}
            expected=e.mean_probability([e.audit.training_order_scores(model,X[[index[k] for k in fold['held']]]) for model in models])
            scores={x['sha256']:x for x in e.cache.read(out/tag/'development-scores.json')}
            np.testing.assert_allclose([scores[k]['reviewer_score'] for k in fold['held']],expected,atol=1e-15)
            cp=e.mean_probability([e.audit.training_order_scores(model,X[[index[k] for k in fold['calibration']]]) for model in models])
            policy=e.r.c.assess_policy(e.r.s.software_calibration([entries[k]['record'] for k in fold['calibration']],cp,entries),fold['calibration_diversity'])
            self.assertEqual(report['arms'][tag]['folds'][0]['calibration'],policy)
            self.assertEqual(before,{str(p):e.cache.digest(p) for d in (original,stability) for p in d.rglob('*') if p.is_file()})
            damaged=stability/'seed-8708/plus_imports/prior_only/development-scores.json'
            damaged.write_text(damaged.read_text()+' ');args.output=root/'bad'
            with patch.object(e.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),self.assertRaisesRegex(ValueError,'Input changed'):
                e.run(args)
            self.assertFalse(args.output.exists())


if __name__=='__main__':unittest.main()
