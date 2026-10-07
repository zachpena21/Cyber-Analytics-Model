#!/usr/bin/env python3
"""Calibration constraint attribution and end-to-end immutable ensemble replay."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_seed_ensemble_calibration_audit as a
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


class AuditTests(unittest.TestCase):
    def test_next_recall_blocker_is_calibration_benign(self):
        rows=[dict(sha256=f'{i:064x}',label=int(i<2),source='calibration',adapter_probability=1.) for i in range(27)]
        entries={x['sha256']:dict(record=x) for x in rows}
        scores=np.asarray([.9,.8,.85]+[.1]*24)
        policy=a.r.s.software_calibration(rows,scores,entries)
        result=a.c.audit_policy(rows,scores,entries,'software',policy)
        self.assertEqual(result['selected']['threshold'],.9)
        self.assertEqual(result['next_lower_threshold_increasing_recall']['threshold'],.8)
        self.assertEqual(result['limiting_sample_details'][0]['constraint'],'overall')
        self.assertEqual(result['limiting_sample_details'][0]['new_errors'][0]['sha256'],rows[2]['sha256'])
        self.assertFalse(result['held_alternative_thresholds_evaluated'])
        scores[2]=.7
        after=a.r.s.software_calibration(rows,scores,entries)
        self.assertEqual(after['threshold'],.8)

    def test_full_replay_no_fits_no_changes_and_saved_ensemble_tamper(self):
        entries,features,new=fixture();config=dict(n_estimators=2,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(a.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(tmp);original=root/'original';stability=root/'stability';ensemble=root/'ensemble';out=root/'audit'
            groups,plans,_=a.t.make_plan(entries,NAMES,features,new,original)
            summary=a.t.panel(entries,NAMES,features,new,groups,plans,original);summary['complete']=True
            a.cache.dump(original/'targeted-coverage-summary.json',summary)
            prior=root/'prior/rich-feature-summary.json';target=root/'target/targeted-feature-summary.json'
            a.cache.dump(prior,{});a.cache.dump(target,{})
            a.cache.dump(original/'inputs.json',dict(seed=8704,input_sha256={str(p):a.cache.digest(p) for p in (prior,target,Path(a.t.__file__).resolve())}))
            with patch.object(a.t,'load_inputs',return_value=(entries,NAMES,features,new,{})):
                a.s.run(SimpleNamespace(root=root,run=original,output=stability,resume=None,structural_bundle=root/'frozen'))
                a.e.run(SimpleNamespace(root=root,run=stability,output=ensemble,structural_bundle=root/'frozen'))
            before={str(p):a.cache.digest(p) for d in (original,stability,ensemble) for p in d.rglob('*') if p.is_file()}
            args=SimpleNamespace(root=root,run=ensemble,output=out,structural_bundle=root/'frozen')
            with patch.object(a.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(a.r.g,'fit_model',side_effect=AssertionError('No fitting')):
                a.run(args)
            report=a.cache.read(out/'seed-ensemble-calibration-audit-summary.json')
            self.assertTrue(report['complete']);self.assertFalse(report['training']);self.assertFalse(report['threshold_tuning'])
            self.assertFalse(report['held_threshold_search']);self.assertEqual(len(report['arms']),4)
            for arm in report['arms'].values():
                self.assertEqual(len(arm['folds']),5)
                self.assertTrue(all(f['reproduced'] for f in arm['folds']))
            self.assertEqual(before,{str(p):a.cache.digest(p) for d in (original,stability,ensemble) for p in d.rglob('*') if p.is_file()})
            damaged=ensemble/'plus_imports/prior_only/development-scores.json';records=a.cache.read(damaged)
            records[0]['reviewer_score']+=.001;a.cache.dump(damaged,records);args.output=root/'bad'
            with patch.object(a.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),self.assertRaisesRegex(ValueError,'scores do not reproduce'):
                a.run(args)
            self.assertFalse(args.output.exists())


if __name__=='__main__':unittest.main()
