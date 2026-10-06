#!/usr/bin/env python3
"""Fixed splits, all-seed reporting, failure restoration and completed-seed resume."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import reviewer_v8_targeted_seed_stability as s
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_grouped_experiment import NAMES


class StabilityTests(unittest.TestCase):
    def test_training_seed_restored_on_failure(self):
        before=s.r.g.SEED
        with self.assertRaisesRegex(RuntimeError,'stop'):
            with s.training_seed(8708):
                self.assertEqual(s.r.g.SEED,8708);raise RuntimeError('stop')
        self.assertEqual(s.r.g.SEED,before)
        self.assertEqual(s.SEEDS,(8704,8705,8706,8707,8708))

    def test_all_seeds_fixed_splits_source_integrity_and_resume(self):
        entries,features,new=fixture();config=dict(n_estimators=3,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(s.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(tmp);source=root/'original';out=root/'stability'
            groups,plans,_=s.t.make_plan(entries,NAMES,features,new,source)
            original=s.t.panel(entries,NAMES,features,new,groups,plans,source);original['complete']=True
            s.cache.dump(source/'targeted-coverage-summary.json',original)
            prior=root/'prior/rich-feature-summary.json';target=root/'target/targeted-feature-summary.json'
            s.cache.dump(prior,{});s.cache.dump(target,{})
            bindings={str(p):s.cache.digest(p) for p in (prior,target,Path(s.t.__file__).resolve())}
            s.cache.dump(source/'inputs.json',dict(input_sha256=bindings,seed=8704))
            old_hashes={str(p):s.cache.digest(p) for p in source.rglob('*') if p.is_file()}
            args=SimpleNamespace(root=root,run=source,structural_bundle=root/'frozen',output=out,resume=None)
            fit=s.r.g.fit_model;seen=[]
            def tracked(X,rows):
                seen.append((s.r.g.SEED,frozenset(r['sha256'] for r in rows)))
                return fit(X,rows)
            with patch.object(s.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(s.r.g,'fit_model',side_effect=tracked):
                s.run(args)
            self.assertEqual(len(seen),80)
            for seed in s.SEEDS[1:]:
                self.assertEqual(sum(actual==seed for actual,_ in seen),20)
            self.assertEqual([ids for seed,ids in seen if seed==8705],[ids for seed,ids in seen if seed==8708])
            report=s.cache.read(out/'targeted-seed-stability-summary.json')
            self.assertTrue(report['complete']);self.assertEqual(report['completed_seeds'],list(s.SEEDS))
            self.assertFalse(report['seed_selection']);self.assertFalse(report['ensemble']);self.assertFalse(report['split_search'])
            self.assertEqual(len(report['per_seed']),5)
            self.assertEqual(report['per_seed'][0]['arms']['plus_imports/prior_only']['pooled'],original['arms']['plus_imports/prior_only']['pooled'])
            args.resume=out
            with patch.object(s.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),patch.object(s.r.g,'fit_model',side_effect=AssertionError('resume must skip fits')):
                s.run(args)
            self.assertEqual(report,s.cache.read(out/'targeted-seed-stability-summary.json'))
            self.assertEqual(old_hashes,{str(p):s.cache.digest(p) for p in source.rglob('*') if p.is_file()})
            damaged=out/'seed-8705/plus_imports/prior_only/development-scores.json'
            damaged.write_text(damaged.read_text()+' ')
            with patch.object(s.t,'load_inputs',return_value=(entries,NAMES,features,new,{})),self.assertRaisesRegex(ValueError,'Input changed'):
                s.run(args)

    def test_aggregate_retains_negative_effects_without_winner_selection(self):
        entries,features,new=fixture();config=dict(n_estimators=2,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(s.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            out=Path(tmp);groups,plans,_=s.t.make_plan(entries,NAMES,features,new,out)
            summary=s.t.panel(entries,NAMES,features,new,groups,plans,out)
            records={tag:{r['sha256']:r for r in s.cache.read(out/tag/'development-scores.json')} for tag in summary['arms']}
            watch={next(iter(groups.values())):[k for k in entries if groups[k]==next(iter(groups.values())) and entries[k]['record']['label']==1]}
            watch={g:ks for g,ks in watch.items() if ks}
            first=s.summarize_seed(8704,summary,records,entries,new,groups,watch);second=copy.deepcopy(first);second['seed']=8705
            metric=second['arms']['plus_imports/targeted_fit_added']['pooled']['prior']['software']['sample_metrics']
            metric['fn']+=10
            result=s.aggregate([first,second]);effects=result['coverage_effect']['plus_imports']['per_seed']
            self.assertEqual(effects[1]['additional_malware_detected'],effects[0]['additional_malware_detected']-10)
            self.assertEqual(result['seeds'],[8704,8705]);self.assertNotIn('best_seed',result)


if __name__=='__main__':unittest.main()
