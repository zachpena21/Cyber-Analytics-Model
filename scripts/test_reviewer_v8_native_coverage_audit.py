#!/usr/bin/env python3
"""Audit replay integrity, read-only behavior and fit-only profile comparisons."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import reviewer_v8_native_coverage_audit as a
from test_reviewer_v8_targeted_coverage_experiment import fixture
from test_reviewer_v8_native_coverage import additions
from test_reviewer_v8_grouped_experiment import NAMES


class AuditTests(unittest.TestCase):
    def test_json_error_identifies_file_and_reader_is_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'empty.json';path.write_text('')
            original=a.cache.read
            with self.assertRaisesRegex(ValueError,r'Cannot parse JSON: .*empty.json \(0 bytes\)'):
                with a.named_json_reads():a.cache.read(path)
            self.assertIs(a.cache.read,original)
            path.write_text('{invalid')
            with self.assertRaisesRegex(ValueError,r'Cannot parse JSON: .*empty.json \(8 bytes\)'):
                with a.named_json_reads():a.cache.read(path)
            self.assertIs(a.cache.read,original)

    def test_label_aware_changes(self):
        entries={str(i):dict(record=dict(label=label)) for i,label in enumerate((1,1,0,0,1))}
        before={str(i):dict(software_prediction=value) for i,value in enumerate((1,0,1,0,1))}
        after={str(i):dict(software_prediction=value) for i,value in enumerate((0,1,0,1,1))}
        self.assertEqual(a.change_sets(entries,before,after,'software'),dict(malware_regressed=['0'],malware_rescued=['1'],benign_rescued=['2'],benign_regressed=['3']))

    def test_full_replay_profiles_no_training_and_tamper(self):
        n=a.n;entries,features,earlier=fixture();combined,extra,native=additions(entries,features)
        config=dict(n_estimators=2,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(a.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(tmp);base=root/'baseline';source=root/'reviewer-v8-native-coverage-test';out=root/'audit'
            prior=root/'prior/rich-feature-summary.json';a.cache.dump(prior,{})
            hashes={str(prior):a.cache.digest(prior)}
            n.t.make_plan(entries,NAMES,features,earlier,root/'plan');old=a.cache.read(root/'plan/split-manifest.json')
            plans=n.s.plans_from_manifest(old,entries)
            original=root/'original';summary=n.t.panel(entries,NAMES,features,earlier,old['groups'],plans,original)
            records,oldmodels,_,_=n.audit.replay(entries,NAMES,features,earlier,original,summary,old)
            previous={seed:{(v+'/prior_only',f):oldmodels[(v+'/targeted_fit_added',f)] for v in n.t.VARIANTS for f in range(5)} for seed in n.s.SEEDS}
            references={seed:{v:records[v+'/targeted_fit_added'] for v in n.t.VARIANTS} for seed in n.s.SEEDS}
            reference_models={seed:{(v+'/'+arm,f):previous[seed][(v+'/prior_only',f)] for v in n.t.VARIANTS for arm in n.t.ARMS for f in range(5)} for seed in n.s.SEEDS}
            baseline=n.e.ensemble(entries,NAMES,features,earlier,old,reference_models,{},base)
            loaded=(entries,NAMES,features,earlier,hashes,old,{},baseline,{},base)
            native_input=({k:v for k,v in combined.items() if k not in earlier},NAMES,{k:v for k,v in extra.items() if k not in earlier},native,{})
            args=SimpleNamespace(root=root,run=base,native_cache=root/'native',structural_bundle=root/'frozen',output=source,resume=None,audit_only=False)
            with patch.object(n.baseline_loader,'load_baseline',return_value=loaded),patch.object(n.t,'load_inputs',return_value=native_input),patch.object(n,'load_previous_models',side_effect=lambda *args:(copy.deepcopy(previous),references)):
                with a.recovery.checked_scorer():n.run(args)
                with a.named_json_reads(),patch.object(a.r.g,'fit_model',side_effect=AssertionError('Preflight must not train')):
                    self.assertEqual(a.check_saved_json(source),source)
                before={str(p):a.cache.digest(p) for folder in (source,base,original) for p in folder.rglob('*') if p.is_file()}
                settings=SimpleNamespace(root=root,run=source,structural_bundle=root/'frozen',output=out)
                with patch.object(a.r.g,'fit_model',side_effect=AssertionError('Audit must not train')):a.run(settings)
                report=a.cache.read(out/'native-coverage-audit-summary.json')
                self.assertTrue(report['complete']);self.assertFalse(report['training']);self.assertEqual(report['replayed_seeds'],list(n.s.SEEDS))
                manifest=a.cache.read(source/'split-manifest.json')
                # Exercise profiles with an explicit in-memory changed decision;
                # the tiny integration models can legitimately change no gates.
                lookups={v+'/'+arm:{x['sha256']:x for x in a.cache.read(source/'ensemble'/v/arm/'development-scores.json')}
                         for v in n.t.VARIANTS for arm in n.t.ARMS}
                chosen=next(f for f in manifest['folds'] if set(f['expanded_fit'])&native)
                sha=next(k for k in chosen['held'] if combined[k]['record']['label']==0)
                lookups['plus_imports/prior_only'][sha]['software_prediction']=1
                lookups['plus_imports/targeted_fit_added'][sha]['software_prediction']=0
                models=copy.deepcopy(previous)
                for seed in n.s.SEEDS:
                    for v in n.t.VARIANTS:
                        for f in range(5):models[seed][(v+'/targeted_fit_added',f)]=a.cache.read(source/f'seed-{seed}'/v/'targeted_fit_added'/f'fold-{f:02d}-model.json')
                result=a.analyze(combined,NAMES,extra,earlier,native,manifest,models,lookups,a.cache.read(source/'native-coverage-summary.json'),{})
                self.assertTrue(result['profiles']);self.assertIn(sha,result['changes']['software']['benign_rescued'])
                for profile in result['profiles']:
                    f=next(x for x in manifest['folds'] if x['fold']==profile['fold'])
                    eligible=set(f['expanded_fit'])&native
                    self.assertTrue({x['sha256'] for x in profile['nearest_native_fit']}<=eligible)
                    self.assertEqual(set(profile['per_seed_tree_changes']),set(map(str,n.s.SEEDS)))
                self.assertEqual(before,{p:a.cache.digest(p) for p in before})
                # Full repair-mode replay must recover a damaged checkpoint
                # score byte-for-byte without changing its completion marker.
                import repair_reviewer_v8_native_scores as repair
                damaged=source/'seed-8707/structural_control/prior_only/development-scores.json'
                contents=damaged.read_bytes();marker=damaged.parents[2]/'completion.json'
                marker_hash=a.cache.digest(marker);damaged.write_bytes(b'')
                with patch.object(a.r.g,'fit_model',side_effect=AssertionError('Repair must not train')):repair.run(settings)
                self.assertEqual(damaged.read_bytes(),contents);self.assertEqual(a.cache.digest(marker),marker_hash)
                # An unbound ensemble JSON file can be empty even when all
                # completed seed artifacts remain valid; preflight names it.
                path=source/'ensemble/plus_imports/targeted_fit_added/development-scores.json'
                contents=path.read_text();path.write_text('')
                with self.assertRaisesRegex(ValueError,'Cannot parse JSON: .*development-scores.json'),a.named_json_reads():a.check_saved_json(source)
                path.write_text(contents)
                # Ensemble scores have no seed marker: full saved-score replay
                # must still reject a changed score even with unchanged gates.
                path=source/'ensemble/plus_imports/targeted_fit_added/development-scores.json'
                doc=a.cache.read(path);doc[0]['reviewer_score']+=.0001;a.cache.dump(path,doc)
                settings.output=root/'blocked'
                with self.assertRaisesRegex(ValueError,'held scores/decisions'):a.run(settings)
                self.assertFalse(settings.output.exists())


if __name__=='__main__':unittest.main()
