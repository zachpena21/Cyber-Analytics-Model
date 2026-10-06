#!/usr/bin/env python3
"""Matched-role isolation and coverage checks with small synthetic models."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import reviewer_v8_targeted_coverage_experiment as t
from test_reviewer_v8_rich_ablation import extras
from test_reviewer_v8_grouped_experiment import NAMES
from test_reviewer_v8_software_calibration import software_pool


def fixture():
    entries=software_pool();new=set()
    benign=[k for k in sorted(entries) if entries[k]['record']['label']==0][:12]
    for i,k in enumerate(benign):
        sha=f'{1000000+i:064x}';entry=copy.deepcopy(entries[k]);entry['record']['sha256']=sha
        entries[sha]=entry;new.add(sha)
    return entries,extras(entries),new


class CoverageTests(unittest.TestCase):
    def test_joint_groups_common_roles_and_no_new_calibration(self):
        entries,features,new=fixture();before=copy.deepcopy(entries)
        with tempfile.TemporaryDirectory() as tmp:
            groups,plans,audit=t.make_plan(entries,NAMES,features,new,Path(tmp))
            self.assertTrue(audit['all_folds_qualify']);self.assertEqual(len(audit['candidates']),30)
            keys=sorted(entries);held=[]
            for p in plans:
                oldfit={keys[i] for i in p['prior_fit']};expanded={keys[i] for i in p['expanded_fit']}
                cal={keys[i] for i in p['calibration']};hold={keys[i] for i in p['held']}
                self.assertEqual(expanded-new,oldfit);self.assertFalse(cal&new);self.assertFalse(oldfit&new)
                self.assertFalse(expanded&cal or expanded&hold or cal&hold)
                self.assertFalse({groups[k] for k in expanded}&{groups[k] for k in hold|cal})
                held.extend(hold)
            self.assertEqual(len(held),len(entries));self.assertEqual(set(held),set(entries))
        self.assertEqual(entries,before)

    def test_count_only_plan_ignores_predictions_and_scores(self):
        entries,features,new=fixture();changed=copy.deepcopy(entries)
        for e in changed.values():
            for key in list(e['record']):
                if key.endswith('_score'):e['record'][key]=.999
                elif key.endswith('_prediction'):e['record'][key]=1
        with tempfile.TemporaryDirectory() as tmp:
            ga,pa,aa=t.make_plan(entries,NAMES,features,new,Path(tmp)/'a')
            gb,pb,ab=t.make_plan(changed,NAMES,features,new,Path(tmp)/'b')
            self.assertEqual(ga,gb);self.assertEqual(aa,ab)
            for a,b in zip(pa,pb):
                for role in ('prior_fit','expanded_fit','calibration','held'):
                    self.assertEqual(a[role].tolist(),b[role].tolist())

    def test_matched_training_calibration_export_and_pooled_coverage(self):
        entries,features,new=fixture();keys=sorted(entries);seen_fit=[];seen_cal=[]
        config=dict(n_estimators=4,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        original_fit=t.r.g.fit_model;original_cal=t.r.s.software_calibration
        def fit(X,rows):seen_fit.append({r['sha256'] for r in rows});return original_fit(X,rows)
        def cal(rows,scores,entries):seen_cal.append({r['sha256'] for r in rows});return original_cal(rows,scores,entries)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(t.r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            out=Path(tmp);groups,plans,audit=t.make_plan(entries,NAMES,features,new,out)
            with patch.object(t.r.g,'fit_model',side_effect=fit),patch.object(t.r.s,'software_calibration',side_effect=cal):
                result=t.panel(entries,NAMES,features,new,groups,plans,out)
            self.assertEqual(len(seen_fit),20)
            for offset in (0,10):
                self.assertEqual(seen_cal[offset:offset+5],seen_cal[offset+5:offset+10])
                for old,expanded in zip(seen_fit[offset:offset+5],seen_fit[offset+5:offset+10]):
                    self.assertEqual(old,expanded-new)
            self.assertTrue(all(not ids&new for ids in seen_cal))
            for tag,arm in result['arms'].items():
                records=t.r.cache.read(out/tag/'development-scores.json')
                self.assertEqual(len(records),len(entries));self.assertEqual({r['sha256'] for r in records},set(keys))
                self.assertEqual(sum(r['targeted'] for r in records),len(new))
                self.assertEqual(arm['pooled']['prior']['software']['sample_metrics']['count'],len(entries)-len(new))
                self.assertEqual(arm['pooled']['targeted']['software']['sample_metrics']['count'],len(new))
                for fold in arm['folds']:self.assertLessEqual(fold['export_parity'],1e-10)
            self.assertEqual(set(result['paired_coverage']),set(t.VARIANTS))
            self.assertEqual(set(result['paired_imports']),set(t.ARMS))

    def test_blocked_diversity_produces_audit_without_training(self):
        entries,features,new=fixture()
        for e in entries.values():
            if e['record']['label']==0:e['provenance']=dict(provenance=dict(package='one-package'))
        with tempfile.TemporaryDirectory() as tmp,patch.object(t.r.g,'fit_model') as fit:
            _,plans,audit=t.make_plan(entries,NAMES,features,new,Path(tmp))
            self.assertFalse(audit['all_folds_qualify']);self.assertEqual(plans,[])
            self.assertEqual(audit['blocked_held_folds'],list(range(5)));fit.assert_not_called()


if __name__=='__main__':unittest.main()
