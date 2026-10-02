"""Entropy grouping, software constraints, complete held coverage and exports."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_software_calibration as s
from test_reviewer_v8_grouped_experiment import NAMES, pool


def software_pool():
    entries=pool(groups=20,size=24)
    for e in entries.values():
        if e['record']['label']==0:
            group=int(e['feature_vector'][NAMES.index('symbols')])
            e['provenance']={'provenance':{'package':'package-'+str(group)}}
    return entries


class SoftwareCalibrationTests(unittest.TestCase):
    def test_entropy_variants_link_but_other_differences_do_not(self):
        entries=pool(groups=1,size=1); keys=sorted(entries)
        entries[keys[1]]=copy.deepcopy(entries[keys[0]])
        entries[keys[1]]['feature_vector'][NAMES.index('byte_entropy')]+=.03
        self.assertNotEqual(s.c.fingerprint(entries[keys[0]]),s.c.fingerprint(entries[keys[1]]))
        self.assertEqual(s.stable_fingerprint(entries[keys[0]],NAMES),s.stable_fingerprint(entries[keys[1]],NAMES))
        for mode in s.c.MODES:
            groups=s.stable_groups(entries,NAMES,mode)
            self.assertEqual(groups[keys[0]],groups[keys[1]])
        entries[keys[1]]['feature_vector'][NAMES.index('sizeof_code')]+=1
        self.assertNotEqual(s.stable_fingerprint(entries[keys[0]],NAMES),s.stable_fingerprint(entries[keys[1]],NAMES))

    def test_small_software_errors_cannot_hide_in_large_sources(self):
        entries=pool(groups=1,size=1000); keys=sorted(entries); rows=[entries[k]['record'] for k in keys]
        benign=[i for i,r in enumerate(rows) if r['label']==0]; malware=[i for i,r in enumerate(rows) if r['label']==1]
        for i in benign[:20]:entries[keys[i]]['provenance']={'provenance':{'package':'scipy'}}
        scores=np.zeros(len(rows)); scores[benign[:1]]=.9; scores[malware]=.8
        ordinary=s.g.calibration(rows,scores,lambda t:s.g.gated(rows,scores,t))
        robust=s.software_calibration(rows,scores,entries)
        self.assertEqual(ordinary['overall']['fn'],0)
        self.assertEqual(robust['software_benign']['software:scipy']['fp'],0)
        self.assertEqual(robust['overall']['fn'],1000)
        self.assertFalse(s.c.assess_policy(robust,{'diverse':True})['eligible_development_policy'])

    def test_split_counts_and_entropy_isolation_and_complete_control(self):
        entries=software_pool(); keys=sorted(entries); rows=[entries[k]['record'] for k in keys]
        groups=s.stable_groups(entries,NAMES,'provenance'); fp={k:s.stable_fingerprint(entries[k],NAMES) for k in keys}
        folds=s.g.group_folds(rows,groups,5); plan=s.split_plan(rows,groups,fp,folds,entries)
        for f in plan:
            self.assertEqual(len(set(folds[f['calibration']])),2)
            self.assertTrue(f['calibration_software']['diverse']); self.assertTrue(f['fit_software']['diverse'])
            s.c.assert_split(rows,groups,[f[k] for k in ('fit','calibration','held')])
        bad=copy.deepcopy(entries)
        for e in bad.values():e.pop('provenance',None)
        with self.assertRaisesRegex(ValueError,'No qualifying'):
            s.split_plan(rows,groups,fp,folds,bad)
        config=dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory, patch.dict(s.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            for mode in s.c.MODES:
                target=Path(directory)/mode
                result=s.control(entries,NAMES,target,mode)
                self.assertTrue(result['complete'])
                scores=s.g.f.read(target/'development-scores.json')
                self.assertEqual(len(scores),len(entries)); self.assertEqual({r['sha256'] for r in scores},set(entries))
                for f in result['folds']:self.assertLess(f['export_parity'],1e-10)
                for policy in ('ordinary','software','fixed'):
                    for metric in ('count','benign','malicious','fp','fn'):
                        self.assertEqual(sum(f['held'][policy]['overall'][metric] for f in result['folds']),result['pooled'][policy]['overall'][metric])

    def test_error_audit_requires_bound_labels_and_complete_scores(self):
        entries=software_pool(); rows=[]
        for sha,e in entries.items():
            if e['record']['label']==0 and e['feature_vector'][NAMES.index('symbols')]==0:
                e['provenance']={'provenance':{'package':'scipy'}}
            rows.append(dict(sha256=sha,label=e['record']['label'],source=e['record']['source'],fixed_prediction=1,calibrated_prediction=0))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); previous=root/'previous'; output=root/'output'
            s.g.f.w.dump(previous/'control-summary.json',dict(complete=True,mode='provenance'))
            s.g.f.w.dump(previous/'development-scores.json',rows)
            result=s.error_audit(entries,NAMES,previous,output)
            self.assertEqual(result['software']['software:scipy']['fixed_fp'],24)
            rows[0]['label']=1-rows[0]['label']; s.g.f.w.dump(previous/'development-scores.json',rows)
            with self.assertRaisesRegex(ValueError,'mismatch'):s.error_audit(entries,NAMES,previous,output)


if __name__=='__main__':unittest.main()
