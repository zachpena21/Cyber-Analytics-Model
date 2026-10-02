"""Matched split/feature isolation, reproduction and paired error accounting."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_score_ablation as a
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_grouped_experiment import NAMES


class ScoreAblationTests(unittest.TestCase):
    def test_removed_scores_cannot_change_structural_inputs(self):
        entries=software_pool(); data=a.matrices(entries,NAMES); changed=copy.deepcopy(entries)
        for e in changed.values():e['feature_vector'][:6]=[.11,.22,.33,.44,.55,.66]
        other=a.matrices(changed,NAMES)
        self.assertEqual(data['full_72'][0].shape[1],72)
        self.assertEqual(data['structural_66'][0].shape[1],66)
        np.testing.assert_array_equal(data['structural_66'][0],other['structural_66'][0])
        self.assertFalse(np.array_equal(data['full_72'][0],other['full_72'][0]))
        self.assertFalse(set(NAMES[:6])&set(data['structural_66'][1]))

    def test_paired_changes_account_for_rescues_and_regressions(self):
        rows=[dict(label=x,source='test') for x in (0,0,1,1)]
        result=a.paired(rows,np.array([1,0,0,1]),np.array([0,1,1,0]))
        for label in ('benign','malware'):
            self.assertEqual(result['overall'][label],dict(count=2,rescued=1,regressed=1))

    def test_complete_reproduction_and_ablation_and_tamper_rejection(self):
        entries=software_pool(); config=dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory,patch.dict(a.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(directory); previous=root/'previous'
            for mode in a.c.MODES:
                a.s.control(entries,NAMES,previous/mode,mode)
                result=a.experiment_panel(entries,NAMES,previous,root/'ablation'/mode,mode)
                self.assertTrue(result['complete']);self.assertLessEqual(result['baseline_max_score_error'],1e-10)
                before=a.g.f.read(previous/mode/'split-manifest.json');after=a.g.f.read(root/'ablation'/mode/'split-manifest.json')
                self.assertEqual(before,after)
                for variant,v in result['variants'].items():
                    self.assertTrue(v['complete'])
                    scores=a.g.f.read(root/'ablation'/mode/variant/'development-scores.json')
                    self.assertEqual(len(scores),len(entries));self.assertEqual({r['sha256'] for r in scores},set(entries))
                    for f in v['folds']:self.assertLess(f['export_parity'],1e-10)
                for policy in a.POLICIES:
                    b=result['variants']['full_72']['pooled'][policy]['overall'];r=result['variants']['structural_66']['pooled'][policy]['overall']
                    paired=result['paired'][policy]['overall']
                    self.assertEqual(b['fp']-r['fp'],paired['benign']['rescued']-paired['benign']['regressed'])
                    self.assertEqual(b['fn']-r['fn'],paired['malware']['rescued']-paired['malware']['regressed'])
            scores=a.g.f.read(previous/'provenance/development-scores.json');scores[0]['reviewer_score']+=.1
            a.g.f.w.dump(previous/'provenance/development-scores.json',scores)
            with self.assertRaisesRegex(ValueError,'baseline score reproduction'):
                a.experiment_panel(entries,NAMES,previous,root/'bad','provenance')
            manifest=a.g.f.read(previous/'template/split-manifest.json')
            manifest['folds'][0]['fit'].append(manifest['folds'][0]['held'][0])
            a.g.f.w.dump(previous/'template/split-manifest.json',manifest)
            with self.assertRaisesRegex(ValueError,'overlap'):
                a.previous_panel(entries,NAMES,previous,'template')

    def test_default_selects_latest_completed_run_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);complete=root/'reviewer-v8-software-calibration-development-1';incomplete=root/'reviewer-v8-software-calibration-development-2'
            a.g.f.w.dump(complete/'calibration-comparison-summary.json',{'complete':True})
            a.g.f.w.dump(incomplete/'calibration-comparison-summary.json',{'complete':False})
            self.assertEqual(a.find_previous(root),complete)


if __name__=='__main__':unittest.main()
