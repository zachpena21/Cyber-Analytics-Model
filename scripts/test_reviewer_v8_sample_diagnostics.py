import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_sample_diagnostics as q
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_grouped_experiment import NAMES


class SampleDiagnosticTests(unittest.TestCase):
    def test_higher_score_can_regress_due_to_threshold(self):
        row = dict(label=1,adapter_probability=.9)
        before = dict(reviewer_score=.8,software_prediction=1)
        after = dict(reviewer_score=.9,software_prediction=0)
        r = q.sample_change(row,before,after,.7,.95,'software')
        self.assertEqual(r['outcome'],'regressed')
        self.assertGreater(r['correctness_score_contribution'],0)
        self.assertLess(r['correctness_threshold_contribution'],0)
        self.assertAlmostEqual(r['margin_delta'],r['after_margin']-r['before_margin'])
        self.assertFalse(r['score_change_alone_reproduces_flip'])
        self.assertTrue(r['threshold_change_alone_reproduces_flip'])

    def test_gate_and_constant_features(self):
        row = dict(label=0,adapter_probability=.1)
        b = dict(reviewer_score=.8,fixed_prediction=0)
        r = q.sample_change(row,b,b,.6,.6,'fixed')
        self.assertFalse(r['routed']);self.assertIsNone(r['before_margin'])
        altered = dict(reviewer_score=.8,fixed_prediction=1)
        with self.assertRaisesRegex(ValueError,'non-routed'):
            q.sample_change(row,b,altered,.6,.6,'fixed')
        profile = q.feature_profiles(np.ones((3,1)),['constant'],[0],[1,2])
        self.assertIsNone(profile['features']['constant']['median_delta_over_reference_iqr'])
        self.assertEqual(profile['largest_standardized_median_shifts'],[])

    def test_full_export_audit_cohorts_and_overlap_accounting(self):
        entries = software_pool()
        config = dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory,patch.dict(q.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(directory); software=root/'software'; ablation=root/'ablation'; partial=root/'partial';mode='provenance'
            q.s.control(entries,NAMES,software/mode,mode)
            q.a.experiment_panel(entries,NAMES,software,ablation/mode,mode)
            q.p.experiment_panel(entries,NAMES,ablation,software,partial/mode,mode)
            summary,groups,records,_ = q.d.checked_panel(entries,NAMES,partial,mode,{})
            result=q.analyze_panel(entries,NAMES,summary,groups,records,root/'diagnostics')
            for policy in q.a.POLICIES:
                for label,name in ((0,'benign'),(1,'malware')):
                    count=sum(e['record']['label']==label for e in entries.values())
                    self.assertEqual(sum(r['count'] for r in result['overlap'][policy][name]),count)
                    for variant in q.CHALLENGERS:
                        cohorts=result['variants'][variant][policy]['cohorts'][name]
                        self.assertEqual(sum(r['count'] for r in cohorts.values()),count)
                        for kind in ('rescued','regressed'):
                            self.assertEqual(cohorts[kind]['count'],summary['paired_vs_full'][variant][policy]['overall'][name][kind])
                for variant in q.CHALLENGERS:
                    detail=q.g.f.read(root/'diagnostics'/f'{variant}-{policy}-changed-samples.json')
                    self.assertEqual(len(detail['samples']),result['variants'][variant][policy]['changed_samples'])
                    for r in detail['samples']:
                        self.assertEqual(len(r['features']),72)
                        self.assertAlmostEqual(r['margin_delta'],r['after_margin']-r['before_margin'])
            bad=copy.deepcopy(summary)
            bad['paired_vs_full']['structural_66']['fixed']['overall']['malware']['rescued']+=1
            with self.assertRaisesRegex(ValueError,'paired counts'):
                q.analyze_panel(entries,NAMES,bad,groups,records,root/'bad')


if __name__=='__main__':unittest.main()
