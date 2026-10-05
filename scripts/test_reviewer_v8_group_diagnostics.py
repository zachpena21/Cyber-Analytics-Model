"""Group weighting, cluster sensitivity, score verification and paired accounting."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_group_diagnostics as d
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_grouped_experiment import NAMES


class GroupDiagnosticTests(unittest.TestCase):
    def test_group_weighting_is_not_sample_weighting(self):
        rows=[dict(sha256=str(i),label=1,source='test') for i in range(11)]
        groups={str(i):'large' if i<10 else 'small' for i in range(11)}
        pred=np.array([1]*10+[0]);m=d.group_metrics(rows,pred,groups)
        self.assertAlmostEqual(m['sample_metrics']['tpr'],10/11)
        self.assertEqual(m['equal_weight_malware_group_recall'],.5)
        self.assertEqual(m['malware_groups_zero_recall'],1)
        self.assertEqual(d.indexed_rates(rows,pred,groups),d.g.rates(rows,pred,groups))

    def test_exports_and_group_diagnostics_reconcile_and_reject_changed_scores(self):
        entries=software_pool();example=next(copy.deepcopy(e) for e in entries.values() if e['record']['label']==1)
        for i in range(76):
            sha=hashlib.sha256(('cluster-test:'+str(i)).encode()).hexdigest();e=copy.deepcopy(example)
            e['record']['sha256']=sha;e['feature_vector'][NAMES.index('symbols')]=100
            e['feature_vector'][NAMES.index('minor_linker_version')]=140
            e['feature_vector'][NAMES.index('byte_entropy')]+=i*.001
            entries[sha]=e
        config=dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory,patch.dict(d.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(directory);software=root/'software';ablation=root/'ablation';partial=root/'partial'
            mode='provenance'
            d.s.control(entries,NAMES,software/mode,mode)
            d.a.experiment_panel(entries,NAMES,software,ablation/mode,mode)
            d.p.experiment_panel(entries,NAMES,ablation,software,partial/mode,mode)
            summary,groups,records,parity=d.checked_panel(entries,NAMES,partial,mode,{})
            self.assertTrue(all(e<1e-10 for e in parity.values()))
            cluster=groups[hashlib.sha256(b'cluster-test:0').hexdigest()]
            result=d.diagnose(entries,summary,groups,records,root/'diagnostics',cluster=cluster)
            self.assertTrue(result['complete'])
            for variant in d.p.VARIANTS:
                for policy in d.a.POLICIES:
                    r=result['variants'][variant]['policies'][policy]
                    self.assertEqual(r['all']['sample_metrics']['count'],len(entries))
                    self.assertEqual(r['excluding_cluster']['sample_metrics']['count'],len(entries)-76)
                    self.assertEqual(r['cluster_only']['sample_metrics']['malicious'],76)
                    for metric in ('count','benign','malicious','fp','fn'):
                        self.assertEqual(r['all']['sample_metrics'][metric],r['excluding_cluster']['sample_metrics'][metric]+r['cluster_only']['sample_metrics'][metric])
            record_path=partial/mode/'without_base_69/development-scores.json'
            rec=d.g.f.read(record_path);rec[0]['reviewer_score']=.123456
            d.g.f.w.dump(record_path,rec)
            with self.assertRaisesRegex(ValueError,'exported-score parity'):d.checked_panel(entries,NAMES,partial,mode,{})

    def test_changed_group_score_profiles_and_pair_direction(self):
        entries={'a':{'record':dict(label=1,source='test')},'b':{'record':dict(label=0,source='test')}}
        groups={'a':'one','b':'one'}
        before={'a':dict(fold=0,reviewer_score=.4,fixed_prediction=0),'b':dict(fold=0,reviewer_score=.8,fixed_prediction=1)}
        after={'a':dict(fold=0,reviewer_score=.9,fixed_prediction=1),'b':dict(fold=0,reviewer_score=.2,fixed_prediction=0)}
        result=d.changed_groups(entries,groups,before,after,{}, {},'fixed')
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['labels']['malware']['rescued'],1)
        self.assertEqual(result[0]['labels']['benign']['rescued'],1)
        self.assertEqual(result[0]['labels']['malware']['before_scores']['median'],.4)


if __name__=='__main__':unittest.main()
