import copy
import hashlib
import itertools
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_bounded_upstream as b
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_grouped_experiment import NAMES


class BoundedUpstreamTests(unittest.TestCase):
    def test_global_bound_zero_identity_and_invalid_inputs(self):
        Z=np.array(list(itertools.product((-1.,1.),repeat=4)))
        scores=np.linspace(.001,.999,len(Z))
        for beta in itertools.product((-.125,.125),repeat=4):
            corrected,offset=b.correct(scores,Z,beta)
            self.assertLessEqual(float(np.abs(offset).max()),.5)
            self.assertTrue(np.all((corrected>0)&(corrected<1)))
        np.testing.assert_allclose(b.correct(scores,Z,[0]*4)[0],scores,atol=1e-15)
        with self.assertRaisesRegex(ValueError,'exceeds bound'):b.correct(scores,Z,[.2,0,0,0])
        with self.assertRaisesRegex(ValueError,'Invalid structural'):b.correct([-1],Z[:1],[0]*4)

    def test_fit_uses_routed_fitting_rows_only(self):
        rows=[dict(label=i%2,adapter_probability=.9 if i%2 else .4,
                   benign_probability=.1 if i%2 else .9,signature_checked=0,signature_verified=0) for i in range(20)]
        base=np.full(len(rows),.5);beta,report=b.fit_correction(rows,base)
        self.assertLess(report['objective'],report['zero_correction_objective'])
        self.assertTrue(np.all(np.abs(beta)<=.125));self.assertEqual(report['routed_fit_count'],20)
        # Non-routed labels cannot affect the correction fit.
        extra=dict(label=0,adapter_probability=.1,benign_probability=.5,signature_checked=1,signature_verified=1)
        extended=rows+[extra];scores=np.r_[base,.99]
        first=b.fit_correction(extended,scores)[0];extended[-1]['label']=1
        np.testing.assert_array_equal(first,b.fit_correction(extended,scores)[0])

    def test_matched_panel_exports_and_cluster_sensitivity(self):
        entries=software_pool();example=next(copy.deepcopy(e) for e in entries.values() if e['record']['label']==1)
        for i in range(76):
            sha=hashlib.sha256(('bounded-cluster:'+str(i)).encode()).hexdigest();e=copy.deepcopy(example)
            e['record']['sha256']=sha;e['feature_vector'][NAMES.index('symbols')]=100
            e['feature_vector'][NAMES.index('minor_linker_version')]=140
            e['feature_vector'][NAMES.index('byte_entropy')]+=i*.001;entries[sha]=e
        config=dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory,patch.dict(b.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(directory);software=root/'software';ablation=root/'ablation';partial=root/'partial';mode='provenance'
            b.s.control(entries,NAMES,software/mode,mode)
            b.a.experiment_panel(entries,NAMES,software,ablation/mode,mode)
            b.p.experiment_panel(entries,NAMES,ablation,software,partial/mode,mode)
            groups=b.s.stable_groups(entries,NAMES,mode)
            cluster=groups[hashlib.sha256(b'bounded-cluster:0').hexdigest()]
            with patch.object(b.d,'CLUSTER',cluster):
                result=b.experiment_panel(entries,NAMES,partial,root/'bounded',mode,{})
            self.assertTrue(result['complete'])
            self.assertTrue(all(f['export_max_error']<1e-10 and f['max_abs_logit_correction']<=.5+1e-12 for f in result['folds']))
            scores=b.g.f.read(root/'bounded'/b.VARIANT/'development-scores.json')
            self.assertEqual(len(scores),len(entries))
            for policy in b.a.POLICIES:
                metrics=result['policies'][policy]
                self.assertEqual(metrics['all']['sample_metrics']['count'],len(entries))
                self.assertEqual(metrics['excluding_cluster']['sample_metrics']['count'],len(entries)-76)
                for control in b.CONTROLS:
                    paired=result['paired_vs_controls'][control][policy]['all']['overall']
                    cm=result['controls'][control][policy]['overall'];new=metrics['all']['sample_metrics']
                    self.assertEqual(new['fn'],cm['fn']-paired['malware']['rescued']+paired['malware']['regressed'])
                    self.assertEqual(new['fp'],cm['fp']-paired['benign']['rescued']+paired['benign']['regressed'])
            payload=b.g.f.read(root/'bounded'/b.VARIANT/'fold-00-model.json')
            payload['coefficients'][0]=.9
            rows=[entries[k]['record'] for k in sorted(entries)];X=b.p.matrices(entries,NAMES)['structural_66'][0]
            with self.assertRaisesRegex(ValueError,'exceeds bound'):b.exported_scores(payload,X,rows)


if __name__=='__main__':unittest.main()
