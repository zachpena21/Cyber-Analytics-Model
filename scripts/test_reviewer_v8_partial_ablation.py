"""Partial feature isolation, matched control reproduction and paired totals."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_partial_ablation as p
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_grouped_experiment import NAMES


class PartialAblationTests(unittest.TestCase):
    def test_partial_schemas_retain_signatures_and_remove_only_named_features(self):
        entries=software_pool();data=p.matrices(entries,NAMES)
        for variant,count in zip(p.VARIANTS,(72,66,71,69)):
            X,names=data[variant];self.assertEqual(X.shape[1],count)
            self.assertEqual(set(data['full_72'][1])-set(names),set(p.REMOVE[variant]))
        for variant in ('without_adapter_71','without_base_69'):
            self.assertIn('signature_checked',data[variant][1]);self.assertIn('signature_verified',data[variant][1])
        changed=copy.deepcopy(entries)
        for e in changed.values():e['feature_vector'][NAMES.index('adapter_probability')]=.123
        other=p.matrices(changed,NAMES)
        np.testing.assert_array_equal(data['without_adapter_71'][0],other['without_adapter_71'][0])
        self.assertFalse(np.array_equal(data['without_base_69'][0],other['without_base_69'][0]))

    def test_two_controls_reproduce_and_every_variant_has_matched_coverage(self):
        entries=software_pool();config=dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory,patch.dict(p.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(directory);software=root/'software';previous=root/'ablation'
            for mode in p.c.MODES:
                p.s.control(entries,NAMES,software/mode,mode)
                p.a.experiment_panel(entries,NAMES,software,previous/mode,mode)
                result=p.experiment_panel(entries,NAMES,previous,software,root/'partial'/mode,mode)
                self.assertTrue(result['complete']);self.assertEqual(result['control_max_score_error'],{'full_72':0.,'structural_66':0.})
                self.assertEqual(p.g.f.read(root/'partial'/mode/'split-manifest.json'),p.g.f.read(previous/mode/'split-manifest.json'))
                for variant,v in result['variants'].items():
                    records=p.g.f.read(root/'partial'/mode/variant/'development-scores.json')
                    self.assertEqual(len(records),len(entries));self.assertEqual({r['sha256'] for r in records},set(entries))
                    for fold in v['folds']:self.assertLess(fold['export_parity'],1e-10)
                for baseline,target in [('full_72','paired_vs_full'),('structural_66','paired_vs_structural')]:
                    for variant,policies in result[target].items():
                        for policy,paired in policies.items():
                            for label,metric in [('benign','fp'),('malware','fn')]:
                                b=result['variants'][baseline]['pooled'][policy]['overall'][metric]
                                v=result['variants'][variant]['pooled'][policy]['overall'][metric]
                                self.assertEqual(b-v,paired['overall'][label]['rescued']-paired['overall'][label]['regressed'])
            records=p.g.f.read(previous/'provenance/structural_66/development-scores.json');records[0]['reviewer_score']+=.1
            p.g.f.w.dump(previous/'provenance/structural_66/development-scores.json',records)
            with self.assertRaisesRegex(ValueError,'structural_66 reproduction'):
                p.experiment_panel(entries,NAMES,previous,software,root/'bad','provenance')
            self.assertFalse((root/'bad/without_adapter_71').exists())

    def test_discovery_ignores_incomplete_ablation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);complete=root/'reviewer-v8-score-ablation-development-1';incomplete=root/'reviewer-v8-score-ablation-development-2'
            p.g.f.w.dump(complete/'ablation-comparison-summary.json',{'complete':True})
            p.g.f.w.dump(incomplete/'ablation-comparison-summary.json',{'complete':False})
            self.assertEqual(p.find_previous(root),complete)


if __name__=='__main__':unittest.main()
