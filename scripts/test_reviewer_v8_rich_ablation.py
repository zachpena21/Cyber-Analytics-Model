#!/usr/bin/env python3
"""Synthetic checks of rich schemas, grouping, integrity, splits and exports."""
import copy
from collections import Counter
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_rich_ablation as r
from test_reviewer_v8_grouped_experiment import NAMES, pool
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_rich_features import pe


def extras(entries):
    result = {}
    for sha,e in entries.items():
        feature = r.rich.extract(bytes(pe()),e['libraries'])
        feature.update(raw_sha256=sha,byte_size=1024,location='synthetic-fixture')
        result[sha] = feature
    return result


class RichAblationTests(unittest.TestCase):
    def test_failed_software_diversity_is_explained_for_every_choice(self):
        entries = software_pool()
        for n,e in enumerate(entries.values()):
            if e['record']['label']==0:
                e['provenance'] = dict(provenance=dict(package='only-two-'+str(n%2)))
        features = extras(entries)
        groups = r.matched_groups(entries,NAMES,features,'template')
        rows = [entries[k]['record'] for k in sorted(entries)]
        fold_ids = r.g.group_folds(rows,groups,5)
        audit = r.split_diversity_audit(entries,NAMES,groups,fold_ids)
        self.assertEqual(len(audit['candidates']),30)
        self.assertEqual(audit['held_folds_without_qualifying_choice'],[0,1,2,3,4])
        for choice in audit['candidates']:
            self.assertFalse(choice['eligible'])
            self.assertIn('calibration_software_diversity',choice['blocking_requirements'])
        with tempfile.TemporaryDirectory() as tmp,patch.object(r,'make_plan') as make,patch.object(r,'panel') as train:
            make.side_effect = [ValueError('blocked'),({},[])]
            plans,summary = r.preflight(entries,NAMES,features,['provenance','template'],Path(tmp))
            self.assertEqual(make.call_count,2)
            self.assertFalse(summary['all_panels_qualify'])
            self.assertTrue(summary['complete'])
            self.assertEqual(set(plans),{'template'})
            self.assertEqual(summary['modes']['provenance']['error'],'blocked')
            train.assert_not_called()

    def test_schemas_remove_scores_and_add_only_requested_block(self):
        entries = pool(groups=2,size=2)
        features = extras(entries)
        matrices = r.matrices(entries,NAMES,features)
        self.assertEqual([matrices[v][0].shape[1] for v in r.VARIANTS],[66,83,90,75,116])
        for variant,(X,schema) in matrices.items():
            self.assertFalse(set(r.g.f.w.SCORE_FEATURES) & set(schema))
            expected = [n for block in r.ADDITIONS[variant] for n in r.rich.BLOCKS[block]]
            self.assertEqual(schema[66:],expected)
            np.testing.assert_array_equal(X[:,:66],matrices['structural_control'][0])
        changed = copy.deepcopy(entries)
        for e in changed.values():
            e['feature_vector'][:6] = [.123]*6
        for variant,(X,_) in r.matrices(changed,NAMES,features).items():
            np.testing.assert_array_equal(X,matrices[variant][0])

    def test_near_shape_links_ignore_sizes_entropy_source_and_label(self):
        entries = pool(groups=1,size=2)
        keys = sorted(entries)
        entries = {k:copy.deepcopy(entries[keys[0]]) for k in keys[:2]}
        for k,e in entries.items():
            e['record']['sha256'] = k
        first,second = keys[:2]
        entries[second]['record']['label'] = 1-entries[first]['record']['label']
        entries[second]['record']['source'] = 'other-acquisition'
        for name in ('timestamp','byte_size','byte_entropy','virtual_size','sizeof_code','string_urls'):
            entries[second]['feature_vector'][NAMES.index(name)] += 42
        features = extras(entries)
        features[second]['values'][r.rich.FEATURE_NAMES.index('section_entropy_max')] += .4
        features[second]['values'][r.rich.FEATURE_NAMES.index('section_virtual_excess_fraction')] += .1
        self.assertEqual(r.shape_fingerprint(entries[first],NAMES,features[first]),
                         r.shape_fingerprint(entries[second],NAMES,features[second]))
        for mode in r.c.MODES:
            groups = r.matched_groups(entries,NAMES,features,mode)
            self.assertEqual(groups[first],groups[second])
        features[second]['values'][r.rich.FEATURE_NAMES.index('clr_directory_present')] = 1.
        self.assertNotEqual(r.shape_fingerprint(entries[first],NAMES,features[first]),
                            r.shape_fingerprint(entries[second],NAMES,features[second]))

    def test_cache_integrity_coverage_and_parser_binding(self):
        entries = pool(groups=2,size=2)
        features = extras(entries)
        converted = sorted(entries)[:2]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            baseline = dict(complete=True,feature_names=NAMES,samples=entries)
            extra = dict(complete=True,feature_names=list(r.rich.FEATURE_NAMES),
                         blocks={k:list(v) for k,v in r.rich.BLOCKS.items()},samples=copy.deepcopy(features))
            identity = dict(input_sha256={str(Path(m.__file__)):r.cache.digest(m.__file__) for m in (r.rich,r.cache)},
                            baseline_feature_names=NAMES,feature_names=list(r.rich.FEATURE_NAMES),
                            parser_version=r.rich.VERSION,sample_sha256=sorted(entries))
            report = dict(complete=True,sample_count=len(entries),
                          labels=dict(Counter('malware' if e['record']['label'] else 'benign' for e in entries.values())),
                          by_source=dict(Counter(e['record']['source'] for e in entries.values())),
                          parser_status={'parsed':len(entries)},converted_sha256=converted,
                          new_development_samples=2,prior_development_samples=len(entries)-2,
                          required_sha_coverage_complete=True,archive_warning_count=0,training=False,threshold_tuning=False)
            for filename,doc in [('development-input-cache.json',baseline),('rich-feature-cache.json',extra),
                                 ('collection-inputs.json',identity),('rich-feature-summary.json',report),
                                 ('excluded-sha256.json',sorted(entries)),('archive-read-warnings.json',[])]:
                r.cache.dump(output/filename,doc)
            actual,hashes = r.validate_cache(output,entries,NAMES,converted)
            self.assertEqual(actual,features)
            self.assertIn(str(output/'rich-feature-cache.json'),hashes)
            extra['samples'].pop(sorted(entries)[0])
            r.cache.dump(output/'rich-feature-cache.json',extra)
            with self.assertRaisesRegex(ValueError,'SHA coverage'):
                r.validate_cache(output,entries,NAMES,converted)
            extra['samples'] = features
            r.cache.dump(output/'rich-feature-cache.json',extra)
            identity['input_sha256'].pop(str(Path(r.rich.__file__)))
            r.cache.dump(output/'collection-inputs.json',identity)
            with self.assertRaisesRegex(ValueError,'binding missing'):
                r.validate_cache(output,entries,NAMES,converted)

    def test_shared_splits_fit_calibration_isolation_and_export_coverage(self):
        entries = software_pool()
        features = extras(entries)
        config = dict(n_estimators=6,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(r.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            output = Path(tmp)
            groups,plan = r.make_plan(entries,NAMES,features,'provenance',output)
            template_groups,template_plan = r.make_plan(entries,NAMES,features,'template',output/'template-preflight')
            self.assertEqual(len(template_plan),5)
            self.assertEqual(sum(len(f['held']) for f in template_plan),len(entries))
            self.assertEqual(set(template_groups),set(entries))
            rows = [entries[k]['record'] for k in sorted(entries)]
            expected_fit = [frozenset(rows[i]['sha256'] for i in f['fit']) for f in plan]
            expected_cal = [frozenset(rows[i]['sha256'] for i in f['calibration']) for f in plan]
            fit_seen,cal_seen = [],[]
            fit_original,cal_original = r.g.fit_model,r.s.software_calibration
            def fit(X,selected_rows):
                fit_seen.append(frozenset(row['sha256'] for row in selected_rows))
                return fit_original(X,selected_rows)
            def calibrate(selected_rows,scores,selected_entries):
                cal_seen.append(frozenset(row['sha256'] for row in selected_rows))
                return cal_original(selected_rows,scores,selected_entries)
            with patch.object(r.g,'fit_model',side_effect=fit),patch.object(r.s,'software_calibration',side_effect=calibrate):
                result = r.panel(entries,NAMES,features,sorted(entries)[:20],output,'provenance',groups,plan)
            self.assertTrue(result['complete'])
            self.assertEqual(fit_seen,expected_fit*5)
            self.assertEqual(cal_seen,expected_cal*5)
            for variant in r.VARIANTS:
                records = r.cache.read(output/variant/'development-scores.json')
                self.assertEqual(len(records),len(entries))
                self.assertEqual({row['sha256'] for row in records},set(entries))
                model = r.cache.read(output/variant/'fold-00-model.json')
                self.assertFalse(model['runtime_supported'])
                for fold in result['variants'][variant]['folds']:
                    self.assertLessEqual(fold['export_parity'],1e-10)
                for policy in r.POLICIES:
                    for field in ('count','benign','malicious','fp','fn'):
                        pooled = result['variants'][variant]['pooled'][policy]['sample_metrics'][field]
                        self.assertEqual(sum(f['held'][policy]['sample_metrics'][field]
                                             for f in result['variants'][variant]['folds']),pooled)
            for comparison in result['paired_vs_control'].values():
                for counts in comparison['software']['overall'].values():
                    self.assertLessEqual(counts['rescued']+counts['regressed'],counts['count'])


if __name__ == '__main__':
    unittest.main()
