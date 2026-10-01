"""Threshold-only freezing, SHA exclusions and strict fresh-acquisition validation."""
import hashlib
import json
from pathlib import Path
import sys
import types
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import reviewer_v8_fresh_validation as f
from test_reviewer_v8_coverage_compare import specification, runtime, details, info


class FreshValidationTests(unittest.TestCase):
    def bundle(self,root):
        paths=['v7.json','expanded.json','fixed.json']
        ps=[specification(),specification(8,.3181019231722836),specification(8,f.FIXED_THRESHOLD)]
        models={}
        for name,path,p in zip(f.c.NAMES,paths,ps):
            f.w.dump(root/path,p);models[name]=dict(path=path,sha256=f.t.digest(root/path))
        f.w.dump(root/'excluded.json',['a'*64])
        f.w.dump(root/'freeze-manifest.json',dict(complete=True,threshold_tuning=False,models=models,
            exclusions=dict(path='excluded.json',sha256=f.t.digest(root/'excluded.json'),count=1),scope='test'))
        return ps

    def test_frozen_policies_share_scores_and_reject_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);ps=self.bundle(root)
            manifest,cs,excluded=f.load_bundle(root)
            self.assertEqual(excluded,{'a'*64})
            sample=dict(sha256='b'*64,label=1,source_id='new',categories=[])
            row=f.c.compare_one(sample,b'MZ',details(sha='b'*64),info(),cs)
            self.assertEqual(row['v8_import_upper_score'],row['v8_import_midpoint_score'])
            self.assertEqual(row['v8_import_upper_prediction'],1)
            self.assertEqual(row['v8_import_midpoint_prediction'],0)
            (root/'fixed.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'hash changed'):f.load_bundle(root)

    def test_prior_csv_shas_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'report.csv').write_text('sha256,label\n'+'a'*64+',0\n')
            excluded,hashes=f.report_exclusions(root)
            self.assertEqual(excluded,{'a'*64});self.assertEqual(len(hashes),1)
            (root/'report.csv').write_text('sha256\nnot-a-hash\n')
            with self.assertRaisesRegex(ValueError,'Invalid SHA'):f.report_exclusions(root)

    def test_new_archives_exclusion_duplicates_and_label_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);old=b'MZold';fresh=b'MZfresh';mal=b'MZmal'
            with zipfile.ZipFile(root/'benign.zip','w') as z:
                z.writestr('old.dll',old);z.writestr('new.dll',fresh);z.writestr('copy.dll',fresh)
            with zipfile.ZipFile(root/'malware.zip','w') as z:z.writestr('one.exe',mal)
            sources=[dict(path='benign.zip',label=0,source_id='new-version',provenance='Trusted installer version X'),
                     dict(path='malware.zip',label=1,source_id='new-acquisition',provenance='New batch date Y')]
            f.w.dump(root/'sources.json',sources)
            excluded={hashlib.sha256(old).hexdigest()}
            rows,audit=f.scan_sources(root/'sources.json',excluded,zipfile.ZipFile)
            self.assertEqual(len(rows),2);self.assertEqual(audit['duplicate_entries'],1)
            self.assertEqual(set(audit['excluded_overlap_sha256']),excluded)
            self.assertEqual({r['label'] for r in rows.values()},{0,1})
            with zipfile.ZipFile(root/'malware.zip','w') as z:z.writestr('bad.exe',fresh)
            with self.assertRaisesRegex(ValueError,'Conflicting fresh labels'):
                f.scan_sources(root/'sources.json',excluded,zipfile.ZipFile)

    def test_complete_evaluation_with_exact_feature_service(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/'bundle';bundle.mkdir();self.bundle(bundle)
            (root/'benign.exe').write_bytes(b'MZbenign');(root/'malware.exe').write_bytes(b'MZmalware')
            f.w.dump(root/'sources.json',[dict(path='benign.exe',label=0,source_id='trusted-new',provenance='version X'),
                                          dict(path='malware.exe',label=1,source_id='new-batch',provenance='date Y')])
            class Response:
                def __init__(self,value):self.value=value
                def raise_for_status(self):pass
                def json(self):return self.value
            class Session:
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def get(self,*args,**kwargs):return Response(info())
                def post(self,*args,**kwargs):
                    return Response(details(sha=hashlib.sha256(kwargs['data']).hexdigest()))
            modules={'requests':types.SimpleNamespace(Session=Session),
                     'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)}
            output=root/'out'
            with patch.dict(sys.modules,modules),patch('builtins.print'):
                f.evaluate(Namespace(output=output,bundle=bundle,sources=root/'sources.json',
                                     service_url='http://test',api_timeout=1))
            summary=f.read(output/'comparison-summary.json')
            self.assertTrue(summary['complete']);self.assertFalse(summary['threshold_tuning'])
            self.assertEqual(summary['sample_count'],2)
            self.assertTrue(f.read(output/'evaluation-manifest.json')['complete'])
            self.assertEqual(summary['v7_service_parity']['max_abs'],0.)
            self.assertEqual(summary['models']['v8_import_midpoint']['label'],'v8_expanded_fixed_06397')

    def test_freeze_complete_candidate_and_reproduction_guard(self):
        from argparse import Namespace
        from test_reviewer_v8_docker_train import DockerTrainTests
        fixture=DockerTrainTests().fixture()
        original,new,cached,groups,samples,candidates=fixture
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);training=root/'training';audit=root/'audit';audit.mkdir()
            for name in ('docker-feature-cache.json','docker-audit-summary.json'):
                f.w.dump(audit/name,{'fixture':True})
            coverage=root/'coverage.json';f.w.dump(coverage,{'fixture':True})
            with patch('builtins.print'):f.t.run_experiment(*fixture,training)
            f.w.dump(training/'inputs.json',dict(docker_cache_sha256=f.t.digest(audit/'docker-feature-cache.json'),
                docker_audit_summary_sha256=f.t.digest(audit/'docker-audit-summary.json'),coverage_sha256=f.t.digest(coverage)))
            args=Namespace(output=root/'bundle',training=training,audit=audit,coverage=coverage,reports=root)
            with patch.object(f.t,'load_data',return_value=fixture),patch('builtins.print'):
                f.freeze(args)
                manifest,cs,excluded=f.load_bundle(args.output)
                self.assertEqual(len(excluded),136)
                self.assertEqual(cs['v8_import_midpoint'][0].threshold,f.FIXED_THRESHOLD)
                scores=f.read(training/'development-scores.json')
                next(r for r in scores if r['model']=='expanded_candidate')['score']+=.1
                f.w.dump(training/'development-scores.json',scores)
                args.output=root/'bad-bundle'
                with self.assertRaisesRegex(ValueError,'does not reproduce'):f.freeze(args)
                self.assertFalse((args.output/'freeze-manifest.json').exists())

    def test_freeze_incomplete_and_dirty_output_stop(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);f.w.dump(root/'training-summary.json',dict(completed=False))
            f.w.dump(root/'inputs.json',{})
            with self.assertRaisesRegex(ValueError,'not completed'):
                f.freeze(Namespace(output=root/'out',training=root))
            (root/'out').mkdir();(root/'out'/'partial').write_text('x')
            with self.assertRaisesRegex(ValueError,'not empty'):f.fresh_output(root/'out')


if __name__=='__main__':unittest.main()
