"""Completed evaluation reproduction, audit output, and resume provenance guards."""
from argparse import Namespace
import hashlib
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import reviewer_v8_fresh_error_audit as a
from test_reviewer_v8_fresh_validation import FreshValidationTests
from test_reviewer_v8_coverage_compare import details,info


class ErrorAuditTests(unittest.TestCase):
    def test_full_evaluation_audit_and_label_tamper_guard(self):
        class Response:
            def __init__(self,value):self.value=value
            def raise_for_status(self):pass
            def json(self):return self.value
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def get(self,*args,**kwargs):return Response(info())
            def post(self,*args,**kwargs):return Response(details(sha=hashlib.sha256(kwargs['data']).hexdigest()))
        modules={'requests':types.SimpleNamespace(Session=Session),'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/'bundle';bundle.mkdir();FreshValidationTests().bundle(bundle)
            (root/'benign.exe').write_bytes(b'MZbenign');(root/'malware.exe').write_bytes(b'MZmalware')
            sources=root/'sources.json';a.f.w.dump(sources,[dict(path=str(root/'benign.exe'),label=0,source_id='benign',provenance='trusted'),
                                                         dict(path=str(root/'malware.exe'),label=1,source_id='malware',provenance='batch')])
            evaluation=root/'eval';output=root/'audit'
            with patch.dict(sys.modules,modules),patch('builtins.print'):
                a.f.evaluate(Namespace(output=evaluation,bundle=bundle,sources=sources,service_url='http://test',api_timeout=1))
                args=Namespace(bundle=bundle,comparison=evaluation,sources=sources,output=output,resume=False,
                    service_url='http://test',api_timeout=1,training_cache=root/'cache',training_split=root/'split')
                with patch.object(a,'training_references',return_value={}):a.run(args)
                summary=a.f.read(output/'audit-summary.json');audit=a.f.read(output/'error-audit.json')
                self.assertEqual(summary['error_count'],1);self.assertEqual(summary['malware_errors'],1)
                self.assertFalse(summary['training']);self.assertEqual(len(audit['errors'][0]['tree_paths']),3)
                args.resume=True
                with patch.object(a,'training_references',return_value={}):a.run(args)
                cache=a.f.read(output/'docker-feature-cache.json');sha=next(iter(cache['samples']))
                cache['samples'][sha]['record']['label']=1-cache['samples'][sha]['record']['label']
                a.f.w.dump(output/'docker-feature-cache.json',cache)
                with self.assertRaisesRegex(ValueError,'label/source'):a.run(args)


if __name__=='__main__':unittest.main()
