#!/usr/bin/env python3
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
import check_reviewer_v8_batch_runtime as batch


class BatchTests(unittest.TestCase):
    def test_nested_zip_payloads_and_no_extraction(self):
        nested=io.BytesIO()
        with zipfile.ZipFile(nested,'w') as z:z.writestr('sample.exe',b'MZnested')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'samples.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('readme.txt',b'ordinary text');z.writestr('inner.zip',nested.getvalue());z.writestr('direct.dll',b'MZdirect')
            warnings=[]
            with patch.object(zipfile.ZipFile,'read',lambda self,entry,pwd=None:original(self,entry)):
                results=list(batch.payloads(path,zipfile.ZipFile,warnings))
            self.assertEqual([raw for _,raw in results],[b'MZnested',b'MZdirect'])
            self.assertEqual(warnings,[]);self.assertEqual(list(Path(tmp).iterdir()),[path])

    def test_nested_depth_limit(self):
        with self.assertRaisesRegex(ValueError,'depth'):list(batch.payloads(io.BytesIO(),zipfile.ZipFile,[],9))


original=zipfile.ZipFile.read
if __name__=='__main__':unittest.main()
