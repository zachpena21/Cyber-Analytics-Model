"""Datalake listing, PE/SHA filters, complete fallback and cached resume."""
from argparse import Namespace
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import collect_reviewer_v8_batches as b
from test_collect_reviewer_v8_fresh import pe,archive


class BatchTests(unittest.TestCase):
    def test_listing_accepts_only_recent_plain_batch_links(self):
        name=datetime.now(timezone.utc).strftime('%Y-%m-%d-%H.zip')
        html=f'<a href="{name}">batch</a><a href="2001-01-01-01.zip">old</a><a href="https://evil/{name}">evil</a>'
        self.assertEqual(b.batch_names(html,48),[name])

    def test_pe_only_sha_exclusions_and_hash_validation(self):
        old,new=pe(b'old'),pe(b'new');d=b.c.sha(new)
        content=archive([(b.c.sha(old),old),(d,new),('notes.txt',b'not PE')])
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            rows,counts=b.select_members(z,{b.c.sha(old)},10)
        self.assertEqual([r[2] for r in rows],[d]);self.assertEqual(counts['overlap'],1)
        with zipfile.ZipFile(io.BytesIO(archive([('a'*64,new)]))) as z:
            with self.assertRaisesRegex(ValueError,'advertised hash'):b.select_members(z,set(),10)

    def test_complete_fallback_and_resume_with_no_api(self):
        old,new=pe(b'old'),pe(b'new');name=datetime.now(timezone.utc).strftime('%Y-%m-%d-%H.zip')
        data=archive([(b.c.sha(old),old),(b.c.sha(new),new)])
        class AESZipFile(zipfile.ZipFile):
            def __init__(self,*args,**kwargs):kwargs.pop('encryption',None);super().__init__(*args,**kwargs)
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        modules={'requests':types.SimpleNamespace(Session=Session,HTTPError=type('HTTPError',(Exception,),{}),
                   Timeout=TimeoutError,ConnectionError=ConnectionError),
                 'pyzipper':types.SimpleNamespace(AESZipFile=AESZipFile,WZ_AES=99)}
        calls=[]
        def downloaded(session,url,limit,*args,**kwargs):
            calls.append(url)
            return f'<a href="{name}">batch</a>'.encode() if url==b.INDEX else data
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/'bundle';bundle.mkdir();b.f.w.dump(bundle/'freeze-manifest.json',dict(fixture=True))
            freeze=b.f.t.digest(bundle/'freeze-manifest.json')
            benign_path=root/'benign.zip';benign_path.write_bytes(archive([('benign.pyd',pe(b'benign'))]))
            b.f.w.dump(root/'benign/collection-summary.json',dict(complete=True,freeze_manifest_sha256=freeze,
                artifacts=[dict(path=str(benign_path),sha256=b.f.t.digest(benign_path),source_id='benign',provenance='trusted')]))
            args=Namespace(output=root,bundle=bundle,count=1,hours=48,max_download_mb=10,max_batch_mb=10,resume=False)
            with patch.dict(sys.modules,modules),patch.object(b.f,'load_bundle',return_value=({}, {}, {b.c.sha(old)})),\
                 patch.object(b.c,'download',side_effect=downloaded),patch('builtins.print'):
                b.collect(args)
                summary=b.f.read(root/'malware-batches/collection-summary.json')
                self.assertTrue(summary['complete']);self.assertTrue(summary['target_met'])
                self.assertEqual(summary['count'],1);self.assertEqual(summary['samples'][0]['sha256'],b.c.sha(new))
                sources=b.f.read(root/'batch-sources.json');self.assertEqual({r['label'] for r in sources},{0,1})
                rows,audit=b.f.scan_sources(root/'batch-sources.json',set(),AESZipFile)
                self.assertEqual(len(rows),2);self.assertFalse(audit['archive_warnings'])
                calls.clear();args.resume=True;b.collect(args);self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
