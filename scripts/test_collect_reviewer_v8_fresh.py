"""Fresh collection provenance, hashes, PE validation and deterministic selection."""
from argparse import Namespace
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import collect_reviewer_v8_fresh as c


def pe(marker=b'x'):
    data=bytearray(128);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,64);data[64:68]=b'PE\0\0'
    return bytes(data)+marker


def archive(entries):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        for name,data in entries:z.writestr(name,data)
    return stream.getvalue()


class CollectionTests(unittest.TestCase):
    def test_windows_stable_minor_version_selection(self):
        def file(version,abi='cp312',platform='win_amd64',yanked=False):
            return dict(filename=f'pkg-{version}-{abi}-{abi}-{platform}.whl',yanked=yanked)
        releases={'1.0.1':[file('1.0.1')],'1.0.2':[file('1.0.2')],
                  '1.1.0':[file('1.1.0')],'2.0.0rc1':[file('2.0.0rc1')],
                  '2.0.0':[file('2.0.0',platform='manylinux')],'1.2.0':[file('1.2.0',yanked=True)]}
        selected=c.choose_wheels(dict(releases=releases),['cp312'],2)
        self.assertEqual([version for version,_ in selected],['1.1.0','1.0.2'])

    def test_wheels_filter_hashes_duplicate_and_mz_only(self):
        old,new=pe(b'old'),pe(b'new')
        content=archive([('old.pyd',old),('new.pyd',new),('copy.dll',new),('fake.exe',b'MZfake'),('code.py',new)])
        rows,overlaps,oversize=c.wheel_samples(content,{c.sha(old)})
        self.assertEqual(len(rows),1);self.assertEqual(rows[0][2],c.sha(new))
        self.assertEqual(overlaps,[c.sha(old)]);self.assertEqual(oversize,0)

    def test_malware_freshness_exclusion_and_requested_hash(self):
        payload=pe();digest=c.sha(payload);since=datetime.now(timezone.utc)-timedelta(days=7)
        entry=dict(sha256_hash=digest,file_type='exe',file_size=len(payload),first_seen=c.now())
        self.assertTrue(c.eligible_malware(entry,set(),since))
        self.assertFalse(c.eligible_malware(entry,{digest},since))
        self.assertFalse(c.eligible_malware(dict(entry,first_seen='2001-01-01 00:00:00'),set(),since))
        self.assertEqual(c.verify_malware(archive([('one.exe',payload)]),digest,zipfile.ZipFile)['byte_size'],len(payload))
        with self.assertRaisesRegex(ValueError,'additional PE|requested SHA'):
            c.verify_malware(archive([('one.exe',payload)]),'a'*64,zipfile.ZipFile)

    def test_collectors_and_generated_sources_end_to_end(self):
        benign,mal=pe(b'benign'),pe(b'malware');wheel=archive([('pkg/core.pyd',benign)])
        wheelentry=dict(filename='scipy-1.0.0-cp312-cp312-win_amd64.whl',url='https://files.pythonhosted.org/example',
                        size=len(wheel),digests=dict(sha256=c.sha(wheel)),yanked=False)
        malentry=dict(sha256_hash=c.sha(mal),file_type='exe',file_size=len(mal),first_seen=c.now(),signature='TestFamily')
        malzip=archive([('one.exe',mal)])
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        modules={'requests':types.SimpleNamespace(Session=Session,HTTPError=type('HTTPError',(Exception,),{})),
                 'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)}
        def downloaded(session,url,limit,headers=None,data=None):
            if data and data['query']=='get_file_type':return json.dumps(dict(query_status='ok',data=[malentry])).encode()
            if data and data['query']=='get_file':return malzip
            return wheel
        with tempfile.TemporaryDirectory() as directory:
            args=Namespace(output=Path(directory),packages=['scipy'],abis=['cp312'],versions=1,
                           max_download_mb=1,count=1,days=7,file_types=['exe'])
            with patch.dict(sys.modules,modules),patch.dict(os.environ,{'MALWAREBAZAAR_AUTH_KEY':'test-secret'}),\
                 patch.object(c,'pypi_json',return_value=dict(releases={'1.0.0':[wheelentry]})),\
                 patch.object(c,'download',side_effect=downloaded),patch.object(c.time,'sleep'),patch('builtins.print'):
                c.benign(args,set(),'freeze');c.malware(args,set(),'freeze');c.sources(args,'freeze')
                args.resume=True
                with patch.object(c,'download',side_effect=AssertionError('Resume should not redownload')):
                    c.malware(args,set(),'freeze')
            sources=c.f.read(args.output/'sources.json')
            self.assertEqual({r['label'] for r in sources},{0,1})
            self.assertEqual(c.f.read(args.output/'malware/collection-summary.json')['signature_counts'],{'TestFamily':1})
            rows,audit=c.f.scan_sources(args.output/'sources.json',set(),zipfile.ZipFile)
            self.assertEqual(len(rows),2);self.assertFalse(audit['archive_warnings'])
            self.assertNotIn('test-secret',(args.output/'malware/collection-summary.json').read_text())
            Path(sources[0]['path']).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'archive changed'):c.sources(args,'freeze')

    def test_network_retry_discards_partial_stream_and_honors_timeout(self):
        class Response:
            def __init__(self,broken):self.broken=broken
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def raise_for_status(self):pass
            def iter_content(self,*args):
                yield b'prefix'
                if self.broken:raise TimeoutError('read stalled')
                yield b'done'
        responses=iter([Response(True),Response(False)]);calls=[]
        def get(*args,**kwargs):calls.append(kwargs);return next(responses)
        errors=types.SimpleNamespace(Timeout=TimeoutError,ConnectionError=ConnectionError,
                                     HTTPError=type('HTTPError',(Exception,),{}))
        with patch.dict(sys.modules,{'requests':errors}),patch.object(c.time,'sleep') as sleep,patch('builtins.print'):
            value=c.download(types.SimpleNamespace(get=get),'https://test',100)
        self.assertEqual(value,b'prefixdone');self.assertEqual(len(calls),2)
        self.assertEqual(calls[0]['timeout'],(20.,180.));sleep.assert_called_once_with(5)

    def test_timeout_checkpoint_resume_moves_past_failed_sha(self):
        payloads=[pe(str(i).encode()) for i in range(3)]
        entries=[dict(sha256_hash=c.sha(p),file_type='exe',file_size=len(p),first_seen=c.now()) for p in payloads]
        order=sorted((e['sha256_hash'] for e in entries),key=lambda s:c.sha(('704:'+s).encode()))
        payload_by_sha={c.sha(p):p for p in payloads};calls=[]
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        modules={'requests':types.SimpleNamespace(Session=Session,Timeout=TimeoutError,ConnectionError=ConnectionError,
                   HTTPError=type('HTTPError',(Exception,),{})),
                 'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)}
        def downloaded(session,url,limit,headers=None,data=None):
            if data['query']=='get_file_type':return json.dumps(dict(query_status='ok',data=entries)).encode()
            digest=data['sha256_hash'];calls.append(digest)
            if digest==order[0]:raise TimeoutError('timeout')
            return archive([('sample.exe',payload_by_sha[digest])])
        with tempfile.TemporaryDirectory() as directory:
            args=Namespace(output=Path(directory),count=2,days=7,file_types=['exe'],resume=False)
            with patch.dict(sys.modules,modules),patch.dict(os.environ,{'MALWAREBAZAAR_AUTH_KEY':'secret'}),                 patch.object(c,'download',side_effect=downloaded),patch.object(c.time,'sleep'),patch('builtins.print'):
                c.malware(args,set(),'freeze')
                result=c.f.read(args.output/'malware/collection-summary.json')
                self.assertEqual(result['count'],2);self.assertTrue(result['target_met'])
                self.assertIn(order[0],result['attempted_sha256'])
                # Simulate an interrupted batch with no saved success yet: preserve attempts/failure,
                # remove later attempts so resume must advance past the first timed-out sample.
                result['samples']=[];result['complete']=False;result['attempted_sha256']=[order[0]]
                c.f.w.dump(args.output/'malware/collection-summary.json',result)
                args.resume=True;calls.clear();c.malware(args,set(),'freeze')
                self.assertEqual(calls,order[1:])

    def test_download_is_bounded(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def raise_for_status(self):pass
            def iter_content(self,*args):return iter([b'123',b'456'])
        session=types.SimpleNamespace(get=lambda *a,**k:Response())
        errors=types.SimpleNamespace(Timeout=TimeoutError,ConnectionError=ConnectionError,HTTPError=type('HTTPError',(Exception,),{}))
        with patch.dict(sys.modules,{'requests':errors}):
            with self.assertRaisesRegex(ValueError,'byte limit'):c.download(session,'https://test',5)


if __name__=='__main__':unittest.main()
