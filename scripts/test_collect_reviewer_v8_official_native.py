#!/usr/bin/env python3
"""Official collection bounds, overlap filtering, checksums, provenance and resume."""
import io
from pathlib import Path
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import collect_reviewer_v8_official_native as c
from test_reviewer_v8_rich_features import pe


def sample(marker=0):
    raw=pe(plus=True);struct.pack_into('<H',raw,132,0x8664)
    raw.extend(bytes(10*1024*1024-len(raw)));raw[-1]=marker
    return bytes(raw)


def info(data):
    return dict(valid_pe=True,imports_complete=True,clr_metadata_valid=False,machine=0x8664,
        byte_size=len(data),section_count=9,imports=['kernel32.dll'])


class OfficialTests(unittest.TestCase):
    def test_static_pattern_bounds_and_published_checksum(self):
        x=info(bytes(10*1024*1024));self.assertEqual(c.pattern(x),'large_native')
        x['section_count']=6;self.assertEqual(c.pattern(x),'large_native_adjacent')
        x['clr_metadata_valid']=True;self.assertIsNone(c.pattern(x))
        x['clr_metadata_valid']=False;x['machine']=0x14c;self.assertIsNone(c.pattern(x))
        sha='a'*64;self.assertEqual(c.published_checksum(sha+'  archive.zip\n','archive.zip'),sha)
        self.assertIsNone(c.published_checksum(sha+'  other.zip\n','archive.zip'))
        with self.assertRaises(ValueError):c.checked_url('https://unrelated.example/archive.zip')

    def test_discovery_freezes_official_checksums_and_patch_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);meta=root/'metadata.json';c.dump(meta,{'fixture':True})
            files=lambda version:[dict(os='windows',arch='amd64',kind='archive',filename=version+'.windows-amd64.zip',size=100,sha256='a'*64)]
            go=[dict(version='go1.23.1',files=files('go1.23.1')),dict(version='go1.23.12',files=files('go1.23.12'))]
            release=dict(draft=False,prerelease=False,assets=[dict(name='gh_2.0.0_windows_amd64.zip',size=100,digest='sha256:'+'b'*64,
                browser_download_url='https://github.com/cli/cli/releases/download/v2.0.0/gh_2.0.0_windows_amd64.zip')])
            def metadata(url,output):return (go if url.startswith('https://go.dev') else release),meta
            with patch.object(c,'metadata',side_effect=metadata),patch.object(c,'GO_MINORS',('1.23',)),patch.object(c,'CATALOG',(('cli/cli','v2.0.0'),)):
                plan=c.discover(root)
                self.assertEqual(len(plan['assets']),2);self.assertEqual(plan['assets'][0]['version'],'go1.23.12')
                self.assertEqual(plan['assets'][1]['sha256'],'b'*64)
                release['assets'][0]['browser_download_url']='https://github.com/unrelated/project/releases/download/v2.0.0/archive.zip'
                with self.assertRaisesRegex(ValueError,'outside official release'):c.discover(root)

    def test_zip_tar_bounds_and_no_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);raw=sample();z=root/'archive.zip';tar=root/'archive.tar.gz'
            with zipfile.ZipFile(z,'w',compression=zipfile.ZIP_DEFLATED) as archive:archive.writestr('../../outside.exe',raw)
            with tarfile.open(tar,'w:gz') as archive:
                entry=tarfile.TarInfo('../../outside.exe');entry.size=len(raw);archive.addfile(entry,io.BytesIO(raw))
                link=tarfile.TarInfo('link.exe');link.type=tarfile.SYMTYPE;link.linkname='/outside';archive.addfile(link)
            self.assertEqual(list(c.members(z)),[('../../outside.exe',raw)])
            self.assertEqual(list(c.members(tar)),[('../../outside.exe',raw)])
            self.assertFalse((root/'outside.exe').exists())
            with patch.object(c,'MAX_UNPACKED',100),self.assertRaisesRegex(ValueError,'expansion bound'):list(c.members(z))

    def test_download_rejects_bad_checksum_and_reuses_completed_asset(self):
        class Response:
            url='https://github.com/cli/cli/releases/download/v1.14.0/archive.zip';headers={}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def geturl(self):return self.url
            def read(self,size):
                if getattr(self,'done',False):return b''
                self.done=True;return b'payload'
        with tempfile.TemporaryDirectory() as tmp,patch.object(c,'urlopen',side_effect=lambda *args,**kwargs:Response()) as get:
            path=Path(tmp)/'asset.zip'
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):c.download(Response.url,path,100,'a'*64)
            self.assertFalse(path.exists());c.download(Response.url,path,100,c.digest(b'payload'))
            before=get.call_count;c.download(Response.url,path,100,c.digest(b'payload'));self.assertEqual(get.call_count,before)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'Saved download changed'):c.download(Response.url,path,100,c.digest(b'payload'))

    def test_collection_filters_before_quota_preserves_release_cohort_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp,patch('builtins.print'),patch.object(c.pe,'extract',side_effect=info):
            root=Path(tmp);source=root/'source.zip';old=sample(1);new=sample(2)
            with zipfile.ZipFile(source,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('old.exe',old);archive.writestr('new.exe',new);archive.writestr('duplicate.exe',new)
            excluded=root/'prior/excluded-sha256.json';c.dump(excluded,[c.digest(old)])
            asset=dict(package='Go',version='go1.23.12',filename='archive.zip',size=source.stat().st_size,
                url='https://go.dev/dl/archive.zip',sha256=c.file_hash(source),checksum_basis='Fixture published checksum')
            args=SimpleNamespace(root=root,exclude=[excluded],output=root/'collection',resume=None,max_download_mb=100,per_asset=1)
            plan=dict(assets=[asset],warnings=[],metadata_sha256={})
            def transfer(url,path,limit,expected):
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(source.read_bytes());return path
            with patch.object(c,'discover',return_value=plan),patch.object(c,'download',side_effect=transfer):c.run(args)
            result=c.read(args.output/'official-native-collection-summary.json')
            self.assertTrue(result['complete']);self.assertEqual(result['unique_new_samples'],1);self.assertEqual(result['historical_overlaps'],1)
            self.assertEqual(result['by_pattern'],{'large_native':1});self.assertEqual(result['distinct_projects'],1)
            artifact=result['artifacts'][0]
            with zipfile.ZipFile(artifact['path']) as archive:
                manifest=c.json.loads(archive.read('collection-manifest.json'))
                self.assertEqual(manifest['provenance']['package'],'Go');self.assertEqual(manifest['provenance']['release_version'],'go1.23.12')
                self.assertEqual(manifest['samples'][0]['sha256'],c.digest(new))
            # Validate interoperability with the existing Docker feature collector.
            import reviewer_v8_targeted_feature_cache as target
            samples,bindings=target.inventory_samples(args.output,excluded);self.assertEqual(set(samples),{c.digest(new)})
            before={str(p):c.file_hash(p) for p in args.output.rglob('*') if p.is_file()}
            args.resume=args.output
            with patch.object(c,'download',side_effect=AssertionError('Completed resume is offline')):c.run(args)
            self.assertEqual(before,{str(p):c.file_hash(p) for p in args.output.rglob('*') if p.is_file()})
            Path(artifact['path']).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'Input changed'):c.run(args)

    def test_failed_asset_can_resume_without_refetching_catalog(self):
        with tempfile.TemporaryDirectory() as tmp,patch('builtins.print'):
            root=Path(tmp);exclude=root/'excluded-sha256.json';c.dump(exclude,[])
            asset=dict(package='Go',version='go1.23.12',filename='archive.zip',size=10,url='https://go.dev/dl/archive.zip',sha256='a'*64,checksum_basis='fixture')
            args=SimpleNamespace(root=root,exclude=[exclude],output=root/'collection',resume=None,max_download_mb=100,per_asset=1)
            with patch.object(c,'discover',return_value=dict(assets=[asset],warnings=[],metadata_sha256={})),patch.object(c,'download',side_effect=c.URLError('timeout')),self.assertRaisesRegex(ValueError,'Some assets failed'):c.run(args)
            self.assertFalse(c.read(args.output/'official-native-collection-summary.json')['complete'])
            args.resume=args.output
            with patch.object(c,'discover',side_effect=AssertionError('Frozen catalog must be reused')),patch.object(c,'download',side_effect=c.URLError('timeout')),self.assertRaisesRegex(ValueError,'Some assets failed'):c.run(args)


if __name__=='__main__':unittest.main()
