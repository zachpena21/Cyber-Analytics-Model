#!/usr/bin/env python3
"""Synthetic PE metadata, acquisition and historical-overlap checks."""
import copy
import json
import os
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import reviewer_v8_pe_metadata as m
import collect_reviewer_v8_targeted_benign as c
from test_reviewer_v8_rich_features import pe


def block(key,value='',children=()):
    text=(key+'\0').encode('utf-16-le');raw=(value+'\0').encode('utf-16-le') if value else b''
    data=bytearray(struct.pack('<HHH',0,len(raw)//2,1)+text)
    data.extend(b'\0'*((-len(data))%4));data.extend(raw);data.extend(b'\0'*((-len(data))%4))
    for child in children:data.extend(child);data.extend(b'\0'*((-len(data))%4))
    struct.pack_into('<H',data,0,len(data));return data


def version_pe():
    data=pe();data.extend(b'\0'*1536);table=152+224
    struct.pack_into('<IIII',data,table+8,2048,0x1000,2048,512);data[512:]=b'\0'*2048
    blob=block('VS_VERSION_INFO',children=[block('StringFileInfo',children=[block('040904b0',children=[block('ProductName','Fixture Product'),block('OriginalFilename','fixture.exe')])])])
    struct.pack_into('<II',data,152+96+2*8,0x1000,2048)
    for offset,name,target in [(0,16,0x80000020),(32,1,0x80000040),(64,1033,96)]:
        struct.pack_into('<H',data,512+offset+14,1);struct.pack_into('<II',data,512+offset+16,name,target)
    struct.pack_into('<IIII',data,512+96,0x1100,len(blob),0,0);data[768:768+len(blob)]=blob
    struct.pack_into('<II',data,152+96+8,0x1500,40)
    struct.pack_into('<IIIII',data,512+1280,0,0,0,0x1600,0)
    data[512+1536:512+1536+13]=b'KERNEL32.dll\0'
    return data


class TargetedTests(unittest.TestCase):
    def test_version_strings_and_imports_are_static_unverified_claims(self):
        result=m.extract(version_pe())
        self.assertTrue(result['valid_pe']);self.assertTrue(result['imports_complete'])
        self.assertEqual(result['imports'],['kernel32.dll'])
        self.assertEqual(result['version_strings']['ProductName'],['Fixture Product'])
        self.assertEqual(result['version_strings']['OriginalFilename'],['fixture.exe'])
        self.assertFalse(result['signature_verified']);self.assertFalse(result['warnings'])
        self.assertTrue(m.extract(pe(managed=True))['clr_metadata_valid'])
        self.assertTrue(m.extract(pe(plus=True,managed=True))['clr_metadata_valid'])

    def test_malformed_resources_and_imports_fail_closed_for_targeting(self):
        data=version_pe();struct.pack_into('<I',data,512+1280+12,0xFFFFFFF0)
        result=m.extract(data);self.assertFalse(result['imports_complete']);self.assertIsNone(c.category(result))
        data=version_pe();struct.pack_into('<I',data,512+16+4,0x80000000)
        self.assertTrue(any('cycle' in x for x in m.extract(data)['warnings']))
        for data in (b'',b'MZ',bytes(64),b'MZ'+bytes(100)):
            self.assertFalse(m.extract(data)['valid_pe'])

    def test_collection_preserves_cohorts_and_inventory_excludes_known_sha(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);installed=root/'installed';out=root/'collection';filtered=root/'inventory'
            a=bytes(pe(managed=True));b=bytearray(a);struct.pack_into('<I',b,136,42);b=bytes(b)
            for product,data in [('Product A',a),('Product B',b)]:
                directory=installed/product;directory.mkdir(parents=True);(directory/'library.dll').write_bytes(data)
            args=SimpleNamespace(scan_root=[installed],output=out,per_pattern_product=10,controls_per_product=3,max_samples=400,max_bytes_mb=500)
            with patch.object(c,'os',SimpleNamespace(name='nt',environ={},walk=os.walk)):
                c.collect(args)
            prior=c.read(out/'collection-summary.json');self.assertEqual(prior['sample_count'],2);self.assertEqual(prior['product_cohorts'],2)
            for artifact in prior['artifacts']:
                with zipfile.ZipFile(out/artifact['path']) as archive:
                    manifest=json.loads(archive.read('collection-manifest.json'))
                    self.assertIn('installed:',manifest['provenance']['package'])
                    self.assertTrue(Path(manifest['samples'][0]['original_path']).exists())
            excluded=root/'excluded.json';c.dump(excluded,[c.digest(a)]);originals={p:c.digest(p.read_bytes()) for p in out.iterdir()}
            c.inventory(SimpleNamespace(collection=out,exclude=excluded,output=filtered))
            summary=c.read(filtered/'targeted-benign-inventory-summary.json')
            self.assertEqual(summary['unique_new_samples'],1);self.assertEqual(summary['historical_overlaps'],1)
            self.assertEqual(summary['by_pattern'],{'tiny_managed':1})
            sources=c.read(filtered/'sources.json');self.assertEqual(len(sources),1);self.assertTrue(sources[0]['development_only'])
            self.assertEqual(originals,{p:c.digest(p.read_bytes()) for p in originals})
            with self.assertRaisesRegex(ValueError,'new or empty'):c.inventory(SimpleNamespace(collection=out,exclude=excluded,output=filtered))

    def test_blocker_metadata_replays_hash_matched_archive_without_execution(self):
        import sys
        import reviewer_v8_blocker_metadata as inspector
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);coverage=root/'coverage';profile=root/'profile';output=root/'metadata';archive_path=root/'original.zip'
            data=bytes(version_pe());sha=c.digest(data)
            with zipfile.ZipFile(archive_path,'w') as archive:archive.writestr('hashed.exe',data)
            original=c.digest(archive_path.read_bytes())
            c.dump(coverage/'inputs.json',dict(profile=str(profile),input_sha256={},original_input_sha256={}))
            c.dump(coverage/'rich-pattern-coverage-summary.json',dict(complete=True,blockers={sha:dict(recorded_original_path=None,label=0,source='fixture')}))
            c.dump(profile/'rich-blocker-profile-summary.json',dict(samples={sha:dict(recovered_location=str(archive_path))}))
            args=SimpleNamespace(root=root,coverage=coverage,output=output)
            with patch.dict(sys.modules,{'pyzipper':SimpleNamespace(AESZipFile=zipfile.ZipFile)}):inspector.run(args)
            summary=c.read(output/'blocker-metadata-summary.json')
            self.assertTrue(summary['all_required_sha_covered']);self.assertEqual(summary['files_with_version_strings'],1)
            self.assertEqual(summary['samples'][sha]['metadata']['version_strings']['ProductName'],['Fixture Product'])
            self.assertEqual(original,c.digest(archive_path.read_bytes()))


if __name__=='__main__':unittest.main()
