"""Inventory tests use synthetic bytes; no PE execution or LIEF dependency."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import reviewer_v8_coverage as c


def sha(value):return hashlib.sha256(value).hexdigest()


class Extractor:
    def __init__(self,bytez):self.bytez=bytez
    def extract(self):
        if b'broken' in self.bytez:raise ValueError('Malformed fixture')
        return dict(libraries='NTOSKRNL.EXE' if b'driver' in self.bytez else 'KERNEL32.dll',
                    imports=1,major_linker_version=2 if b'linker' in self.bytez else 14,
                    symbols=10 if b'linker' in self.bytez else 0,has_debug=0,has_tls=1)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.pyzipper=patch.dict(sys.modules,{'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)})
        self.pyzipper.start()
    def tearDown(self):self.pyzipper.stop();self.temp.cleanup()
    def archive(self,name,items):
        path=self.root/name
        with zipfile.ZipFile(path,'w') as z:
            for member,data in items:z.writestr(member,data)
        return path
    def test_known_reserved_duplicate_and_category_inventory(self):
        driver,linker,known,reserved=b'MZdriver',b'MZlinker',b'MZold',b'MZreserved'
        path=self.archive('benign.zip',[('driver.sys',driver),('copy.sys',driver),('linker.dll',linker),('old.exe',known),('reserved.exe',reserved)])
        result=c.inspect_inputs([(0,path)],{sha(known):0},'dev','development',{sha(reserved):0},Extractor)
        self.assertTrue(result['complete']);self.assertEqual(result['counts']['unused_pe'],2)
        self.assertEqual(result['counts']['duplicate_input'],1)
        self.assertEqual(result['counts']['previously_recorded'],1)
        self.assertEqual(result['counts']['reserved_in_other_manifest'],1)
        self.assertEqual(result['category_counts']['kernel_driver_import']['benign'],1)
        self.assertEqual(result['category_counts']['linker2_symbols_no_debug_tls']['benign'],1)
        self.assertTrue(all(r['selected_for_development'] for r in result['samples']))
        evaluation=c.inspect_inputs([(0,path)],{},'independent','evaluation',extractor=Extractor)
        self.assertTrue(all(r['reserved_for_evaluation'] and not r['selected_for_development'] for r in evaluation['samples']))
        self.assertEqual(len(evaluation['samples']),4) # Evaluation retains other-category samples too.
    def test_class_conflicts_fail_and_parser_failures_are_incomplete(self):
        path=self.archive('one.zip',[('a',b'MZdriver')])
        with self.assertRaisesRegex(ValueError,'Known/input class conflict'):
            c.inspect_inputs([(0,path)],{sha(b'MZdriver'):1},'dev','development',extractor=Extractor)
        with self.assertRaisesRegex(ValueError,'Input class conflict'):
            c.inspect_inputs([(0,path),(1,path)],{},'dev','development',extractor=Extractor)
        broken=self.archive('broken.zip',[('bad',b'MZbroken')])
        result=c.inspect_inputs([(1,broken)],{},'dev','development',extractor=Extractor)
        self.assertFalse(result['complete']);self.assertEqual(len(result['parse_errors']),1)
    def test_archive_failures_are_not_clean_results(self):
        path=self.archive('unreadable.zip',[('bad',b'MZdriver')])
        with patch.object(zipfile.ZipFile,'read',side_effect=RuntimeError('Bad magic number')):
            result=c.inspect_inputs([(0,path)],{},'dev','development',extractor=Extractor)
        self.assertFalse(result['complete']);self.assertEqual(len(result['archive_warnings']),1)
    def test_exclusion_source_and_collection_role_guards(self):
        manifest=self.root/'manifest.json'
        manifest.write_text(json.dumps(dict(source_id='dev',samples=[dict(sha256=sha(b'MZold'),label=0)])))
        with self.assertRaisesRegex(ValueError,'Acquisition source already used'):
            c.load_exclusions([manifest],'dev')
        self.assertEqual(c.load_exclusions([manifest],'different'),{sha(b'MZold'):0})
        collected=self.archive('collected.zip',[('collection-manifest.json',json.dumps(dict(source_id='dev',role='development',samples=[dict(label=0)])))])
        with self.assertRaisesRegex(ValueError,'source-id/role differs'):
            c.collection_provenance([(0,collected)],'other','development')
        with self.assertRaisesRegex(ValueError,'manifest label differs'):
            c.collection_provenance([(1,collected)],'dev','development')
    def test_other_recorded_scores_excluded_and_conflicts_fail(self):
        old=sha(b'MZold');extra=sha(b'MZextra')
        path=self.root/'other.csv';path.write_text(f'sha256,label\n{extra},1\n')
        with patch.object(c.w,'load_audit',return_value=([dict(sha256=old,label=0)],{})),patch.object(c.w,'merge_training',return_value=([dict(sha256=old,label=0)],{})):
            labels,_=c.known_samples(self.root)
            self.assertEqual(labels,{old:0,extra:1})
            path.write_text(f'sha256,label\n{old},1\n')
            with self.assertRaisesRegex(ValueError,'Conflicting recorded label'):
                c.known_samples(self.root)


if __name__=='__main__':unittest.main()
