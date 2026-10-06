#!/usr/bin/env python3
"""Synthetic checks for name recovery, descriptive strata and split coverage."""
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import numpy as np
import reviewer_v8_rich_pattern_coverage as p
from test_reviewer_v8_rich_blocker_profile import payload


class CoverageTests(unittest.TestCase):
    def test_strata_do_not_use_labels_or_filenames(self):
        tiny=dict(clr_metadata_signature_valid=1,byte_size=4096,numberof_sections=3)
        self.assertTrue(p.patterns(tiny,'mscoree.dll')['tiny_managed'])
        self.assertFalse(p.patterns(dict(tiny,byte_size=9000),'mscoree.dll')['tiny_managed'])
        self.assertFalse(p.patterns(tiny,'mscoree.dll kernel32.dll')['tiny_managed'])
        self.assertTrue(p.patterns(dict(tiny,byte_size=212992),'')['managed_no_cached_imports'])
        native=dict(clr_metadata_signature_valid=0,byte_size=14000000,numberof_sections=9)
        self.assertTrue(p.patterns(native,'KERNEL32.dll')['large_sparse_import_native'])
        self.assertFalse(p.patterns(dict(native,clr_metadata_signature_valid=1),'kernel32.dll')['large_sparse_import_native'])

    def test_nested_names_match_exact_bytes_and_unreadable_entries_are_logged(self):
        bytez=b'MZ'+b'synthetic-only';sha=hashlib.sha256(bytez).hexdigest()
        inner=io.BytesIO()
        with zipfile.ZipFile(inner,'w') as z:z.writestr('application/file.exe',bytez)
        with tempfile.TemporaryDirectory() as tmp:
            archive=Path(tmp)/'outer.zip'
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('nested.zip',inner.getvalue());z.writestr('other.exe',b'MZdifferent')
            before=p.cache.digest(archive)
            found,warnings,hashes=p.recover_names([archive],{sha},zipfile.ZipFile)
            self.assertEqual(found[sha][0]['member_chain'],str(archive)+'!/nested.zip!/application/file.exe')
            self.assertEqual(set(found),{sha});self.assertFalse(warnings)
            self.assertEqual(before,p.cache.digest(archive));self.assertEqual(hashes[str(archive.resolve())],before)
        class Entry:
            filename='';file_size=1;compress_type=8
        class Broken:
            def infolist(self):return [Entry()]
            def read(self,*args,**kwargs):raise ValueError('bad header')
        warnings=[]
        self.assertEqual(list(p.named_archive_payloads(Broken(),zipfile.ZipFile,warnings,'fixture')),[])
        self.assertEqual(warnings[0]['member'],'');self.assertEqual(warnings[0]['error'],'ValueError')

    def test_coverage_and_full_run_preserve_split_roles_and_input_files(self):
        schema=['shape','unused'];full_names=schema+['clr_metadata_signature_valid','byte_size','numberof_sections']
        entries={};keys=[];X=[];full=[];features={}
        for i in range(120):
            sha=f'{i:064x}';keys.append(sha);label=i%2
            entries[sha]=dict(record=dict(sha256=sha,label=label,source='fixture',adapter_probability=.8),
                libraries='mscoree.dll' if i%3==0 else 'kernel32.dll' if i%3==1 else '',original_path=f'/fixture/file-{i}.exe')
            vector=[1 if label else 0,i/100];X.append(vector)
            shape=[1,4096,3] if i%3==0 else [0,14000000,9] if i%3==1 else [1,212992,2]
            full.append(vector+shape);features[sha]=dict(byte_size=100,location='unused')
        X=np.asarray(X);full=np.asarray(full);model=payload();groups={k:k for k in keys}
        folds=[];profiles=[]
        for n in range(3):
            roles={role:[k for i,k in enumerate(keys) if i%3==part] for role,part in [('held',n),('calibration',(n+1)%3),('fit',(n+2)%3)]}
            folds.append(dict(fold=n,**roles));rep=next(k for k in roles['calibration'] if entries[k]['record']['label']==0)
            profiles.append(dict(fold=n,selected_threshold=.9,profiles=[dict(representative_sha256=rep,blocker_sha256=[rep])]))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);profile=root/'profile';audit=root/'audit';source=root/'run';panel=source/'template';collection=root/'cache';out=root/'out'
            p.cache.dump(source/'inputs.json',dict(rich_cache=str(collection),input_sha256={},converted_acquisition_sha256=[]))
            p.cache.dump(collection/'development-input-cache.json',dict(samples=entries,feature_names=schema))
            p.cache.dump(panel/'split-manifest.json',dict(groups=groups,folds=folds))
            p.cache.dump(audit/'inputs.json',dict(input_sha256={},original_input_sha256={}))
            p.cache.dump(profile/'inputs.json',dict(audit=str(audit),source_run=str(source),input_sha256={},original_input_sha256={}))
            p.cache.dump(profile/'rich-blocker-profile-summary.json',dict(complete=True,mode='template',held_samples_profiled=False,variants={'plus_imports':profiles}))
            for n in range(3):p.cache.dump(panel/'plus_imports'/f'fold-{n:02d}-model.json',model)
            originals={f:p.cache.digest(f) for f in root.rglob('*.json')}
            args=SimpleNamespace(root=root,profile=profile,variant=['plus_imports'],scan_root=None,output=out)
            # Archive opening is unused when recorded names already exist.
            import sys
            with patch.dict(sys.modules,{'pyzipper':SimpleNamespace(AESZipFile=zipfile.ZipFile)}),patch.object(p.r,'validate_cache',return_value=(features,{})),patch.object(p.r,'matrices',return_value={'plus_imports':(X,schema),'plus_all':(full,full_names)}),patch.object(p.g,'fit_model',side_effect=AssertionError('Must not fit')):
                p.run(args)
            report=p.cache.read(out/'rich-pattern-coverage-summary.json')
            self.assertTrue(report['complete']);self.assertFalse(report['held_samples_analyzed']);self.assertEqual(report['name_recovery_required'],0)
            for f in report['variants']['plus_imports']:
                n=f['fold'];fit=set(folds[n]['fit'])
                for neighbor in f['fit_neighbors']:
                    self.assertIn(neighbor['calibration_representative_sha256'],folds[n]['calibration'])
                    for candidates in neighbor['nearest_original_fit_samples'].values():
                        self.assertTrue({c['sha256'] for c in candidates}<=fit)
                self.assertEqual(sum(v['fit']['count'] for v in f['patterns'].values()),40)
                self.assertEqual(sum(v['calibration']['count'] for v in f['patterns'].values()),40)
            self.assertEqual(originals,{f:p.cache.digest(f) for f in originals})


if __name__=='__main__':unittest.main()
