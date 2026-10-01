"""Docker audit guards, cache impact, tree paths, and resumable full workflow."""
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import reviewer_v8_docker_audit as a
from test_reviewer_v8_coverage_compare import specification,runtime,info,details


def candidates():
    return {n:(runtime(p),p) for n,p in zip(a.c.NAMES,[specification(),specification(8),specification(8,.4)])}


class DockerAuditTests(unittest.TestCase):
    def test_structural_and_import_identity_drift(self):
        cs=candidates();sha='a'*64
        row=dict(sha256=sha,label=0,source='reviewer-core-v4',**{k:details()[k] or 0 for k in a.w.SCORE_FEATURES})
        sample=dict(row,source_id=row['source'],categories=[])
        entry=a.service_vector(sample,b'MZ',details(),info(),cs)
        old=list(entry['feature_vector'][6:]);old[0]=1.
        cache={sha:dict(structural_vector=old,attributes={})}
        summary,diffs=a.cache_differences([row],{sha:entry},cache,cs)
        self.assertEqual(summary['samples_with_structural_differences'],1)
        self.assertEqual(len(diffs),1)
        # Equal shared structural values can conceal different import identities.
        cache[sha]['structural_vector']=entry['feature_vector'][6:]
        cache[sha]['attributes']={'libraries':'ntoskrnl.exe'}
        summary,diffs=a.cache_differences([row],{sha:entry},cache,cs)
        self.assertEqual(summary['samples_with_structural_differences'],0)
        self.assertEqual(summary['samples_with_import_indicator_differences'],1)
        self.assertIn(a.c.IMPORT_FEATURES[0],summary['feature_difference_counts'])

    def test_tree_paths_match_float32_runtime(self):
        p=specification(8);p['estimators'][0]=dict(children_left=[1,-1,-1],children_right=[2,-1,-1],
            feature=[1,-2,-2],threshold=[.8,-2.,-2.],raw_value=[0.,-20.,20.])
        model=runtime(p);vector=model._vectorize({},b'MZ',a.c.components(details(),info()))
        result=a.trace(model,vector)
        self.assertAlmostEqual(result['probability'],model.score({},b'MZ',**a.c.components(details(),info())))
        self.assertEqual(result['largest_malware_contributions'][0]['path'][0]['branch'],'right')

    def test_collect_missing_coverage_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);archive=root/'data.zip';bytez=b'MZ fixture';sha=hashlib.sha256(bytez).hexdigest()
            with zipfile.ZipFile(archive,'w') as z:z.writestr('sample',bytez)
            required={sha:dict(sha256=sha,label=0,source_id='fixture',categories=[],pool='coverage_development'),
                'f'*64:dict(sha256='f'*64,label=1,source_id='fixture',categories=[],pool='coverage_development')}
            class Session:
                def post(self,*args,**kw):return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:details(sha=sha))
            collected={}
            with patch.dict(sys.modules,{'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)}):
                with self.assertRaisesRegex(ValueError,'Missing 1'):
                    a.collect(required,[archive],candidates(),info(),Session(),'http://fixture',30,root/'out',collected)
                saved=json.loads((root/'out/docker-feature-cache.json').read_text())
                self.assertFalse(saved['complete']);self.assertEqual(set(saved['samples']),{sha})
                a.collect({sha:required[sha]},[archive],candidates(),info(),Session(),'http://fixture',30,root/'out',collected)
                self.assertTrue(json.loads((root/'out/docker-feature-cache.json').read_text())['complete'])

    def test_complete_main_and_resume_input_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);cs=candidates();paths=['defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json',
                'validation-data/reviewer-v8-import-features-development/model.json',
                'validation-data/reviewer-v8-followup-development/imports-interval_midpoint-model.json']
            hashes={}
            for path,(_,p) in zip(paths,cs.values()):
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(p));hashes[path]=a.file_hash(target)
            archive=root/'data.zip';training=[];coverage=[];prior=[];cache={}
            with zipfile.ZipFile(archive,'w') as z:
                for i in range(10):
                    b=b'MZ'+str(i).encode();sha=hashlib.sha256(b).hexdigest();z.writestr(str(i),b)
                    sample=dict(sha256=sha,label=i%2,source_id='coverage',source='reviewer-core-v4',categories=[],
                                byte_size=len(b),input_location=str(archive))
                    detail=details(sha=sha);entry=a.service_vector(sample,b,detail,info(),cs)
                    if i<8:
                        training.append({k:sample[k] for k in ('sha256','label','source')}|{k:entry['record'][k] for k in a.w.SCORE_FEATURES})
                        cache[sha]=dict(structural_vector=entry['feature_vector'][6:],attributes={})
                    else:coverage.append(sample);prior.append(entry['record'])
            manifest=dict(complete=True,role='development',counts=dict(unused_pe=2),samples=coverage,
                frozen_candidate_sha256=hashes,input_files=[str(archive)])
            mp=root/'coverage.json';mp.write_text(json.dumps(manifest))
            cp=root/'cache.json';cp.write_text(json.dumps(dict(samples=cache,provenance=dict(feature_names=specification()['feature_names']))))
            comparison=root/'comparison';comparison.mkdir()
            (comparison/'comparison-summary.json').write_text(json.dumps(dict(complete=True,frozen_candidate_sha256=hashes)))
            with (comparison/'comparison-scores.csv').open('w',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(prior[0]));writer.writeheader();writer.writerows(prior)
            report=root/'report.csv';report.write_text('fixture')
            class Session:
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def get(self,*args,**kw):return types.SimpleNamespace(raise_for_status=lambda:None,json=info)
                def post(self,*args,**kw):
                    return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:details(sha=hashlib.sha256(kw['data']).hexdigest()))
            modules={'requests':types.SimpleNamespace(Session=Session),'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile)}
            output=root/'out';argv=['audit','--service-url','http://fixture','--coverage',str(mp),
                '--comparison',str(comparison),'--cache',str(cp),'--location',str(archive),'--output',str(output)]
            with patch.dict(sys.modules,modules),patch.object(a.w,'ROOT',root),\
                 patch.object(a.w,'load_audit',return_value=(training,{})),\
                 patch.object(a.w,'merge_training',return_value=(training,{'fixture':str(report)})):
                with patch.object(sys,'argv',argv):a.main()
                summary=json.loads((output/'docker-audit-summary.json').read_text())
                self.assertTrue(summary['complete']);self.assertEqual(summary['total_docker_samples'],10)
                self.assertEqual(summary['coverage_error_counts'],dict(benign=0,malicious=1))
                with patch.object(sys,'argv',argv+['--resume']):a.main()
                # Input drift must not destroy the prior valid checkpoint.
                cp.write_text(cp.read_text()+'\n')
                with patch.object(sys,'argv',argv+['--resume']):
                    with self.assertRaises(SystemExit) as raised:a.main()
                self.assertEqual(raised.exception.code,2)
                self.assertTrue(json.loads((output/'docker-feature-cache.json').read_text())['complete'])


if __name__=='__main__':unittest.main()
