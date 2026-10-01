"""Frozen comparison tests: routing, parity, provenance, and full SHA coverage."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

import reviewer_v8_coverage_compare as c
from defender.models.boundary_reviewer import IMPORT_FEATURES


def specification(version=6, threshold=.6):
    model=c.w.BoundaryReviewer.__new__(c.w.BoundaryReviewer)
    model.categories=dict(machine=['MACHINE_TYPES.AMD64'],magic=['PE32_PLUS'])
    model.derived_features=c.w.DERIVED_FEATURES
    p=dict(format_version=6,model_type='gradient_boosting',route_min=.15,
           reviewer_threshold=threshold,initial_raw_score=0.,learning_rate=.1,
           categories=model.categories,derived_features=list(c.w.DERIVED_FEATURES),
           feature_names=list(model._expected_feature_names()),
           estimators=[dict(children_left=[-1],children_right=[-1],feature=[-2],threshold=[-2.],raw_value=[0.])])
    if version==8:p.update(format_version=8,input_dtype='float32',import_features=list(IMPORT_FEATURES),feature_names=p['feature_names']+list(IMPORT_FEATURES))
    return p


def runtime(p):
    m=c.w.BoundaryReviewer.__new__(c.w.BoundaryReviewer);m._load(p);return m


def info():
    return dict(modern_adapter=True,score_endpoint_enabled=True,modern_adapter_v2=False,
                boundary_reviewer=True,reviewer_threshold=.6,reviewer_route_min=0.,adapter_threshold=.7)


def details(adapter=.8):
    return dict(benign_probability=.3,adapter_probability=adapter,base_trigger_raw=1,
        base_trigger_adjusted=1,signature_checked=False,signature_verified=None,
        adapter_threshold=.7,reviewer_threshold=.6,reviewer_routed=True,
        reviewer_probability=.5,result=0)


class CompareTests(unittest.TestCase):
    def test_routing_thresholds_and_paired_changes(self):
        candidates={n:(runtime(p),p) for n,p in zip(c.NAMES,[specification(),specification(8,.6),specification(8,.4)])}
        sample=dict(sha256='a'*64,label=1,source_id='dev',categories=[])
        row=c.compare_one(sample,b'MZ',{},details(),info(),candidates)
        self.assertEqual([row[n+'_prediction'] for n in c.NAMES],[0,0,1])
        low=c.compare_one(dict(sample,sha256='b'*64,label=0),b'MZ',{},details(.1),info(),candidates)
        self.assertFalse(low['v8_import_midpoint_routed'])
        self.assertEqual(low['v8_import_midpoint_prediction'],0)
        summary=c.summarize([row,low],candidates)
        self.assertEqual(summary['paired_changes_vs_v7']['v8_import_midpoint']['malicious']['rescued'],['a'*64])
        self.assertEqual(summary['models']['v7']['overall']['fn'],1)
        self.assertEqual(summary['v7_service_parity']['checked'],2)
        bad=details();bad['reviewer_probability']=.51
        with self.assertRaisesRegex(ValueError,'parity failed'):
            c.compare_one(sample,b'MZ',{},bad,info(),candidates)

    def test_normalization_and_runtime_precision(self):
        p=specification();index=p['feature_names'].index('characteristics_list_character_count')
        p['estimators']=[dict(children_left=[1,-1,-1],children_right=[2,-1,-1],
            feature=[index,-2,-2],threshold=[10.,-2.,-2.],raw_value=[0.,-20.,20.])]
        model=runtime(p);up=c.components(details(),info())
        attrs=dict(characteristics_list='CHARACTERISTICS.EXECUTABLE_IMAGE')
        normalized=dict(characteristics_list='EXECUTABLE_IMAGE')
        self.assertAlmostEqual(c.reviewer_score(model,p,attrs,b'MZ',up),model.score(normalized,b'MZ',**up))
        p=specification(8);p['estimators'][0]=dict(children_left=[1,-1,-1],children_right=[2,-1,-1],
            feature=[1,-2,-2],threshold=[.8,-2.,-2.],raw_value=[0.,-20.,20.])
        model=runtime(p)
        self.assertAlmostEqual(c.reviewer_score(model,p,{},b'MZ',up),model.score({},b'MZ',**up))

    def test_manifest_and_service_guards(self):
        rows=[dict(sha256='a'*64,label=0),dict(sha256='b'*64,label=1)]
        m=dict(complete=True,role='development',counts=dict(unused_pe=2),samples=rows)
        self.assertEqual(len(c.validate_manifest(m)),2)
        for key,value in [('complete',False),('role','evaluation')]:
            with self.assertRaises(ValueError):c.validate_manifest(dict(m,**{key:value}))
        with self.assertRaises(ValueError):c.validate_manifest(dict(m,samples=[rows[0],rows[0]]))
        model=runtime(specification());c.validate_service(info(),model)
        for key,value in [('reviewer_route_min',.15),('modern_adapter_v2',True),('reviewer_threshold',.61)]:
            with self.assertRaises(ValueError):c.validate_service(dict(info(),**{key:value}),model)

    def test_full_run_sha_coverage_and_changed_model(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=['defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json',
                'validation-data/reviewer-v8-import-features-development/model.json',
                'validation-data/reviewer-v8-followup-development/imports-interval_midpoint-model.json']
            hashes={}
            for path,p in zip(paths,[specification(),specification(8),specification(8,.4)]):
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(p));hashes[path]=hashlib.sha256(target.read_bytes()).hexdigest()
            archive=root/'samples.zip';samples=[]
            with zipfile.ZipFile(archive,'w') as z:
                for label,b in [(0,b'MZ benign'),(1,b'MZ malware')]:
                    sha=hashlib.sha256(b).hexdigest();z.writestr(sha,b)
                    samples.append(dict(sha256=sha,label=label,source_id='dev',byte_size=len(b),categories=[]))
            manifest=dict(complete=True,role='development',counts=dict(unused_pe=2),samples=samples,
                          frozen_candidate_sha256=hashes,input_files=[str(archive)],scope='fixture')
            path=root/'manifest.json';path.write_text(json.dumps(manifest))
            class Response:
                def __init__(self,value):self.value=value
                def json(self):return self.value
                def raise_for_status(self):pass
            class Session:
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def get(self,*args,**kw):return Response(info())
                def post(self,*args,**kw):return Response(details())
            class Extractor:
                def __init__(self,b):pass
                def extract(self):return {}
            modules={'requests':types.SimpleNamespace(Session=Session), 'pyzipper':types.SimpleNamespace(AESZipFile=zipfile.ZipFile),
                     'defender.models.attribute_extractor':types.SimpleNamespace(PEAttributeExtractor=Extractor)}
            with patch.object(c.w,'ROOT',root),patch.dict(sys.modules,modules):
                output=root/'results'
                with patch.object(sys,'argv',['compare','--manifest',str(path),'--output',str(output),'--service-url','http://fixture']):c.main()
                summary=json.loads((output/'comparison-summary.json').read_text())
                self.assertEqual(summary['sample_count'],2);self.assertTrue(summary['complete'])
                self.assertEqual(summary['v7_service_parity']['checked'],2)
                (root/paths[0]).write_text('{}')
                with self.assertRaisesRegex(ValueError,'candidate changed'):c.load_candidates(manifest,root)
                (root/paths[0]).write_text(json.dumps(specification()))
                manifest['samples'][1]['sha256']='f'*64;path.write_text(json.dumps(manifest))
                output=root/'missing'
                with patch.object(sys,'argv',['compare','--manifest',str(path),'--output',str(output),'--service-url','http://fixture']):
                    with self.assertRaises(SystemExit) as raised:c.main()
                self.assertEqual(raised.exception.code,2)
                self.assertFalse((output/'comparison-summary.json').exists())


if __name__=='__main__':unittest.main()
