#!/usr/bin/env python3
"""Portable pipeline parity, inference-array identity and package safeguards."""
import gzip
import json
from pathlib import Path
import pickle
import shutil
import struct
from types import SimpleNamespace as NS
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.preprocessing import MaxAbsScaler,OneHotEncoder

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'defender'))
from defender.models.nfs_model import NeedForSpeedModel
from defender.models.compact_model import CompactNeedForSpeedModel
from defender.models.modern_adapter import ModernAdapterModel
from defender.models.portable_model import PortableModernAdapter
from defender.models.portable_pipeline import PortableFeaturePipeline,export_pipeline
from defender.models.boundary_reviewer import BoundaryReviewer
from defender.models.submission_extractor import legacy_text_features
import check_reviewer_v8_runtime_parity as check
import prepare_reviewer_v8_submission as prepare


def fixture():
    records=[]
    for i in range(12):
        d={name:float(i*(j+1)) for j,name in enumerate(NeedForSpeedModel.NUMERICAL_ATTRIBUTES)}
        d.update(machine='MACHINE_TYPES.AMD64' if i%2 else 'MACHINE_TYPES.I386',magic='PE32_PLUS' if i%2 else 'PE32')
        d.update({name:['',' alpha beta alpha ',' UNICODE éé Beta  Gamma ',' kernel32.dll  user32.dll '][(i+j)%4]
                  for j,name in enumerate(NeedForSpeedModel.TEXTUAL_ATTRIBUTES)})
        records.append(d)
    frame=pd.DataFrame(records)
    model=NeedForSpeedModel(categorical_extractor=OneHotEncoder(handle_unknown='ignore'),
        textual_extractor=HashingVectorizer(n_features=16,token_pattern=r'(?<=\s)(.*?)(?=\s)'),feature_scaler=MaxAbsScaler())
    model._train_categorical_extractor(frame[model.CATEGORICAL_ATTRIBUTES]);model._train_textual_extractor(frame[model.TEXTUAL_ATTRIBUTES])
    raw=sparse.hstack([sparse.csr_matrix(frame[model.NUMERICAL_ATTRIBUTES].values),
        model._transform_categorical_attributes(frame[model.CATEGORICAL_ATTRIBUTES]),model._transform_textual_attributes(frame[model.TEXTUAL_ATTRIBUTES])])
    model._train_feature_scaler(raw);model.classifier=None
    return model,frame


class SubmissionTests(unittest.TestCase):
    def test_legacy_import_and_forwarded_export_semantics(self):
        raw=bytearray(1024);struct.pack_into('<I',raw,0x3c,64)
        struct.pack_into('<H',raw,88,0x20b);struct.pack_into('<I',raw,200,256)
        struct.pack_into('<I',raw,272,10);struct.pack_into('<I',raw,280,3)
        struct.pack_into('<I',raw,288,320);struct.pack_into('<I',raw,292,340)
        struct.pack_into('<III',raw,320,400,420,440);struct.pack_into('<HHH',raw,340,0,1,1)
        raw[400:411]=b'PublicName\0';raw[420:426]=b'Alias\0';raw[440:450]=b'LastAlias\0'
        binary=NS(has_imports=True,imports=[NS(name='normal.dll')],
            delay_imports=[NS(entries=[NS(is_ordinal=False,name='Delayed'),NS(is_ordinal=True,name='')])],
            imported_functions=[NS(name='Regular'),NS(name='ResolvedOrdinal'),NS(name='Delayed')],
            has_exports=True,rva_to_offset=lambda rva:rva,
            get_export=lambda:NS(entries=[NS(ordinal=10,name='other.ForwardTarget'),NS(ordinal=11,name='Alias'),NS(ordinal=12,name='unnamed.Target')]))
        result=legacy_text_features(binary,bytes(raw))
        self.assertEqual(result,dict(libraries='normal.dll',functions='Regular ResolvedOrdinal',
            exports_list='PublicName LastAlias unnamed.Target',exports=3))
        struct.pack_into('<I',raw,280,4);struct.pack_into('<I',raw,332,500);struct.pack_into('<H',raw,346,2)
        raw[500:802]=b'X'*301+b'\0'
        result=legacy_text_features(binary,bytes(raw))
        self.assertEqual(result['exports'],2)
        self.assertEqual(result['exports_list'],'PublicName LastAlias')
        raw[800]=0
        self.assertEqual(legacy_text_features(binary,bytes(raw))['exports'],3)
        # A short alias cannot undo the old parser's corrupted-ordinal marker.
        raw[800]=ord('X');struct.pack_into('<I',raw,280,5)
        struct.pack_into('<I',raw,336,400);struct.pack_into('<H',raw,348,2)
        self.assertEqual(legacy_text_features(binary,bytes(raw))['exports'],2)
        binary.has_imports=False;binary.has_exports=False
        self.assertEqual(legacy_text_features(binary,b''),dict(libraries='',functions='',exports_list='',exports=0))
        binary.has_exports=True
        with self.assertRaises(struct.error):legacy_text_features(binary,b'MZ')

    def test_actual_final_weights_ignore_upstream_scores(self):
        path=Path(__file__).resolve().parents[1]/'defender/defender/models/boundary_reviewer_v8_final/model.json'
        self.assertEqual(prepare.verified_model_bytes(path),path.read_bytes().replace(b'\r\n',b'\n'))
        payload=json.loads(path.read_text());reviewer=BoundaryReviewer(path)
        self.assertEqual(len(reviewer.estimators),128);self.assertEqual(reviewer.route_min,.15)
        rng=np.random.default_rng(8704)
        for _ in range(16):
            vector=rng.normal(size=72).tolist();reviewer._vectorize=lambda *args,**kwargs:vector
            expected=check.model_score(payload,vector);self.assertEqual(reviewer.score({},b''),expected)
            vector[:6]=[100.,-100.,20.,30.,40.,50.];self.assertEqual(reviewer.score({},b''),expected)

    def test_portable_vectors_include_unknown_categories_and_unicode(self):
        pipeline,frame=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'feature-pipeline.json';path.write_text(json.dumps(export_pipeline(pipeline)))
            portable=PortableFeaturePipeline(path)
            extra=frame.copy();extra.loc[0,'machine']='UNKNOWN';extra.loc[1,'magic']='UNKNOWN'
            np.testing.assert_array_equal(portable._extract_features(extra).toarray(),pipeline._extract_features(extra).toarray())
            pipeline.categorical_extractor.drop='first'
            with self.assertRaisesRegex(ValueError,'Unsupported original'):export_pipeline(pipeline)

    def test_windows_model_newlines_and_weight_changes(self):
        source=Path(__file__).resolve().parents[1]/'defender/defender/models/boundary_reviewer_v8_final/model.json'
        canonical=prepare.verified_model_bytes(source)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'model.json';path.write_bytes(canonical.replace(b'\n',b'\r\n'))
            self.assertEqual(prepare.verified_model_bytes(path),canonical)
            path.write_bytes(path.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'Final v8 model hash differs'):prepare.verified_model_bytes(path)

    def test_portable_forest_and_adapter_unchanged(self):
        pipeline,frame=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);compact=root/'compact';adapter=root/'adapter';compact.mkdir();adapter.mkdir()
            payload=export_pipeline(pipeline);width=len(payload['scale'])
            (compact/'feature-pipeline.json').write_text(json.dumps(payload));(compact/'metadata.json').write_text(json.dumps(dict(feature_count=width,tree_count=1)))
            arrays=dict(offsets=[0,3],children_left=[1,-1,-1],children_right=[2,-1,-1],features=[0,-2,-2],thresholds=[.5,-2.,-2.],malware_probability=[0.,.2,.8])
            for name,value in arrays.items():np.save(compact/(name+'.npy'),np.asarray(value,dtype=np.float64 if name in ('thresholds','malware_probability') else np.int32))
            with gzip.open(compact/'feature_pipeline.pkl.gz','wb') as stream:pickle.dump(pipeline,stream)
            (adapter/'metadata.json').write_text(json.dumps(dict(feature_count=width+1,adapter_threshold=.7,base_benign_threshold=.510001)))
            np.save(adapter/'coefficients.npy',np.linspace(-.1,.1,width+1));np.save(adapter/'intercept.npy',np.array([.2]))
            before=ModernAdapterModel(compact,adapter);after=PortableModernAdapter(compact,adapter)
            b,bf=before.extract_base_components(frame);a,af=after.extract_base_components(frame)
            np.testing.assert_array_equal(a,b);np.testing.assert_array_equal(af.toarray(),bf.toarray())
            np.testing.assert_array_equal(after.score_adapter(af,b<.510001),before.score_adapter(bf,b<.510001))
            # The migrated class must not need the legacy pickle.
            (compact/'feature_pipeline.pkl.gz').unlink();PortableModernAdapter(compact,adapter)

    def test_runtime_checker_detects_feature_and_decision_drift(self):
        model=dict(feature_names=['x']*6+['import_library='+s for s in check.IMPORTS]+['kernel_driver_import_count'],
            route_min=.15,reviewer_threshold=.6,initial_raw_score=1.,learning_rate=.1,estimators=[dict(children_left=[-1],children_right=[-1],feature=[-2],threshold=[-2.],raw_value=[0.])])
        old=dict(benign_probability=.4,adapter_probability=.9,base_trigger_raw=1,base_trigger_adjusted=1,
            signature_checked=False,signature_verified=None,reviewer_libraries='kernel32.dll',reviewer_feature_vector=[.4,.9,1,1,0,0],reviewer_feature_names=['x']*6)
        new=dict(old,reviewer_feature_names=model['feature_names'],reviewer_feature_vector=old['reviewer_feature_vector']+[0.]*6,
            result=1,reviewer_routed=True,reviewer_probability=check.model_score(model,[0.]*12))
        self.assertTrue(check.compare(old,new,model)['pass_'])
        new['result']=0;self.assertFalse(check.compare(old,new,model)['pass_'])
        new['result']=1;new['adapter_probability']=.91;self.assertIn('adapter_probability',check.compare(old,new,model)['changed_fields'])

    def test_package_whitelist_preserves_sources_and_excludes_pickle_samples(self):
        actual=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp,patch('builtins.print'):
            root=Path(tmp);artifacts=root/'artifacts';compact=artifacts/'compact';adapter=artifacts/'modern_adapter';compact.mkdir(parents=True);adapter.mkdir()
            for name in prepare.ARRAYS:(compact/name).write_text('{}')
            (compact/'pipeline-export-summary.json').write_text(json.dumps(dict(complete=True,export_sha256=prepare.digest(compact/'feature-pipeline.json'))))
            for name in ('metadata.json','coefficients.npy','intercept.npy'):(adapter/name).write_text('{}')
            (compact/'malware.exe').write_bytes(b'MZ');(compact/'feature_pipeline.pkl.gz').write_bytes(b'oldpickle')
            # Exercise a Windows checkout all the way through context creation.
            repo=root/'repo'
            for name in prepare.CODE:
                relative=Path('defender/defender')/name;destination=repo/relative
                destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(actual/relative,destination)
            relative=Path('defender/defender/models/boundary_reviewer_v8_final')
            shutil.copytree(actual/relative,repo/relative)
            model=repo/relative/'model.json';model.write_bytes(prepare.verified_model_bytes(model).replace(b'\n',b'\r\n'))
            shutil.copytree(actual/'submission',repo/'submission')
            output=root/'context';prepare.prepare(repo,artifacts,output)
            self.assertEqual(len(list(output.rglob('Dockerfile'))),1);self.assertFalse(list(output.rglob('*.exe')));self.assertFalse(list(output.rglob('*.pkl.gz')))
            manifest=json.loads((output/'submission-manifest.json').read_text());self.assertFalse(manifest['runtime_qualified'])
            self.assertEqual(prepare.digest(output/'app/defender/models/boundary_reviewer_v8_final/model.json'),prepare.MODEL_SHA)
            with self.assertRaisesRegex(ValueError,'not empty'):prepare.prepare(repo,artifacts,output)


if __name__=='__main__':unittest.main()
