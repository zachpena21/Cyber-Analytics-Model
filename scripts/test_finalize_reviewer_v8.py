#!/usr/bin/env python3
"""Exact frozen-to-runtime mapping, upstream independence and immutable sources."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import numpy as np
import finalize_reviewer_v8 as final
from test_reviewer_v8_docker_train import specification


def fixture():
    payload=specification(7);payload.update(format_version=7,input_dtype='float32')
    reference=final.frozen.w.BoundaryReviewer.__new__(final.frozen.w.BoundaryReviewer);reference._load(payload)
    schema=list(reference.feature_names)[6:]+list(final.frozen.g.f.t.e.IMPORT_FEATURES)
    threshold=1.+float(np.finfo(np.float32).eps)*.75
    structural=dict(feature_names=schema,reviewer_threshold=final.THRESHOLD,initial_raw_score=.123,learning_rate=.1,
        estimators=[dict(children_left=[1,-1,-1],children_right=[2,-1,-1],feature=[0,-2,-2],threshold=[threshold,-2.,-2.],raw_value=[0.,-2.,2.]) for _ in range(8)])
    entries={}
    for i in range(12):
        attrs=dict(virtual_size=1. if i%2==0 else float(np.nextafter(np.float32(1.),np.float32(2.))),libraries='kernel32.dll')
        components={name:.2 for name in final.frozen.w.SCORE_FEATURES};components['adapter_probability']=.9 if i%3 else .1
        record=dict(sha256=f'{i:064x}',label=i%2,source='fixture',**components)
        entries[record['sha256']]=dict(record=record,feature_vector=reference._vectorize(attrs,b'MZ',components),libraries=attrs['libraries'])
    return reference,structural,entries


class FinalizationTests(unittest.TestCase):
    def test_exact_runtime_mapping_and_live_vectorization(self):
        reference,structural,entries=fixture();before=copy.deepcopy(structural)
        payload,reviewer=final.runtime_export(structural,reference)
        self.assertEqual(structural,before);self.assertEqual(payload['feature_names'][:6],list(reference.feature_names[:6]))
        self.assertEqual(payload['estimators'][0]['feature'],[6,-2,-2])
        result=final.check_parity(structural,reviewer,entries,list(reference.feature_names))
        self.assertEqual(result['max_abs_score_error'],0.);self.assertEqual(result['decision_mismatches'],0)
        for i,entry in enumerate(entries.values()):
            attrs=dict(virtual_size=entry['feature_vector'][6],libraries=entry['libraries'])
            expected=final.frozen.g.exported_scores(structural,np.asarray([entry['feature_vector'][6:]+list(final.frozen.g.f.t.e._import_values(attrs))]))[0]
            self.assertEqual(reviewer.score(attrs,b'MZ',**{k:entry['record'][k] for k in final.frozen.w.SCORE_FEATURES}),expected)
        altered=copy.deepcopy(structural);altered['reviewer_threshold']=.5
        with self.assertRaisesRegex(ValueError,'threshold differs'):final.runtime_export(altered,reference)
        altered=copy.deepcopy(structural);altered['feature_names'].reverse()
        with self.assertRaisesRegex(ValueError,'schema differs'):final.runtime_export(altered,reference)

    def test_export_archive_and_source_preservation(self):
        reference,structural,entries=fixture()
        with tempfile.TemporaryDirectory() as tmp,patch('builtins.print'):
            root=Path(tmp);bundle=root/'bundle';prior=root/'cache';output=root/'output'
            final.cache.dump(bundle/'structural-primary-model.json',structural)
            final.cache.dump(bundle/'freeze-manifest.json',dict(complete=True))
            final.cache.dump(prior/'development-input-cache.json',dict(samples=entries,feature_names=list(reference.feature_names)))
            final.cache.dump(prior/'rich-feature-summary.json',dict(converted_sha256=[]))
            old=root/'defender/defender/models/boundary_reviewer_v7_gbdt_candidate/metadata.json';final.cache.dump(old,dict(name='v7'))
            sourcehash=final.cache.digest(bundle/'structural-primary-model.json')
            manifest=dict(models={final.frozen.PRIMARY:dict(path='structural-primary-model.json',threshold=final.THRESHOLD,route_min=final.ROUTE)},selection=dict(mode='provenance',fold=0,policy='software'))
            originals={str(p):final.cache.digest(p) for p in root.rglob('*') if p.is_file()}
            settings=SimpleNamespace(root=root,bundle=bundle,cache=prior,output=output)
            with patch.object(final,'SELECTED_SHA',sourcehash),patch.object(final.frozen,'load_bundle',return_value=(manifest,structural,{},dict(v7=(reference,{})),set())),patch.object(final.rich,'validate_cache',return_value=({},{})):
                final.run(settings)
            report=final.cache.read(output/'reviewer-v8-finalization-summary.json')
            self.assertTrue(report['complete']);self.assertFalse(report['training'])
            self.assertEqual(len(report['candidates']),1)
            with zipfile.ZipFile(output/'reviewer-v8-final-model.zip') as z:
                self.assertEqual(set(z.namelist()),{'boundary_reviewer_v8_final/model.json','boundary_reviewer_v8_final/metadata.json'})
            self.assertEqual(originals,{p:final.cache.digest(p) for p in originals})
            with patch.object(final.frozen,'load_bundle',return_value=(manifest,structural,{},dict(v7=(reference,{})),set())),self.assertRaisesRegex(ValueError,'not the selected'):
                settings.output=root/'refused';final.run(settings)
            self.assertFalse(settings.output.exists())


if __name__=='__main__':unittest.main()
