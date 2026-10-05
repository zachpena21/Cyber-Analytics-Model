import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_structural_validation as v
from test_reviewer_v8_software_calibration import software_pool
from test_reviewer_v8_grouped_experiment import NAMES


class StructuralValidationTests(unittest.TestCase):
    def test_acquisition_dates_and_sha_validation(self):
        now=datetime.now(timezone.utc);frozen=(now-timedelta(hours=2)).isoformat()
        v.check_acquisitions([dict(acquired_at=(now-timedelta(hours=1)).isoformat())],frozen)
        for bad in ({},dict(acquired_at=frozen),dict(acquired_at=(now+timedelta(hours=1)).isoformat()),dict(acquired_at='2026-01-01T00:00:00')):
            with self.assertRaises(ValueError):v.check_acquisitions([bad],frozen)
        self.assertTrue(v.valid_sha('a'*64));self.assertFalse(v.valid_sha('G'*64))

    def test_frozen_comparison_preserves_gate_and_structural_vector(self):
        row=dict(sha256='a'*64,label=1,source='new',adapter_probability=.1,benign_probability=.9,
                 signature_checked=0,signature_verified=0,v7_service_parity_error=0.)
        schema=NAMES[6:]+list(v.g.f.t.e.IMPORT_FEATURES)
        model=dict(feature_names=schema,initial_raw_score=0.,learning_rate=.1,estimators=[dict(
            children_left=[-1],children_right=[-1],feature=[-2],threshold=[-2.],raw_value=[1.])])
        bounded=dict(format_version='bounded_upstream_development_v1',configuration=v.b.CONFIG,
                     upstream_features=list(v.b.FEATURES),coefficients=[.1,.1,0,0],structural_model=model)
        details=dict(reviewer_feature_vector=[0.]*66,reviewer_libraries='kernel32.dll')
        manifest=dict(models={v.PRIMARY:dict(threshold=.5),v.COMPARISON:dict(threshold=.5)})
        with patch.object(v.f.c,'compare_one',return_value=row):
            result=v.compare_one({},b'bytes',details,{},manifest,model,bounded,{})
        self.assertEqual(result[v.PRIMARY+'_prediction'],0)
        self.assertEqual(result[v.COMPARISON+'_prediction'],0)
        self.assertFalse(result[v.PRIMARY+'_routed'])
        self.assertAlmostEqual(result[v.PRIMARY+'_score'],1/(1+np.exp(-.1)))

    def test_evaluation_requires_complete_sha_coverage(self):
        payloads=[b'MZ-benign-test',b'MZ-malware-test']
        samples={hashlib.sha256(data).hexdigest():dict(sha256=hashlib.sha256(data).hexdigest(),
            byte_size=len(data),label=i,source_id='new',categories=[]) for i,data in enumerate(payloads)}
        def compare(sample,*args):
            return dict(sha256=sample['sha256'],label=sample['label'],source='new',v7_service_parity_error=0.,
                **{name+'_prediction':sample['label'] for name in (v.PRIMARY,v.COMPARISON,'v7','v8_import_upper')})
        class Response:
            def raise_for_status(self):pass
            def json(self):return {}
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def get(self,*args,**kwargs):return Response()
            def post(self,*args,**kwargs):return Response()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'sources.json';now=datetime.now(timezone.utc)
            v.w.dump(source,[dict(acquired_at=(now-timedelta(minutes=1)).isoformat())])
            manifest=dict(frozen_at=(now-timedelta(hours=1)).isoformat(),scope='test',models={
                name:dict(threshold=.8) for name in (v.PRIMARY,v.COMPARISON)})
            legacy={name:(SimpleNamespace(threshold=.7,route_min=.15),{}) for name in ('v7','v8_import_upper')}
            args=SimpleNamespace(output=root/'good',bundle=root/'bundle',sources=source,benign_only=False,service_url='http://test',api_timeout=1.)
            v.w.dump(args.bundle/'freeze-manifest.json',dict(test=True))
            acquisition=dict(input_files=['test-path'],archive_warnings=[],excluded_overlap_sha256=[])
            with patch.dict('sys.modules',dict(requests=SimpleNamespace(Session=Session),pyzipper=SimpleNamespace(AESZipFile=object))),\
                 patch.object(v,'load_bundle',return_value=(manifest,{}, {},legacy,set())),\
                 patch.object(v.f.c,'validate_service'),patch.object(v,'compare_one',side_effect=compare),\
                 patch.object(v.f,'scan_sources',side_effect=lambda *args:(copy.deepcopy(samples),acquisition)),\
                 patch.object(v.w,'payloads',return_value=iter(payloads)),patch('builtins.print'):
                v.evaluate(args)
            self.assertTrue(v.f.read(root/'good/comparison-summary.json')['complete'])
            args.output=root/'missing'
            with patch.dict('sys.modules',dict(requests=SimpleNamespace(Session=Session),pyzipper=SimpleNamespace(AESZipFile=object))),\
                 patch.object(v,'load_bundle',return_value=(manifest,{}, {},legacy,set())),\
                 patch.object(v.f.c,'validate_service'),patch.object(v,'compare_one',side_effect=compare),\
                 patch.object(v.f,'scan_sources',return_value=(copy.deepcopy(samples),acquisition)),\
                 patch.object(v.w,'payloads',return_value=iter(payloads[:1])):
                with self.assertRaisesRegex(ValueError,'Required SHA coverage'):v.evaluate(args)
            self.assertFalse((args.output/'comparison-summary.json').exists())

    def test_freeze_reproduces_both_panels_and_rejects_tampering(self):
        entries=software_pool();example=next(copy.deepcopy(e) for e in entries.values() if e['record']['label']==1)
        for i in range(76):
            sha=hashlib.sha256(('freeze-cluster:'+str(i)).encode()).hexdigest();e=copy.deepcopy(example)
            e['record']['sha256']=sha;e['feature_vector'][NAMES.index('symbols')]=100
            e['feature_vector'][NAMES.index('minor_linker_version')]=140
            e['feature_vector'][NAMES.index('byte_entropy')]+=i*.001;entries[sha]=e
        config=dict(n_estimators=8,learning_rate=.1,max_depth=2,min_samples_leaf=2,max_features=None,subsample=1.)
        with tempfile.TemporaryDirectory() as directory,patch.dict(v.g.f.w.CONFIG,config,clear=True),patch('builtins.print'):
            root=Path(directory);software=root/'software';ablation=root/'ablation';partial=root/'partial';bounded=root/'bounded'
            for mode in v.c.MODES:
                v.s.control(entries,NAMES,software/mode,mode)
                v.a.experiment_panel(entries,NAMES,software,ablation/mode,mode)
                v.p.experiment_panel(entries,NAMES,ablation,software,partial/mode,mode)
                groups=v.s.stable_groups(entries,NAMES,mode);cluster=groups[hashlib.sha256(b'freeze-cluster:0').hexdigest()]
                with patch.object(v.d,'CLUSTER',cluster):v.b.experiment_panel(entries,NAMES,partial,bounded/mode,mode,{})
            oldbundle=root/'old';excluded={'b'*64}
            legacy=dict(models={k:dict(path=k+'-model.json') for k in v.f.c.NAMES},exclusions=dict(path='excluded-sha256.json'))
            candidates={k:(SimpleNamespace(feature_names=NAMES),{}) for k in v.f.c.NAMES}
            for k in v.f.c.NAMES:v.w.dump(oldbundle/(k+'-model.json'),{})
            v.w.dump(oldbundle/'excluded-sha256.json',list(excluded))
            v.w.dump(oldbundle/'freeze-manifest.json',legacy)
            args=SimpleNamespace(previous=bounded,output=root/'frozen',bundle=oldbundle,reports=root,
                                 fresh_audit=[],fresh_comparison=[])
            with patch.object(v,'verify_previous',return_value=dict(partial=str(partial),input_sha256={})),\
                 patch.object(v.g,'load_inputs',return_value=(entries,NAMES,{},[])),\
                 patch.object(v.f,'load_bundle',return_value=(legacy,candidates,excluded)):
                v.w.dump(bounded/'inputs.json',dict(test=True))
                v.freeze(args)
                manifest,structural,correction,_,exclusions=v.load_bundle(args.output)
                self.assertEqual(manifest['selection']['fold'],0)
                self.assertEqual(manifest['selection']['mode'],'provenance')
                self.assertTrue(set(entries)<=exclusions)
                self.assertEqual(structural,correction['structural_model'])
                self.assertEqual(manifest['models'][v.PRIMARY]['threshold'],structural['reviewer_threshold'])
                path=args.output/'structural-primary-model.json';model=v.f.read(path);model['initial_raw_score']+=.1;v.w.dump(path,model)
                with self.assertRaisesRegex(ValueError,'Frozen artifact changed'):v.load_bundle(args.output)
            # Verification fails before freezing if a completed bounded held score changes.
            path=bounded/'provenance'/v.b.VARIANT/'development-scores.json';records=v.f.read(path)
            records[0]['reviewer_score']=.123;v.w.dump(path,records)
            with self.assertRaisesRegex(ValueError,'exported-score parity'):
                v.check_bounded(entries,NAMES,bounded,partial,'provenance',{})


if __name__=='__main__':unittest.main()
