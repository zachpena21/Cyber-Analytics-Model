#!/usr/bin/env python3
"""Integrity and interruption tests for additive targeted feature collection."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import reviewer_v8_targeted_feature_cache as t


class TargetedCacheTests(unittest.TestCase):
    def fixture(self, root):
        root.mkdir(exist_ok=True)
        data=b'MZ'+b'candidate'*20;sha=hashlib.sha256(data).hexdigest()
        exclude=root/'excluded.json';t.cache.dump(exclude,[])
        path=root/'product.zip';provenance=dict(development_only=True,package='installed:Example')
        row=dict(sha256=sha,label=0,byte_size=len(data),archive_member='samples/'+sha+'.dll',pattern='tiny_managed')
        with zipfile.ZipFile(path,'w') as z:
            z.writestr(row['archive_member'],data)
            z.writestr('collection-manifest.json',json.dumps(dict(provenance=provenance,samples=[row])))
        artifact=dict(path=str(path),sha256=t.cache.digest(path),sample_count=1,by_pattern={'tiny_managed':1})
        t.cache.dump(root/'sources.json',[dict(path=str(path),label=0,source_id='Example',development_only=True,provenance=provenance)])
        t.cache.dump(root/'inputs.json',dict(input_sha256={str(exclude):t.cache.digest(exclude)}))
        t.cache.dump(root/'targeted-benign-inventory-summary.json',dict(complete=True,role='targeted_benign_development_inventory',
            training=False,independent_validation=False,unique_new_samples=1,product_cohorts=1,by_pattern={'tiny_managed':1},artifacts=[artifact]))
        return sha,exclude,path

    def test_inventory_lineage_payload_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sha,exclude,path=self.fixture(root)
            before={p:t.cache.digest(p) for p in root.iterdir()}
            samples,hashes=t.inventory_samples(root,exclude)
            self.assertEqual(set(samples),{sha});self.assertIn(str(path),hashes)
            self.assertEqual(before,{p:t.cache.digest(p) for p in root.iterdir()})
            path.write_bytes(path.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'identity'):
                t.inventory_samples(root,exclude)

    def test_historical_overlap_rejected_even_with_rebound_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sha,exclude,_=self.fixture(root)
            t.cache.dump(exclude,[sha]);t.cache.dump(root/'inputs.json',dict(input_sha256={str(exclude):t.cache.digest(exclude)}))
            with self.assertRaisesRegex(ValueError,'overlapping'):
                t.inventory_samples(root,exclude)

    def test_interruption_resume_replays_without_rescoring(self):
        samples={'a':{'bytez':b'a'},'b':{'bytez':b'b'}};saved={};calls=[];checkpoints=[]
        def score(data):
            calls.append(data)
            if data==b'b':raise TimeoutError('interrupted')
            return {'value':data.decode()}
        def build(sha,sample,details):return {'diagnostic_details':details,'identity':sha}
        with self.assertRaises(TimeoutError):
            t.collect(samples,saved,score,build,lambda:checkpoints.append(dict(saved)))
        self.assertEqual(list(saved),['a']);self.assertEqual(len(checkpoints),1)
        t.collect(samples,saved,lambda b:calls.append(b) or {'value':b.decode()},build,lambda:None)
        self.assertEqual(calls,[b'a',b'b',b'b']);self.assertEqual(set(saved),set(samples))
        saved['a']['identity']='tampered'
        with self.assertRaisesRegex(ValueError,'Resume parity'):
            t.collect(samples,saved,lambda b:self.fail('must replay first'),build,lambda:None)
        with self.assertRaisesRegex(ValueError,'unexpected'):
            t.collect(samples,{'extra':{}},score,build,lambda:None)


if __name__=='__main__':unittest.main()
