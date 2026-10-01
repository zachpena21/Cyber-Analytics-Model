"""Grouped data isolation, frozen provenance, gated calibration, export parity."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import reviewer_v8_docker_train as t
from test_reviewer_v8_coverage_compare import specification as small_specification, runtime


def specification(version=6,threshold=.6):
    p=small_specification(6,threshold)
    p['categories']=dict(machine=['MACHINE_TYPES.AMD64','MACHINE_TYPES.ARM64','MACHINE_TYPES.ARMNT','MACHINE_TYPES.I386','MACHINE_TYPES.IA64'],magic=['PE32','PE32_PLUS'])
    m=t.w.BoundaryReviewer.__new__(t.w.BoundaryReviewer);m.categories=p['categories'];m.derived_features=t.w.DERIVED_FEATURES
    p['feature_names']=list(m._expected_feature_names())
    if version==8:p.update(format_version=8,input_dtype='float32',import_features=list(t.e.IMPORT_FEATURES),feature_names=p['feature_names']+list(t.e.IMPORT_FEATURES))
    return p


class DockerTrainTests(unittest.TestCase):
    def test_installation_and_acquisition_groups(self):
        def entry(path,label=0,source='windows'):
            return dict(original_path=path,record=dict(label=label,source=source))
        self.assertEqual(t.group_for(entry('C:\\Program Files\\Git\\bin\\one.exe')),
                         t.group_for(entry('C:\\Program Files (x86)\\Git\\bin\\two.dll')))
        self.assertNotEqual(t.group_for(entry('C:/Program Files/Git/bin/one.exe')),
                            t.group_for(entry('C:/Program Files/Cura/bin/two.exe')))
        self.assertEqual(t.group_for(entry(None,1,'coverage-malware:batch-a')),'malware-acquisition:batch-a')
        self.assertEqual(t.related_old_sources('malware-acquisition:malwarebazaar-v10-final-pool-20260928'),{'reviewer-v5-v10-diagnostic'})

    def test_group_split_is_deterministic_and_intact(self):
        rows=[];groups={}
        for label in (0,1):
            for group,size in [('one',2),('two',8),('three',15)]:
                for i in range(size):
                    sha=hashlib.sha256(f'{label}:{group}:{i}'.encode()).hexdigest()
                    rows.append(dict(sha256=sha,label=label));groups[sha]=f'{label}:{group}'
        fit,cal,assignment=t.grouped_split(rows,groups)
        fit2,cal2,assignment2=t.grouped_split(list(reversed(rows)),groups)
        self.assertEqual((fit,cal,assignment),(fit2,cal2,assignment2))
        self.assertFalse({groups[r['sha256']] for r in fit}&{groups[r['sha256']] for r in cal})
        self.assertEqual({r['label'] for r in fit},{0,1});self.assertEqual({r['label'] for r in cal},{0,1})
        self.assertEqual(len(fit)+len(cal),len(rows))

    def fixture(self):
        rng=np.random.RandomState(37);base=specification();model=runtime(base)
        frozen={n:(runtime(p),p) for n,p in zip(t.c.NAMES,[base,specification(8),specification(8,.4)])}
        original=[];new=[];cached={};groups={};samples={}
        for i in range(136):
            label=i%2;sha=hashlib.sha256(str(i).encode()).hexdigest()
            row=dict(sha256=sha,label=label,source='reviewer-core-v4' if i<96 else ('windows' if label==0 else 'coverage-malware:batch-'+str(i%4)),
                benign_probability=float(.8-.6*label+rng.uniform(-.05,.05)),adapter_probability=float(.4+.4*label),
                base_trigger_raw=float(label),base_trigger_adjusted=float(label),signature_checked=0.,signature_verified=0.)
            attrs=dict(string_urls=int(rng.randint(0,25)),libraries='KERNEL32.dll',virtual_size=int(rng.randint(1000,10000)))
            vector=model._vectorize(attrs,b'MZ',row);extra=list(t.e._import_values(attrs))
            cached[sha]=dict(structural_vector=vector[6:]+extra)
            samples[sha]=dict(feature_vector=vector,libraries=attrs['libraries'])
            if i<96:original.append(row)
            else:
                new.append(row);groups[sha]=('benign-software:app-'+str(i%4) if label==0 else 'malware-acquisition:batch-'+str(i%4))
        return original,new,cached,groups,samples,frozen

    def test_full_control_expansion_and_export_parity(self):
        fixture=self.fixture();original,new,cached,groups,samples,frozen=fixture
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            result=t.run_experiment(*fixture,path)
            self.assertTrue(result['completed']);self.assertEqual(result['feature_count'],72)
            self.assertEqual(result['original_samples'],96);self.assertEqual(result['new_samples'],40)
            self.assertEqual(len(result['group_holdouts']),4)
            self.assertTrue(all(v<1e-10 for m in result['models'].values() for v in m['export_parity'].values()))
            manifest=json.loads((path/'split_manifest.json').read_text())
            self.assertEqual(set(manifest['new_training'])|set(manifest['new_calibration']),{r['sha256'] for r in new})
            self.assertFalse({groups[s] for s in manifest['new_training']}&{groups[s] for s in manifest['new_calibration']})
            self.assertEqual(len(json.loads((path/'development-scores.json').read_text())),160)
            for model in result['models'].values():
                self.assertLessEqual(model['policies']['calibration']['fpr'],.01)
            # A sample below the original route is classified by the adapter,
            # even when its reviewer score is high.
            low=dict(new[0],adapter_probability=.1)
            self.assertEqual(t.gated([low],[.99],.5).tolist(),[0])

    def test_loader_rejects_labels_and_changed_reports(self):
        original,new,cached,groups,samples,cs=self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);audit=root/'audit';audit.mkdir();reports=root/'report.csv';reports.write_text('fixture')
            paths=['defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json',
                'validation-data/reviewer-v8-import-features-development/model.json',
                'validation-data/reviewer-v8-followup-development/imports-interval_midpoint-model.json']
            hashes={}
            for path,(_,payload) in zip(paths,cs.values()):
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(payload));hashes[path]=t.digest(target)
            coverage=[]
            for row in new:coverage.append(dict(row,source_id='windows',input_location='fixture'))
            manifest=root/'coverage.json';manifest.write_text(json.dumps(dict(complete=True,role='development',samples=coverage,
                counts=dict(unused_pe=len(coverage)),frozen_candidate_sha256=hashes)))
            records={}
            for row in original+new:
                sha=row['sha256'];entry=samples[sha];vector=entry['feature_vector'];flags=list(t.e._import_values({'libraries':entry['libraries']}))
                record=dict(row,adapter_threshold=.7)
                for name,(model,_) in cs.items():
                    score=t.c.reviewer_score(model,vector+(flags if name!='v7' else []))
                    routed,pred=t.c.verdict(score,model,row,.7)
                    record.update({name+'_score':score,name+'_prediction':pred,name+'_routed':routed})
                records[sha]=dict(entry,record=record)
            cachepath=audit/'docker-feature-cache.json'
            cachepath.write_text(json.dumps(dict(complete=True,samples=records)))
            (audit/'docker-audit-summary.json').write_text(json.dumps(dict(complete=True,total_docker_samples=len(records),frozen_candidate_sha256=hashes)))
            (audit/'run-inputs.json').write_text(json.dumps(dict(coverage_sha256=t.digest(manifest),report_sha256={'fixture':t.digest(reports)})))
            with patch.object(t.w,'ROOT',root),patch.object(t.w,'load_audit',return_value=([],{})),patch.object(t.w,'merge_training',return_value=(original,{'fixture':str(reports)})):
                loaded=t.load_data(audit,manifest,root)
                self.assertEqual((len(loaded[0]),len(loaded[1])),(96,40))
                changed=copy.deepcopy(records);first=new[0]['sha256'];changed[first]['record']['label']=1-new[0]['label']
                cachepath.write_text(json.dumps(dict(complete=True,samples=changed)))
                with self.assertRaisesRegex(ValueError,'label/SHA'):t.load_data(audit,manifest,root)
                cachepath.write_text(json.dumps(dict(complete=True,samples=records)));reports.write_text('changed')
                with self.assertRaisesRegex(ValueError,'reports changed'):t.load_data(audit,manifest,root)


if __name__=='__main__':unittest.main()
