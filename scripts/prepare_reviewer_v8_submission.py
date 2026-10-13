#!/usr/bin/env python3
"""Prepare an inference-only Python-3.11 context from existing inference arrays."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


CODE=('__init__.py','apps.py','signature_policy.py','submission_main.py','models/__init__.py',
      'models/attribute_extractor.py','models/boundary_reviewer.py','models/nfs_model.py',
      'models/compact_model.py','models/modern_adapter.py','models/portable_pipeline.py','models/portable_model.py')
ARRAYS=('metadata.json','offsets.npy','children_left.npy','children_right.npy','features.npy','thresholds.npy','malware_probability.npy','feature-pipeline.json')
MODEL_SHA='6dbe19e2f0962b4797ee5f58e17a37511b16dae94385253394e8f1add1df78be'


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verified_model_bytes(path):
    raw=Path(path).read_bytes()
    # Git autocrlf may change checkout newlines on Windows. Only accept bytes
    # that reproduce the frozen artifact exactly after CRLF-to-LF conversion.
    canonical=raw.replace(b'\r\n',b'\n')
    actual=hashlib.sha256(canonical).hexdigest()
    if actual!=MODEL_SHA:
        raise ValueError(f'Final v8 model hash differs: checkout={hashlib.sha256(raw).hexdigest()}, LF={actual}, expected={MODEL_SHA}')
    return canonical


def prepare(repo,artifacts,output):
    model=repo/'defender/defender/models/boundary_reviewer_v8_final/model.json'
    model_bytes=verified_model_bytes(model)
    proof=json.loads((artifacts/'compact/pipeline-export-summary.json').read_text())
    if proof.get('complete') is not True or proof['export_sha256']!=digest(artifacts/'compact/feature-pipeline.json'):
        raise ValueError('Portable pipeline export not verified')
    if output.exists() and any(output.iterdir()):raise ValueError('Output directory not empty')
    output.mkdir(parents=True,exist_ok=True)
    def copy(source,relative):
        destination=output/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination)
    for name in CODE:copy(repo/'defender/defender'/name,'app/defender/'+name)
    for name in ARRAYS:copy(artifacts/'compact'/name,'app/defender/models/compact/'+name)
    for name in ('metadata.json','coefficients.npy','intercept.npy'):
        copy(artifacts/'modern_adapter'/name,'app/defender/models/modern_adapter/'+name)
    for name in ('metadata.json','export-verification.json'):
        copy(model.parent/name,'app/defender/models/boundary_reviewer_v8_final/'+name)
    destination=output/'app/defender/models/boundary_reviewer_v8_final/model.json'
    destination.write_bytes(model_bytes)
    for name in ('Dockerfile','requirements.txt'):copy(repo/'submission'/name,name)
    files={str(path.relative_to(output)).replace('\\','/'):digest(path) for path in output.rglob('*') if path.is_file()}
    if len(list(output.rglob('Dockerfile')))!=1 or (output/'Dockerfile').stat().st_size>100*1024:raise ValueError('Dockerfile count/size invalid')
    manifest=dict(complete=True,role='submission_build_context',runtime_qualified=False,model_sha256=MODEL_SHA,
        preprocessing_export=proof,files=files,contains_samples=False,contains_legacy_pickle=False,
        pending='Clean build, restricted startup and raw-PE parity; confirm course-approved base-image pin.')
    (output/'submission-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(dict(context=str(output),files=len(files),model_sha256=MODEL_SHA)))


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--repo',type=Path,required=True)
    ap.add_argument('--artifacts',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();prepare(args.repo.resolve(),args.artifacts.resolve(),args.output.resolve())


if __name__=='__main__':main()
