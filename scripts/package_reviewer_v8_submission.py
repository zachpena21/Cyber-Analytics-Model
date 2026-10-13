#!/usr/bin/env python3
"""Verify the tested context and create a single-Dockerfile submission ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
import prepare_reviewer_v8_submission as prepare


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()


def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def package(repo,work):
    context=work/'context';manifest=read(context/'submission-manifest.json')
    preflight=read(work/'submission-preflight-summary.json');smoke=read(work/'runtime-parity-summary.json')
    regression=read(repo/'submission/runtime-validation.json');resources=read(work/'submission-resource-summary.json')
    if not preflight['complete'] or not smoke['passed'] or not regression['passed']:raise ValueError('Runtime evidence incomplete')
    if preflight['clean_build_seconds']>300 or preflight['restricted_startup_seconds']>25:raise ValueError('Build/startup timing failed')
    if resources['image_id']!=preflight['image_id'] or resources['oom_killed']:raise ValueError('Image identity/OOM check failed')
    if resources['memory_limit_bytes']!=1073741824 or not resources['readonly'] or resources['nano_cpus']!=1000000000:
        raise ValueError('Diagnostic resource configuration differs')
    peak=resources.get('cgroup_peak_bytes')
    if peak is not None and peak>=1073741824:raise ValueError('Measured peak reaches the memory cap; inspect resource report')
    files={str(p.relative_to(context)).replace('\\','/') for p in context.rglob('*') if p.is_file()}
    if files!=set(manifest['files'])|{'submission-manifest.json'}:raise ValueError('Unexpected/missing build-context files')
    for relative,expected in manifest['files'].items():
        if digest(context/relative)!=expected:raise ValueError('Context changed: '+relative)
    for name in prepare.CODE:
        source=repo/'defender/defender'/name;staged=context/'app/defender'/name
        if source.read_bytes().replace(b'\r\n',b'\n')!=staged.read_bytes().replace(b'\r\n',b'\n'):
            raise ValueError('Staged code is stale: '+name+'; rerun preflight')
    for name in ('Dockerfile','requirements.txt'):
        if (repo/'submission'/name).read_bytes().replace(b'\r\n',b'\n')!=(context/name).read_bytes().replace(b'\r\n',b'\n'):
            raise ValueError('Staged build definition is stale: '+name)
    model=context/'app/defender/models/boundary_reviewer_v8_final/model.json'
    if digest(model)!=prepare.MODEL_SHA or regression['model_sha256']!=prepare.MODEL_SHA:raise ValueError('Final model identity differs')
    dockerfiles=list(context.rglob('Dockerfile'))
    if len(dockerfiles)!=1 or dockerfiles[0].stat().st_size>102400:raise ValueError('Dockerfile count/size failed')
    output=work/'reviewer-v8-submission.zip'
    if output.exists():raise ValueError('Submission ZIP already exists; preserve it before packaging again')
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1) as archive:
        for relative in sorted(files):archive.write(context/relative,relative)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:raise ValueError('ZIP integrity failed')
    summary=dict(complete=True,zip_name=output.name,zip_sha256=digest(output),zip_bytes=output.stat().st_size,
        image_id=preflight['image_id'],model_sha256=prepare.MODEL_SHA,dockerfile_count=1,contains_samples=False,
        raw_pe_regression=regression,resources=resources,clean_build_seconds=preflight['clean_build_seconds'],
        restricted_startup_seconds=preflight['restricted_startup_seconds'],diagnostics_disabled=preflight['diagnostics_disabled'],
        course_base_pin_confirmed=preflight.get('course_base_pin_confirmed',False),
        submission_ready=False,pending='Review current course base-image requirements against the tested python:3.11-slim template; runtime evidence covers supplied regression samples only.')
    (work/'submission-package-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'zip':str(output),'sha256':summary['zip_sha256'],'bytes':summary['zip_bytes'],'summary':str(work/'submission-package-summary.json')}))


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--repo',type=Path,required=True);ap.add_argument('--work',type=Path,required=True)
    args=ap.parse_args();package(args.repo,args.work)


if __name__=='__main__':main()
