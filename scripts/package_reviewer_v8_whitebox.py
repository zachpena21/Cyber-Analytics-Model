#!/usr/bin/env python3
"""Create the standalone whitebox ZIP from the hash-verified blackbox package."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import zipfile

SOURCE_SHA = '0205b5eefae26075e3d8d12c6987647c9dc594d693734ebbffce5defe52f26a2'
MODEL_SHA = 'a9e350a04f77ff912486d45f9813b04dd686d5cae6661debd6eed316838d06e5'
MODEL_DIR = 'app/defender/models/boundary_reviewer_v8_whitebox_t060/'
REMOVE_PREFIX = 'app/defender/models/boundary_reviewer_v8_final/'
README = '''# V8 whitebox malware defense

Extract this ZIP and run from the folder containing Dockerfile:

    docker build -t blackbox-defense:v8-whitebox-rescue .
    docker run --rm -p 127.0.0.1:8080:8080 --read-only --memory 1g --cpus 1 --cap-drop ALL --security-opt no-new-privileges blackbox-defense:v8-whitebox-rescue

The service listens on container port 8080. POST raw PE bytes to / using
Content-Type: application/octet-stream. Response: {"result": 0} for benign or
{"result": 1} for malware. GET /healthz and GET /model expose service status.
Diagnostics are disabled by default. No external model files, repository,
training data, network service, or volume mounts are needed for inference.
Build requires internet access to install the pinned dependencies.

For restricted grading, use the grader's prescribed launch command. A
--network none container can be checked internally using docker exec; it is
not reachable through a published host port.

This package contains the threshold-0.60 frozen reviewer plus the verified
agreement rescue rule. The disclosed TA set was used for tuning and achieved
50/50 malware detections with zero benign errors in the tested overlay runtime.
No malware samples are included. Standalone clean-build/resource qualification
must be recorded separately for this exact ZIP.
'''


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def file_bytes(path):
    return Path(path).read_bytes().replace(b'\r\n', b'\n')


def assemble(repo, source, output):
    if output.exists():
        raise ValueError('Output ZIP already exists; preserve prior artifacts')
    if digest(source) != SOURCE_SHA:
        raise ValueError('Source is not the verified blackbox submission ZIP')
    replacements = {'README.md': README.encode()}
    for name in ('apps.py', 'reviewer_rescue.py', 'whitebox_main.py'):
        replacements['app/defender/'+name] = file_bytes(repo/'defender/defender'/name)
    for name in ('model.json', 'metadata.json'):
        replacements[MODEL_DIR+name] = file_bytes(repo/'defender/defender/models/boundary_reviewer_v8_whitebox_t060'/name)
    if hashlib.sha256(replacements[MODEL_DIR+'model.json']).hexdigest() != MODEL_SHA:
        raise ValueError('Candidate model hash differs')
    with zipfile.ZipFile(source) as old:
        names = old.namelist()
        if len(set(names)) != len(names):
            raise ValueError('Duplicate source members')
        manifest = json.loads(old.read('submission-manifest.json'))
        if set(names) != set(manifest['files']) | {'submission-manifest.json'}:
            raise ValueError('Source manifest member coverage differs')
        for name, expected in manifest['files'].items():
            if hashlib.sha256(old.read(name)).hexdigest() != expected:
                raise ValueError('Source member hash differs: '+name)
        docker = old.read('Dockerfile')
        before = b'CMD ["python", "-m", "defender.submission_main"]'
        if docker.count(before) != 1:
            raise ValueError('Unexpected source Docker entrypoint')
        replacements['Dockerfile'] = docker.replace(before, b'CMD ["python", "-m", "defender.whitebox_main"]')
        kept = {n for n in names if n != 'submission-manifest.json'
                and n != 'app/defender/submission_main.py' and not n.startswith(REMOVE_PREFIX)}
        target_names = kept | set(replacements)
        files = {n: hashlib.sha256(replacements[n]).hexdigest() if n in replacements else manifest['files'][n]
                 for n in target_names}
        new_manifest = dict(complete=True, role='whitebox_submission_build_context', runtime_qualified=False,
            source_blackbox_zip_sha256=SOURCE_SHA, reviewer_model_sha256=MODEL_SHA,
            contains_samples=False, contains_legacy_pickle=False, files=dict(sorted(files.items())),
            inference_policy='Frozen t060 reviewer plus agreement rescue; original forest/adapter/preprocessing retained.',
            pending='Clean build, restricted startup, public raw-PE scoring and resource checks for this exact standalone ZIP.')
        replacements['submission-manifest.json'] = (json.dumps(new_manifest, indent=2)+'\n').encode()
        target_names.add('submission-manifest.json')
        for name in target_names:
            p = PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or '\\' in name:
                raise ValueError('Unsafe archive name')
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for name in sorted(target_names):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                if name in replacements:
                    archive.writestr(info, replacements[name], compresslevel=1)
                else:
                    with old.open(name) as src, archive.open(info, 'w') as dest:
                        shutil.copyfileobj(src, dest, 1048576)
    verification = verify(output)
    result = dict(complete=True, zip_name=output.name, zip_sha256=digest(output), zip_bytes=output.stat().st_size,
        source_blackbox_zip_sha256=SOURCE_SHA, reviewer_model_sha256=MODEL_SHA,
        verification=verification, standalone_runtime_qualified=False,
        prior_overlay_ta_result=dict(malware_detected=50, benign_correct=50, errors=0),
        pending='Run qualify_reviewer_v8_whitebox.ps1 against this exact ZIP before submission.')
    output.with_suffix('.summary.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def verify(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if z.testzip() is not None or len(names) != len(set(names)):
            raise ValueError('ZIP integrity/member uniqueness failed')
        if [n for n in names if PurePosixPath(n).name == 'Dockerfile'] != ['Dockerfile']:
            raise ValueError('Expected exactly one root Dockerfile')
        manifest = json.loads(z.read('submission-manifest.json'))
        if set(names) != set(manifest['files']) | {'submission-manifest.json'}:
            raise ValueError('Whitebox manifest coverage differs')
        for name, sha in manifest['files'].items():
            if hashlib.sha256(z.read(name)).hexdigest() != sha:
                raise ValueError('Whitebox member hash differs: '+name)
        if any(n.startswith(REMOVE_PREFIX) or n.endswith('/submission_main.py') for n in names):
            raise ValueError('Old reviewer/entrypoint retained unexpectedly')
        if any(n.endswith(('.exe', '.dll', '.bin', '.pkl', '.gz')) for n in names):
            raise ValueError('Unexpected sample/pickle/archive member')
        if hashlib.sha256(z.read(MODEL_DIR+'model.json')).hexdigest() != MODEL_SHA:
            raise ValueError('Packaged model hash differs')
        if b'defender.whitebox_main' not in z.read('Dockerfile'):
            raise ValueError('Whitebox entrypoint is not configured')
        for name in names:
            if name.endswith('.py'):
                compile(z.read(name), name, 'exec')
        return dict(zip_integrity=True, file_hashes_verified=len(manifest['files']),
                    dockerfile_count=1, python_sources_compile=True, old_reviewer_removed=True,
                    contains_samples=False, dependencies_unchanged=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(assemble(args.repo, args.source, args.output), indent=2))


if __name__ == '__main__':
    main()
