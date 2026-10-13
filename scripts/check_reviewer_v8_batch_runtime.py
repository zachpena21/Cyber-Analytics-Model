#!/usr/bin/env python3
"""Bounded raw-PE migration parity from existing benign/malware archives; no fits."""
import argparse
import hashlib
import io
import itertools
import json
from pathlib import Path
import time
import zipfile

import check_reviewer_v8_runtime_parity as parity


def payloads(path, reader, warnings, depth=0):
    if depth>8:raise ValueError('Nested ZIP depth exceeds eight')
    if isinstance(path,Path):
        if path.is_dir():
            for child in sorted(path.rglob('*')):
                if child.is_file():yield from payloads(child,reader,warnings,depth)
            return
        with path.open('rb') as stream:header=stream.read(2)
        if header==b'MZ':
            if path.stat().st_size<=16777216:yield str(path),path.read_bytes()
            else:warnings.append(dict(path=str(path),error='PE exceeds 16 MiB service limit'))
            return
        source=str(path)
        if not zipfile.is_zipfile(source):return
    else:source=path
    with reader(source) as archive:
        for entry in archive.infolist():
            if entry.filename.endswith('/'):continue
            origin=str(getattr(archive,'filename',None) or '<nested>')+'!/'+entry.filename
            # Bound decompression before allocating a member in memory.
            if entry.file_size>67108864:
                warnings.append(dict(path=origin,error='Archive member exceeds 64 MiB scan limit'));continue
            try:data=archive.read(entry,pwd=b'infected')
            except Exception as error:
                warnings.append(dict(path=origin,error=str(error)));continue
            if data[:2]==b'MZ':
                if len(data)<=16777216:yield origin,data
                else:warnings.append(dict(path=origin,error='PE exceeds 16 MiB service limit'))
            elif zipfile.is_zipfile(io.BytesIO(data)):
                yield from payloads(io.BytesIO(data),reader,warnings,depth+1)


def run(args):
    import pyzipper
    model=json.loads(args.model.read_text());rows=[];warnings=[];seen=set()
    reference=args.reference.rstrip('/');candidate=args.candidate.rstrip('/')
    old_info=parity.request(reference+'/model');new_info=parity.request(candidate+'/model')
    if not old_info.get('score_endpoint_enabled') or not new_info.get('score_endpoint_enabled'):
        raise ValueError('Both diagnostic services must be enabled')
    if (new_info.get('reviewer_route_min')!=model['route_min']
            or new_info.get('reviewer_threshold')!=model['reviewer_threshold']):
        raise ValueError('Candidate routing/threshold differs')
    counts={};timings=[]
    malware_paths=args.malware or sorted(Path(__file__).resolve().parents[1].joinpath('validation-data').glob('malwarebazaar*-final-*'))
    if not malware_paths:raise ValueError('No existing MalwareBazaar batches found; pass --malware with paths')
    sources={'benign':[args.benign],'malware':malware_paths}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    def save(complete):
        ordered=sorted(timings)
        report=dict(complete=complete,passed=complete and all(row['pass_'] for row in rows)
                    and all(n==args.limit for n in counts.values()) and len(counts)==2,
            per_class_target=args.limit,counts=counts,sample_count=len(rows),source_paths={role:list(map(str,paths)) for role,paths in sources.items()},
            max_abs_error=max((row['max_abs_error'] for row in rows),default=0.),
            candidate_http_latency_seconds=dict(max=max(ordered,default=0.),
                p95=ordered[min(len(ordered)-1,int(.95*len(ordered)))] if ordered else 0.),
            rows=rows,archive_warnings=warnings,reference_model=old_info,candidate_model=new_info,
            training=False,scope='Deterministic bounded runtime regression cohort from existing data, not independent accuracy validation. HTTP timings include VM network and diagnostic serialization.')
        temporary=args.output.with_suffix('.tmp');temporary.write_text(json.dumps(report,indent=2)+'\n');temporary.replace(args.output)
        return report
    try:
        for role,paths in sources.items():
            for path in paths:
                if not path.exists():raise FileNotFoundError(path)
            counts[role]=0
            streams=(payloads(path,pyzipper.AESZipFile,warnings) for path in paths)
            for origin,raw in itertools.chain.from_iterable(streams):
                sha=hashlib.sha256(raw).hexdigest()
                if sha in seen:continue
                seen.add(sha)
                try:
                    old=parity.request(reference+'/diagnostics/score?include_features=1',raw)
                    start=time.perf_counter()
                    new=parity.request(candidate+'/diagnostics/score?include_features=1',raw)
                    seconds=time.perf_counter()-start;timings.append(seconds)
                    result=parity.compare(old,new,model)
                    result['candidate_http_seconds']=seconds
                except Exception as error:
                    result=dict(pass_=False,max_abs_error=0.,changed_fields=['request_or_parser_failure'],error=str(error))
                rows.append(dict(role=role,path=origin,sha256=sha,bytes=len(raw),**result));counts[role]+=1
                save(False)
                print(f"{role} {counts[role]}/{args.limit}: {sha[:12]} "+('PASS' if result['pass_'] else 'FAIL '+','.join(result['changed_fields'])),flush=True)
                if counts[role]>=args.limit:break
        report=save(True)
    except BaseException:
        save(False);raise
    if not report['passed']:raise ValueError('Bounded parity/coverage failed; see '+str(args.output))
    print('PASS: '+str(args.output))


def main():
    root=Path(__file__).resolve().parents[1]
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',required=True);ap.add_argument('--candidate',required=True)
    ap.add_argument('--benign',type=Path,default=root/'validation-data/benign-final-6.zip')
    ap.add_argument('--malware',type=Path,nargs='+',help='Existing batch paths; defaults to sorted validation-data/malwarebazaar*-final-*')
    ap.add_argument('--model',type=Path,default=root/'defender/defender/models/boundary_reviewer_v8_final/model.json')
    ap.add_argument('--limit',type=int,default=64);ap.add_argument('--output',type=Path,default=root/'validation-data/v8-batch-runtime-parity-summary.json')
    args=ap.parse_args()
    if args.limit<1:ap.error('--limit must be positive')
    run(args)


if __name__=='__main__':main()
