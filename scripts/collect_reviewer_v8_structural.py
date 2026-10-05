#!/usr/bin/env python3
"""Collect post-freeze Windows wheels and hourly malware for structural validation."""
import argparse
from pathlib import Path
import re
from types import SimpleNamespace

import collect_reviewer_v8_fresh as wheels
import collect_reviewer_v8_batches as batches
import reviewer_v8_structural_validation as v


def sources(args,manifest):
    root=args.output;freeze_hash=v.g.digest(args.bundle/'freeze-manifest.json')
    benign=v.f.read(root/'benign/collection-summary.json');malware=v.f.read(root/'malware-batches/collection-summary.json')
    rows=[]
    for summary in (benign,malware):
        if not summary.get('complete') or summary['freeze_manifest_sha256']!=freeze_hash:
            raise ValueError('Both collectors must complete against this exact structural freeze')
        v.check_acquisitions([dict(acquired_at=summary['started_utc'])],manifest['frozen_at'])
    for artifact in benign['artifacts']:
        if not artifact.get('path'):continue
        if v.g.digest(Path(artifact['path']))!=artifact['sha256']:raise ValueError('Benign archive changed')
        rows.append(dict(path=artifact['path'],label=0,source_id=artifact['source_id'],provenance=artifact['provenance'],
                         acquired_at=artifact['provenance']['collected_utc']))
    for sample in malware['samples']:
        if v.g.digest(Path(sample['path']))!=sample['archive_sha256']:raise ValueError('Malware archive changed')
        v.check_acquisitions([dict(acquired_at=sample['collected_utc'])],manifest['frozen_at'])
    if not rows or not malware['samples']:raise ValueError('Need nonempty benign and malware acquisitions')
    rows.append(dict(path=str((root/'malware-batches').resolve()),label=1,
        source_id='malwarebazaar-hourly-'+malware['started_utc'],acquired_at=malware['started_utc'],
        provenance=dict(index=batches.INDEX,batches=[x['url'] for x in malware['batches']],
            label_basis=malware['label_basis'],metadata_path=str((root/'malware-batches/collection-summary.json').resolve()),
            note='Acquisition time is recorded locally; batch hour does not prove first-seen date or family independence.')))
    v.check_acquisitions(rows,manifest['frozen_at']);v.w.dump(root/'sources.json',rows)
    print(f'Ready for frozen structural evaluation: {root/"sources.json"}',flush=True)


def run(args):
    manifest,_,_,_,excluded=v.load_bundle(args.bundle)
    if min(args.versions,args.count,args.hours,args.max_download_mb,args.max_batch_mb,args.connect_timeout,args.read_timeout,args.attempts)<=0:
        raise ValueError('Collection limits must be positive')
    if args.count>500:raise ValueError('Use at most 500 selected malware samples per collection')
    if any(not re.fullmatch('cp3[0-9]+',x) for x in args.abis):raise ValueError('Expected ABI such as cp313')
    if args.resume and args.command!='malware':raise ValueError('--resume is for hourly malware collection only')
    wheels.NETWORK.update(connect_timeout=args.connect_timeout,read_timeout=args.read_timeout,attempts=args.attempts)
    freeze_hash=v.g.digest(args.bundle/'freeze-manifest.json')
    if args.command=='benign':
        v.check_acquisitions([dict(acquired_at=wheels.now())],manifest['frozen_at'])
        wheels.benign(args,excluded,freeze_hash)
    elif args.command=='malware':
        benign=v.f.read(args.output/'benign/collection-summary.json')
        if not benign.get('complete') or benign['freeze_manifest_sha256']!=freeze_hash:
            raise ValueError('Run matching benign collection first')
        v.check_acquisitions([dict(acquired_at=benign['started_utc'])],manifest['frozen_at'])
        if args.resume:
            prior=v.f.read(args.output/'malware-batches/collection-summary.json')
            v.check_acquisitions([dict(acquired_at=prior['started_utc'])],manifest['frozen_at'])
        # Give the existing collector a local compatibility facade. Do not replace
        # the shared legacy loader: the structural loader uses it for v7 references.
        previous=batches.f
        batches.f=SimpleNamespace(read=v.f.read,w=v.w,t=v.f.t,fresh_output=v.f.fresh_output,
                                 load_bundle=lambda path:(manifest,{},set(excluded)))
        try:batches.collect(args)
        finally:batches.f=previous
        sources(args,manifest)
    else:sources(args,manifest)


def main():
    root=v.w.ROOT/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command',choices=('benign','malware','sources'))
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path,default=root/'reviewer-v8-structural-fresh-acquisition')
    ap.add_argument('--packages',nargs='+',default=list(wheels.PACKAGES))
    ap.add_argument('--abis',nargs='+',default=['cp313'])
    ap.add_argument('--versions',type=int,default=2);ap.add_argument('--count',type=int,default=200)
    ap.add_argument('--hours',type=int,default=48);ap.add_argument('--max-download-mb',type=int,default=1024)
    ap.add_argument('--max-batch-mb',type=int,default=256);ap.add_argument('--resume',action='store_true')
    ap.add_argument('--connect-timeout',type=float,default=20.);ap.add_argument('--read-timeout',type=float,default=120.)
    ap.add_argument('--attempts',type=int,default=2);args=ap.parse_args()
    try:run(args)
    except Exception as error:ap.exit(2,f'Structural fresh collection stopped: {error}\n')


if __name__=='__main__':main()
