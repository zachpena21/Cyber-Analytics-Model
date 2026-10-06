#!/usr/bin/env python3
"""Recover static version/import metadata from hash-matched archived blockers."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import traceback
import zipfile
import reviewer_v8_pe_metadata as pe
import reviewer_v8_rich_pattern_coverage as p

cache=p.cache


def run(args):
    import pyzipper
    if args.coverage is None:
        options=[x for x in args.root.glob('reviewer-v8-rich-pattern-coverage-*') if
            (x/'rich-pattern-coverage-summary.json').is_file() and cache.read(x/'rich-pattern-coverage-summary.json').get('complete') is True]
        if not options:raise ValueError('No completed pattern coverage; supply --coverage')
        args.coverage=max(options,key=lambda x:((x/'rich-pattern-coverage-summary.json').stat().st_mtime_ns,str(x)))
    binding=cache.read(args.coverage/'inputs.json');cache.verify_hashes(binding['input_sha256']);cache.verify_hashes(binding['original_input_sha256'])
    prior=cache.read(args.coverage/'rich-pattern-coverage-summary.json')
    if not prior.get('complete'):raise ValueError('Incomplete coverage audit')
    profile=cache.read(Path(binding['profile'])/'rich-blocker-profile-summary.json')
    targets=set(prior['blockers']);locations={profile['samples'][sha]['recovered_location'] for sha in targets}
    args.output.mkdir(parents=True,exist_ok=True)
    if any(args.output.iterdir()):raise ValueError('Output must be new or empty')
    result=dict(complete=False,role='static_blocker_identity_metadata',training=False,model_changes=False,samples={},
        requested_samples=len(targets),limitations='Version strings are unverified file claims. Certificate-directory presence is not signature verification. Files remain inherited benign labels. No sample execution or relabeling.')
    warnings=[];hashes={}
    for location in sorted(locations):
        path=Path(location);print('Reading blocker metadata: '+str(path),flush=True)
        hashes[str(path)]=cache.digest(path)
        if not zipfile.is_zipfile(path):raise ValueError('Expected cached archive: '+str(path))
        with pyzipper.AESZipFile(str(path)) as archive:
            for data,chain,member,usable in p.named_archive_payloads(archive,pyzipper.AESZipFile,warnings,str(path)):
                sha=hashlib.sha256(data).hexdigest()
                if sha not in targets:continue
                result['samples'][sha]=dict(sha256=sha,archive_member_chain=chain,original_path=prior['blockers'][sha]['recorded_original_path'],
                    label=prior['blockers'][sha]['label'],source=prior['blockers'][sha]['source'],metadata=pe.extract(data))
                cache.dump(args.output/'blocker-metadata-summary.json',result)
    missing=sorted(targets-set(result['samples']))
    result.update(complete=True,all_required_sha_covered=not missing,missing_sha256=missing,archive_warning_count=len(warnings),
        files_with_version_strings=sum(bool(x['metadata']['version_strings']) for x in result['samples'].values()),
        claimed_products=dict(Counter(value for x in result['samples'].values() for value in x['metadata']['version_strings'].get('ProductName',[]))))
    cache.dump(args.output/'blocker-metadata-summary.json',result);cache.dump(args.output/'archive-read-warnings.json',warnings)
    hashes[str(args.coverage/'rich-pattern-coverage-summary.json')]=cache.digest(args.coverage/'rich-pattern-coverage-summary.json')
    hashes[str(args.coverage/'inputs.json')]=cache.digest(args.coverage/'inputs.json');hashes[str(Path(__file__))]=cache.digest(__file__);hashes[str(Path(pe.__file__))]=cache.digest(pe.__file__)
    cache.dump(args.output/'inputs.json',dict(input_sha256=hashes,parser_version=pe.VERSION))
    print(f'Complete: {args.output}\nSHA coverage: {len(result["samples"])}/{len(targets)}\nSend blocker-metadata-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--coverage',type=Path);ap.add_argument('--debug',action='store_true')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-blocker-metadata-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')))
    args=ap.parse_args();args.root=root
    try:run(args)
    except Exception as e:
        if args.debug:traceback.print_exc()
        raise SystemExit(f'Blocker metadata stopped: {e}')


if __name__=='__main__':main()
