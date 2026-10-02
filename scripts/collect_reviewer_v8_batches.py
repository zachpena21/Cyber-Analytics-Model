#!/usr/bin/env python3
"""MalwareBazaar hourly datalake fallback; no MalwareBazaar API calls."""
import argparse
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import re
import zipfile

import collect_reviewer_v8_fresh as c
import reviewer_v8_fresh_validation as f

INDEX='https://datalake.abuse.ch/malware-bazaar/hourly/'


def batch_names(html,hours):
    cutoff=datetime.now(timezone.utc)-timedelta(hours=hours)
    names=set(re.findall(r'href=[\"\'](\d{4}-\d{2}-\d{2}-\d{2}\.zip)[\"\']',html))
    return sorted((n for n in names if cutoff<=datetime.strptime(n[:-4],'%Y-%m-%d-%H').replace(tzinfo=timezone.utc)
                   <=datetime.now(timezone.utc)),reverse=True)


def select_members(archive,excluded,limit):
    selected=[];seen=set(excluded);counts=dict(oversize=0,non_pe=0,overlap=0,hash_mismatch=0)
    entries=sorted((e for e in archive.infolist() if not e.is_dir()),
                   key=lambda e:c.sha(('704:'+e.filename).encode()))
    for entry in entries:
        if len(selected)>=limit:break
        name=Path(entry.filename).name
        match=re.fullmatch(r'([0-9a-fA-F]{64})(?:\.[A-Za-z0-9]+)?',name)
        if match and match[1].lower() in seen:counts['overlap']+=1;continue
        if entry.file_size>c.MAX_PE:counts['oversize']+=1;continue
        data=archive.read(entry)
        if not c.is_pe(data):counts['non_pe']+=1;continue
        digest=c.sha(data)
        if match and digest!=match[1].lower():
            counts['hash_mismatch']+=1;raise ValueError('Batch member SHA differs from its advertised hash filename')
        if digest in seen:counts['overlap']+=1;continue
        seen.add(digest);selected.append((entry.filename,data,digest))
    return selected,counts


def write_sources(root,result,output):
    benign=f.read(root/'benign/collection-summary.json')
    if not benign.get('complete') or benign['freeze_manifest_sha256']!=result['freeze_manifest_sha256']:
        raise ValueError('Complete matching benign collection is required')
    rows=[]
    for artifact in benign['artifacts']:
        if not artifact.get('path'):continue
        if f.t.digest(Path(artifact['path']))!=artifact['sha256']:raise ValueError('Benign archive changed')
        rows.append(dict(path=artifact['path'],label=0,source_id=artifact['source_id'],provenance=artifact['provenance']))
    for record in result['samples']:
        if f.t.digest(Path(record['path']))!=record['archive_sha256']:raise ValueError('Selected malware archive changed')
    rows.append(dict(path=str((root/'malware-batches').resolve()),label=1,
        source_id='malwarebazaar-hourly-'+result['started_utc'],
        provenance=dict(index=INDEX,batches=[b['url'] for b in result['batches']],
            collected_utc=result['started_utc'],label_basis=result['label_basis'],
            metadata_note='No API family/first-seen metadata available; batch hour is not verified sample first-seen time.')))
    f.w.dump(output,rows)


def collect(args):
    import requests
    import pyzipper
    _,_,excluded=f.load_bundle(args.bundle);freeze_hash=f.t.digest(args.bundle/'freeze-manifest.json')
    root=args.output;directory=root/'malware-batches';cache=root/'batch-downloads'
    if not args.resume:f.fresh_output(directory)
    directory.mkdir(parents=True,exist_ok=True);cache.mkdir(parents=True,exist_ok=True)
    result=dict(complete=False,started_utc=c.now(),freeze_manifest_sha256=freeze_hash,target=args.count,
        label_basis='MalwareBazaar official hourly malware exports; labels retained from source; no independent vetting',
        samples=[],batches=[],failures=[],download_bytes=0)
    # Preserve any already collected API samples and avoid collecting them again.
    existing=root/'malware/collection-summary.json'
    if existing.exists():
        prior=f.read(existing)
        if prior['freeze_manifest_sha256']!=freeze_hash:raise ValueError('Prior API collection uses a different frozen bundle')
        for row in prior['samples']:
            if f.t.digest(Path(row['path']))!=row['archive_sha256']:raise ValueError('Prior API archive changed')
            excluded.add(row['sha256'])
    if args.resume:
        result=f.read(directory/'collection-summary.json')
        if result['freeze_manifest_sha256']!=freeze_hash or result['target']!=args.count:
            raise ValueError('Resume requires the same bundle and target')
        for row in result['samples']:
            if f.t.digest(Path(row['path']))!=row['archive_sha256']:raise ValueError('Selected batch archive changed')
        result['complete']=False
    excluded.update(r['sha256'] for r in result['samples'])
    f.w.dump(directory/'collection-summary.json',result)
    with requests.Session() as session:
        if 'planned_batches' not in result:
            html=c.download(session,INDEX,2*1024*1024).decode('utf-8')
            result['planned_batches']=batch_names(html,args.hours)
            f.w.dump(directory/'collection-summary.json',result)
        finished={b['name'] for b in result['batches']}
        for name in result['planned_batches']:
            if len(result['samples'])>=args.count:break
            if name in finished:continue
            url=INDEX+name;path=cache/name
            print(f'Downloading hourly batch {name}; selected {len(result["samples"])}/{args.count}',flush=True)
            try:
                if not path.exists():
                    remaining=args.max_download_mb*1024*1024-result['download_bytes']
                    if remaining<=0:print('Download budget reached',flush=True);break
                    data=c.download(session,url,min(args.max_batch_mb*1024*1024,remaining))
                    temporary=cache/(name+'.part');temporary.write_bytes(data);temporary.replace(path)
                    result['download_bytes']+=len(data)
                    f.w.dump(directory/'collection-summary.json',result)
                with pyzipper.AESZipFile(path) as archive:
                    archive.setpassword(b'infected')
                    selected,counts=select_members(archive,excluded,args.count-len(result['samples']))
                batch_digest=f.t.digest(path)
                for original,data,digest in selected:
                    target=directory/(digest+'.zip')
                    temporary=cache/(digest+'.selected.part')
                    with pyzipper.AESZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as output:
                        output.setpassword(b'infected');output.writestr(digest+'.exe',data)
                    temporary.replace(target)
                    excluded.add(digest)
                    result['samples'].append(dict(sha256=digest,label=1,path=str(target.resolve()),
                        archive_sha256=f.t.digest(target),byte_size=len(data),original_member=original,
                        batch_url=url,batch_archive_sha256=batch_digest,collected_utc=c.now()))
                    f.w.dump(directory/'collection-summary.json',result)
                result['batches'].append(dict(name=name,url=url,archive_sha256=batch_digest,
                    selected=len(selected),filter_counts=counts))
            except requests.HTTPError as error:
                if error.response.status_code not in (404,500,502,503,504):raise
                result['failures'].append(dict(batch=name,error=f'HTTP {error.response.status_code}'))
                print(f'Skipping unavailable batch {name}',flush=True)
            except (requests.Timeout,requests.ConnectionError) as error:
                result['failures'].append(dict(batch=name,error=type(error).__name__))
                f.w.dump(directory/'collection-summary.json',result)
                raise ValueError('Datalake network failed too; progress saved. Retry with --resume or diagnose VM connectivity.') from None
            except ValueError as error:
                # Size-budget failures are safe to skip; hash/PE provenance failures must stop.
                if 'Download exceeds byte limit' not in str(error):raise
                result['failures'].append(dict(batch=name,error='Batch exceeds download cap'))
            f.w.dump(directory/'collection-summary.json',result)
    result.update(complete=True,finished_utc=c.now(),count=len(result['samples']),target_met=len(result['samples'])>=args.count)
    f.w.dump(directory/'collection-summary.json',result)
    if not result['samples']:raise ValueError('No fresh PE samples collected; inspect collection-summary.json')
    write_sources(root,result,root/'batch-sources.json')
    print(f'Collected {len(result["samples"])} fresh batch PEs; target_met={result["target_met"]}')
    print(f'Ready: {root/"batch-sources.json"}; send {directory/"collection-summary.json"}')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-frozen-validation')
    ap.add_argument('--output',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-acquisition')
    ap.add_argument('--count',type=int,default=200)
    ap.add_argument('--hours',type=int,default=48)
    ap.add_argument('--max-download-mb',type=int,default=1024)
    ap.add_argument('--max-batch-mb',type=int,default=256)
    ap.add_argument('--resume',action='store_true')
    ap.add_argument('--connect-timeout',type=float,default=20.)
    ap.add_argument('--read-timeout',type=float,default=120.)
    ap.add_argument('--attempts',type=int,default=2)
    args=ap.parse_args()
    try:
        if min(args.count,args.hours,args.max_download_mb,args.max_batch_mb,args.connect_timeout,args.read_timeout,args.attempts)<=0:
            raise ValueError('Limits must be positive')
        c.NETWORK.update(connect_timeout=args.connect_timeout,read_timeout=args.read_timeout,attempts=args.attempts)
        collect(args)
    except Exception as error:ap.exit(2,f'Hourly batch collection stopped: {error}\n')


if __name__=='__main__':main()
