#!/usr/bin/env python3
"""Collect SHA-disjoint Windows wheels and MalwareBazaar archives for frozen validation."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import time
import zipfile

from packaging.version import Version, InvalidVersion
import reviewer_v8_fresh_validation as f

API='https://mb-api.abuse.ch/api/v1/'
PACKAGES=('scipy','numpy','scikit-learn','pandas','matplotlib','pillow','lxml','psutil')
MAX_PE=16*1024*1024


def now():return datetime.now(timezone.utc).isoformat()
def sha(data):return hashlib.sha256(data).hexdigest()


def is_pe(data):
    if len(data)<64 or data[:2]!=b'MZ':return False
    offset=struct.unpack_from('<I',data,0x3c)[0]
    return offset+24<=len(data) and data[offset:offset+4]==b'PE\0\0'


def download(session,url,limit,headers=None,data=None):
    method=session.post if data is not None else session.get
    with method(url,headers=headers,data=data,timeout=(15,120),stream=True) as response:
        response.raise_for_status()
        chunks=[];size=0
        for chunk in response.iter_content(1024*1024):
            size+=len(chunk)
            if size>limit:raise ValueError('Download exceeds byte limit')
            chunks.append(chunk)
        return b''.join(chunks)


def pypi_json(session,url):
    return json.loads(download(session,url,32*1024*1024))


def choose_wheels(metadata,abis,versions):
    available=[]
    for version,files in metadata['releases'].items():
        try:v=Version(version)
        except InvalidVersion:continue
        if v.is_prerelease or v.is_devrelease:continue
        chosen=[]
        for abi in abis:
            matches=[entry for entry in files if not entry.get('yanked')
                     and entry['filename'].endswith('-win_amd64.whl')
                     and ('-'+abi+'-'+abi+'-') in entry['filename']]
            if matches:chosen.append(sorted(matches,key=lambda e:e['filename'])[0])
        if chosen:available.append((v,version,chosen))
    # Prefer different minor versions to widen build coverage, then patches if needed.
    available.sort(reverse=True,key=lambda item:item[0]);selected=[];minor=set()
    for entry in available:
        key=entry[0].release[:2]
        if key not in minor:selected.append(entry);minor.add(key)
        if len(selected)==versions:break
    if len(selected)<versions:
        for entry in available:
            if entry not in selected:selected.append(entry)
            if len(selected)==versions:break
    return [(version,file) for _,version,files in selected for file in files]


def wheel_samples(content,excluded):
    records=[];seen=set();overlaps=set();oversize=0
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or Path(entry.filename).suffix.casefold() not in ('.pyd','.dll','.exe','.sys'):continue
            if entry.file_size>MAX_PE:oversize+=1;continue
            bytez=archive.read(entry)
            if not is_pe(bytez):continue
            digest=sha(bytez)
            if digest in excluded:overlaps.add(digest);continue
            if digest in seen:continue
            seen.add(digest);records.append((entry.filename,bytez,digest))
    return records,sorted(overlaps),oversize


def benign(args,excluded,freeze_hash):
    import requests
    directory=args.output/'benign';f.fresh_output(directory)
    directory.mkdir(parents=True,exist_ok=True)
    result=dict(complete=False,started_utc=now(),label=0,label_basis='Established package publishers via PyPI binary wheels; provenance-based label, not independent vetting',
                freeze_manifest_sha256=freeze_hash,packages=args.packages,abis=args.abis,
                artifacts=[],overlap_sha256=[],failures=[])
    remaining=args.max_download_mb*1024*1024
    with requests.Session() as session:
        for package in args.packages:
            metadata=pypi_json(session,f'https://pypi.org/pypi/{package}/json')
            choices=choose_wheels(metadata,args.abis,args.versions)
            if not choices:result['failures'].append(dict(package=package,error='No requested Windows ABI wheels'));continue
            for version,entry in choices:
                if entry['size']>remaining:
                    result['failures'].append(dict(package=package,version=version,error='Download budget exhausted'));continue
                url=entry['url']
                if not url.startswith('https://files.pythonhosted.org/'):
                    raise ValueError('Unexpected PyPI artifact host')
                print(f'Downloading {entry["filename"]}',flush=True)
                content=download(session,url,entry['size']+1024)
                remaining-=len(content)
                if sha(content)!=entry['digests']['sha256']:raise ValueError('PyPI wheel hash mismatch')
                records,overlaps,oversize=wheel_samples(content,excluded)
                result['overlap_sha256'].extend(overlaps)
                provenance=dict(package=package,version=version,wheel=entry['filename'],url=url,
                    wheel_sha256=sha(content),upload_time=entry.get('upload_time_iso_8601'),collected_utc=now())
                # Never install a wheel; store only verified PE members and their provenance.
                source_id=entry['filename'].removesuffix('.whl')
                path=directory/(source_id+'.zip')
                artifact=dict(provenance=provenance,source_id=source_id,sample_count=len(records),oversize_members=oversize)
                if records:
                    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED) as output:
                        members=[]
                        for original,bytez,digest in records:
                            name='samples/'+digest+Path(original).suffix.casefold();output.writestr(name,bytez)
                            members.append(dict(sha256=digest,original_member=original,archive_member=name,byte_size=len(bytez),label=0))
                        output.writestr('collection-manifest.json',json.dumps(dict(provenance=provenance,samples=members)))
                    artifact.update(path=str(path.resolve()),sha256=f.t.digest(path))
                result['artifacts'].append(artifact)
                f.w.dump(directory/'collection-summary.json',result)
    result.update(complete=True,finished_utc=now(),download_bytes=args.max_download_mb*1024*1024-remaining,
        unique_pe_count=count_unique_benign(result),overlap_sha256=sorted(set(result['overlap_sha256'])))
    f.w.dump(directory/'collection-summary.json',result)
    print(f'Benign collection: {result["unique_pe_count"]} unique fresh PEs; {len(result["failures"])} unavailable/budget-limited choices')
    if not result['unique_pe_count']:raise ValueError('No fresh benign PEs; choose additional ABIs/versions with a new output root')


def count_unique_benign(summary):
    seen=set()
    for artifact in summary['artifacts']:
        if not artifact.get('path'):continue
        with zipfile.ZipFile(artifact['path']) as archive:
            seen.update(r['sha256'] for r in json.loads(archive.read('collection-manifest.json'))['samples'])
    return len(seen)


def eligible_malware(metadata,excluded,since):
    digest=metadata.get('sha256_hash','')
    if not re.fullmatch('[0-9a-f]{64}',digest) or digest in excluded:return False
    if metadata.get('file_type') not in ('exe','dll','sys'):return False
    if not 0<int(metadata.get('file_size') or 0)<=MAX_PE:return False
    try:seen=datetime.fromisoformat(metadata['first_seen']).replace(tzinfo=timezone.utc)
    except (KeyError,ValueError):return False
    return seen>=since


def verify_malware(content,digest,zipclass):
    found=None
    with zipclass(io.BytesIO(content)) as archive:
        archive.setpassword(b'infected')
        for entry in archive.infolist():
            if entry.is_dir() or entry.file_size>MAX_PE:continue
            bytez=archive.read(entry)
            if sha(bytez)==digest:
                if not is_pe(bytez):raise ValueError('Metadata payload is not a PE')
                found=dict(archive_member=entry.filename,byte_size=len(bytez))
            elif is_pe(bytez):
                raise ValueError('Archive contains an unexpected additional PE')
    if found:return found
    raise ValueError('Downloaded archive does not contain the requested SHA')


def malware(args,excluded,freeze_hash):
    import requests
    import pyzipper
    key=next((os.environ[k] for k in ('MALWAREBAZAAR_AUTH_KEY','MALWAREBAZAAR_API_KEY','MB_API_KEY') if os.environ.get(k)),None)
    if not key:key=getpass.getpass('MalwareBazaar Auth-Key (hidden; never stored): ').strip()
    if not key:raise ValueError('An Auth-Key is required')
    directory=args.output/'malware'
    resume=getattr(args,'resume',False)
    if not resume:f.fresh_output(directory)
    directory.mkdir(parents=True,exist_ok=True)
    since=datetime.now(timezone.utc)-timedelta(days=args.days)
    result=dict(complete=False,started_utc=now(),label=1,label_basis='MalwareBazaar supplied labels; metadata retained for provenance review',
        freeze_manifest_sha256=freeze_hash,since_utc=since.isoformat(),target=args.count,samples=[],failures=[],queries=[])
    headers={'Auth-Key':key};pool={}
    if resume:
        result=f.read(directory/'collection-summary.json')
        if result['freeze_manifest_sha256']!=freeze_hash or result['target']!=args.count:
            raise ValueError('Resume requires the same frozen bundle and target count')
        for record in result['samples']:
            if f.t.digest(Path(record['path']))!=record['archive_sha256']:
                raise ValueError('Previously collected malware archive changed')
        since=datetime.fromisoformat(result['since_utc'])
        if (directory/'query-metadata.json').exists():
            pool={r['sha256_hash']:r for r in f.read(directory/'query-metadata.json')['eligible_samples']}
        result['complete']=False
    f.w.dump(directory/'collection-summary.json',result)
    with requests.Session() as session:
        for filetype in ([] if pool else args.file_types):
            query=dict(query='get_file_type',file_type=filetype,limit=1000)
            value=json.loads(download(session,API,32*1024*1024,headers,query))
            status=value.get('query_status')
            if status not in ('ok','no_results'):raise ValueError(f'MalwareBazaar metadata query failed: {status}')
            result['queries'].append(dict(parameters=query,status=status,returned=len(value.get('data') or [])))
            for entry in value.get('data') or []:
                if eligible_malware(entry,excluded,since):pool[entry['sha256_hash']]=entry
        f.w.dump(directory/'query-metadata.json',dict(queried_utc=now(),queries=result['queries'],eligible_samples=list(pool.values())))
        # Predetermined hash order avoids choosing by reviewer errors or family recall.
        order=sorted(pool,key=lambda s:sha(('704:'+s).encode()))
        collected={r['sha256'] for r in result['samples']}
        for digest in order:
            if len(result['samples'])>=args.count:break
            if digest in collected or digest in excluded:continue
            print(f'Downloading malware archive {len(result["samples"])+1}/{args.count}: {digest[:12]}',flush=True)
            try:
                content=download(session,API,32*1024*1024,headers,dict(query='get_file',sha256_hash=digest))
                details=verify_malware(content,digest,pyzipper.AESZipFile)
                path=directory/(digest+'.zip');path.write_bytes(content)
                result['samples'].append(dict(sha256=digest,label=1,path=str(path.resolve()),
                    archive_sha256=sha(content),metadata=pool[digest],collected_utc=now(),**details))
            except requests.HTTPError as error:
                # Stop on authentication, throttling, or server failures; don't hammer the API.
                result['failures'].append(dict(sha256=digest,error=f'HTTP {error.response.status_code}'))
                f.w.dump(directory/'collection-summary.json',result);raise ValueError('Download HTTP error; inspect collection-summary.json') from None
            except (ValueError,zipfile.BadZipFile,RuntimeError,NotImplementedError) as error:
                result['failures'].append(dict(sha256=digest,error=str(error)))
            f.w.dump(directory/'collection-summary.json',result)
            time.sleep(1)
    result.update(complete=True,finished_utc=now(),count=len(result['samples']),target_met=len(result['samples'])>=args.count,
        signature_counts=dict(Counter(r['metadata'].get('signature') or 'unknown' for r in result['samples'])))
    f.w.dump(directory/'collection-summary.json',result)
    print(f'Malware collection: {result["count"]}/{args.count} verified fresh PEs; target_met={result["target_met"]}')
    if not result['samples']:raise ValueError('No fresh malware PEs; widen --days with a new output root or collect later')


def sources(args,freeze_hash):
    benign_summary=f.read(args.output/'benign/collection-summary.json')
    malware_summary=f.read(args.output/'malware/collection-summary.json')
    rows=[]
    for summary in (benign_summary,malware_summary):
        if not summary.get('complete') or summary['freeze_manifest_sha256']!=freeze_hash:
            raise ValueError('Both collectors must complete against this frozen bundle')
    for artifact in benign_summary['artifacts']:
        if not artifact.get('path'):continue
        if f.t.digest(Path(artifact['path']))!=artifact['sha256']:raise ValueError('Collected benign archive changed')
        rows.append(dict(path=artifact['path'],label=0,source_id=artifact['source_id'],provenance=artifact['provenance']))
    for record in malware_summary['samples']:
        if f.t.digest(Path(record['path']))!=record['archive_sha256']:raise ValueError('Collected malware archive changed')
    rows.append(dict(path=str((args.output/'malware').resolve()),label=1,
        source_id='malwarebazaar-frozen-v8-fresh-'+malware_summary['started_utc'],
        provenance=dict(api=API,collected_utc=malware_summary['started_utc'],since_utc=malware_summary['since_utc'],
                        label_basis=malware_summary['label_basis'],metadata_path=str((args.output/'malware/collection-summary.json').resolve()))))
    f.w.dump(args.output/'sources.json',rows)
    print(f'Ready for evaluation: {args.output/"sources.json"}')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command',choices=('benign','malware','sources'))
    ap.add_argument('--bundle',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-frozen-validation')
    ap.add_argument('--output',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-acquisition')
    ap.add_argument('--packages',nargs='+',default=list(PACKAGES))
    ap.add_argument('--abis',nargs='+',default=['cp312'])
    ap.add_argument('--versions',type=int,default=2)
    ap.add_argument('--max-download-mb',type=int,default=1024)
    ap.add_argument('--count',type=int,default=200)
    ap.add_argument('--days',type=int,default=7)
    ap.add_argument('--resume',action='store_true',help='Resume malware collection only; checks prior archive hashes')
    ap.add_argument('--file-types',nargs='+',choices=('exe','dll','sys'),default=['exe','dll'])
    args=ap.parse_args()
    try:
        if min(args.versions,args.max_download_mb,args.count,args.days)<1:raise ValueError('Limits must be positive')
        if args.count>500:raise ValueError('Use at most 500 downloads per batch')
        if any(not re.fullmatch('cp3[0-9]+',a) for a in args.abis):raise ValueError('Expected ABI such as cp312')
        _,_,excluded=f.load_bundle(args.bundle);freeze_hash=f.t.digest(args.bundle/'freeze-manifest.json')
        if args.resume and args.command!='malware':raise ValueError('--resume is for malware collection only')
        if args.command=='sources':sources(args,freeze_hash)
        else:(benign if args.command=='benign' else malware)(args,excluded,freeze_hash)
    except Exception as error:ap.exit(2,f'Fresh collection stopped: {error}\n')


if __name__=='__main__':main()
