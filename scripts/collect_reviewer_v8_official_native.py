#!/usr/bin/env python3
"""Collect unused large native Windows PE candidates from official release archives."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import time
from urllib.parse import urlparse, quote
import zipfile

from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import reviewer_v8_pe_metadata as pe

MAX_PE=16*1024*1024
MAX_ARCHIVE=256*1024*1024
MAX_UNPACKED=1024*1024*1024
CATALOG=(('cli/cli','v1.14.0'),('cli/cli','v2.0.0'),('cli/cli','v2.14.0'),
         ('containerd/containerd','v1.7.13'),('containerd/containerd','v1.7.28'),
         ('moby/buildkit','v0.13.2'),('moby/buildkit','v0.16.0'))
GO_MINORS=('1.20','1.21','1.22','1.23','1.24','1.25')
HOSTS={'api.github.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com','go.dev','dl.google.com'}


def digest(data):return hashlib.sha256(data).hexdigest()
def file_hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def read(path):return json.loads(Path(path).read_text())
def dump(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.tmp');tmp.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n');tmp.replace(path)
def now():return datetime.now(timezone.utc).isoformat()
def checked_url(url):
    p=urlparse(url)
    if p.scheme!='https' or p.hostname not in HOSTS or p.username or p.password:raise ValueError('Unexpected release URL: '+url)
    return url


def download(url,path,limit,expected=None):
    """Bounded retries; completed hash-verified assets are reused on resume."""
    checked_url(url);path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_file():
        if path.stat().st_size>limit or (expected and file_hash(path)!=expected):raise ValueError('Saved download changed: '+str(path))
        return path
    temporary=path.with_suffix(path.suffix+'.part')
    for attempt in range(3):
        try:
            start=time.monotonic();h=hashlib.sha256();count=0
            with urlopen(Request(url,headers={'User-Agent':'reviewer-v8-development-collection'}),timeout=45) as response:
                checked_url(response.geturl())
                if int(response.headers.get('Content-Length','0'))>limit:raise ValueError('Download exceeds byte limit')
                with temporary.open('wb') as output:
                    while True:
                        block=response.read(1024*1024)
                        if not block:break
                        count+=len(block)
                        if count>limit or time.monotonic()-start>300:raise ValueError('Download byte/time bound exceeded')
                        output.write(block);h.update(block)
            if expected and h.hexdigest()!=expected:raise ValueError('Published SHA-256 mismatch: '+url)
            temporary.replace(path);return path
        except (URLError,TimeoutError,ConnectionError) as error:
            status=getattr(error,'code',None)
            if status==404 or attempt==2:raise
            print(f'Network retry {attempt+1}/2 for {url}: {type(error).__name__}',flush=True);time.sleep(2*(attempt+1))
    raise AssertionError('Unreachable')


def metadata(url,output):
    path=output/'release-metadata'/(digest(url.encode())+'.json')
    download(url,path,12*1024*1024)
    return read(path),path


def published_checksum(text,filename):
    for line in text.splitlines():
        match=re.fullmatch(r'([0-9a-fA-F]{64})\s+\*?(.+)',line.strip())
        if match and Path(match[2]).name==filename:return match[1].lower()
    if re.fullmatch(r'[0-9a-fA-F]{64}',text.strip()):return text.strip().lower()
    return None


def discover(output):
    assets=[];warnings=[];bindings={}
    releases,path=metadata('https://go.dev/dl/?mode=json&include=all',output);bindings[str(path)]=file_hash(path)
    for minor in GO_MINORS:
        available=[r for r in releases if re.fullmatch('go'+re.escape(minor)+r'\.\d+',r['version'])]
        if not available:warnings.append('No Go '+minor+' release in official catalog');continue
        release=max(available,key=lambda r:int(r['version'].rsplit('.',1)[1]))
        for f in release['files']:
            if f['os']=='windows' and f['arch']=='amd64' and f['kind']=='archive' and f['filename'].endswith('.zip'):
                assets.append(dict(package='Go',version=release['version'],filename=f['filename'],size=f['size'],
                    url='https://go.dev/dl/'+f['filename'],sha256=f['sha256'],checksum_basis='Official Go download catalog SHA-256'))
    for repo,tag in CATALOG:
        try:release,path=metadata('https://api.github.com/repos/'+repo+'/releases/tags/'+quote(tag,safe=''),output)
        except HTTPError as error:
            if error.code==404:warnings.append(repo+' '+tag+': release unavailable');continue
            raise
        bindings[str(path)]=file_hash(path)
        if release.get('draft') or release.get('prerelease'):raise ValueError('Expected stable public release')
        matches=[a for a in release['assets'] if re.search(r'windows[._-](?:amd64|x86_64)',a['name'],re.I) and a['name'].endswith(('.zip','.tar.gz'))]
        if not matches:warnings.append(repo+' '+tag+': no Windows amd64 archive');continue
        for a in matches:
            prefix='https://github.com/'+repo+'/releases/download/'+tag+'/'
            if not a['browser_download_url'].startswith(prefix):raise ValueError('Asset is outside official release')
            sha=a.get('digest') or '';sha=sha[7:] if sha.startswith('sha256:') else ''
            basis='Official GitHub release asset SHA-256'
            if not re.fullmatch('[0-9a-f]{64}',sha):
                sha=None
                checks=[b for b in release['assets'] if b['name'] in (a['name']+'.sha256sum',a['name']+'.sha256') or 'checksums' in b['name'].lower() and not b['name'].endswith(('.sig','.pem','.json'))]
                for b in checks:
                    if not b['browser_download_url'].startswith(prefix) or b['size']>1024*1024:continue
                    path=output/'release-metadata'/(digest(b['browser_download_url'].encode())+'.txt')
                    download(b['browser_download_url'],path,1024*1024);bindings[str(path)]=file_hash(path)
                    sha=published_checksum(path.read_text(),a['name'])
                    if sha:break
                basis='Official release checksum file SHA-256'
            if not sha:warnings.append(repo+' '+tag+' '+a['name']+': no published SHA-256; skipped');continue
            if a['size']>MAX_ARCHIVE:warnings.append(a['name']+': exceeds archive size limit');continue
            assets.append(dict(package=repo,version=tag,filename=a['name'],size=a['size'],url=a['browser_download_url'],sha256=sha,checksum_basis=basis))
    assets=[a for a in assets if 0<a['size']<=MAX_ARCHIVE]
    for a in assets:
        if Path(a['filename']).name!=a['filename'] or not re.fullmatch('[0-9a-f]{64}',a['sha256']):raise ValueError('Invalid published asset identity')
    if not assets:raise ValueError('No checksum-bound official archives discovered')
    return dict(assets=assets,warnings=warnings,metadata_sha256=bindings,catalog=[list(x) for x in CATALOG],go_minors=list(GO_MINORS))


def exclusions(args):
    paths=sorted(set(p.resolve() for p in (args.exclude or list(args.root.rglob('excluded-sha256.json')))))
    if not paths:raise ValueError('No excluded-sha256.json found; supply --exclude')
    values=set();bindings={}
    for path in paths:
        data=read(path)
        if not isinstance(data,list) or any(not isinstance(k,str) or re.fullmatch('[0-9a-f]{64}',k) is None for k in data):raise ValueError('Invalid SHA exclusion list: '+str(path))
        values.update(data);bindings[str(path)]=file_hash(path)
    return values,bindings


def verify(bindings):
    for path,sha in bindings.items():
        if file_hash(path)!=sha:raise ValueError('Input changed: '+path)


def members(path):
    """Read bounded PE bytes; never extract paths or execute downloaded programs."""
    total=0;count=0
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                count+=1;total+=item.file_size
                if count>50000 or total>MAX_UNPACKED:raise ValueError('Archive expansion bound exceeded')
                if item.is_dir() or not item.filename.lower().endswith(('.exe','.dll')) or not 8*1024*1024<=item.file_size<=MAX_PE:continue
                if (item.external_attr>>16)&0o170000==0o120000:continue
                yield item.filename,archive.read(item)
    else:
        with tarfile.open(path,'r:gz') as archive:
            for item in archive:
                count+=1;total+=item.size
                if count>50000 or total>MAX_UNPACKED:raise ValueError('Archive expansion bound exceeded')
                if not item.isfile() or not item.name.lower().endswith(('.exe','.dll')) or not 8*1024*1024<=item.size<=MAX_PE:continue
                with archive.extractfile(item) as stream:data=stream.read(MAX_PE+1)
                if len(data)!=item.size:raise ValueError('Archive member size differs')
                yield item.name,data


def pattern(info):
    if not info['valid_pe'] or not info['imports_complete'] or info['clr_metadata_valid'] or info.get('machine')!=0x8664:return None
    size=info['byte_size'];sections=info['section_count'];libs=len(info['imports'])
    if 10*1024*1024<=size<=MAX_PE and 8<=sections<=10 and libs<=1:return 'large_native'
    if 8*1024*1024<=size<=MAX_PE and 6<=sections<=12 and libs<=4:return 'large_native_adjacent'
    return None


def inspect_asset(asset,path,excluded,seen,max_samples):
    candidates=[];overlaps=[];stats=Counter();local_seen=set(seen)
    for name,data in members(path):
        stats['bounded_large_pe_members']+=1
        info=pe.extract(data);kind=pattern(info)
        if not kind:stats['outside_target_shape']+=1;continue
        sha=digest(data)
        if sha in excluded:overlaps.append(sha);continue
        if sha in local_seen:stats['duplicate_sha']+=1;continue
        local_seen.add(sha)
        candidates.append((0 if kind=='large_native' else 1,name,sha,data,info,kind))
    candidates.sort(key=lambda x:(x[0],x[1],x[2]));selected=candidates[:max_samples]
    stats['eligible_unused']=len(candidates);stats['selected']=len(selected)
    return selected,sorted(set(overlaps)),dict(stats)


def run(args):
    if args.resume:args.output=args.resume
    if not args.resume:
        if args.output.exists() and any(args.output.iterdir()):raise ValueError('Output directory must be new or empty')
        args.output.mkdir(parents=True,exist_ok=True)
    elif not args.output.is_dir():raise ValueError('Resume directory does not exist')
    print('Output: '+str(args.output),flush=True)
    excluded,bindings=exclusions(args)
    modules=[Path(__file__).resolve(),Path(pe.__file__).resolve()]
    bindings.update({str(p):file_hash(p) for p in modules})
    marker=args.output/'collection-inputs.json'
    acquired=read(marker)['collected_utc'] if marker.is_file() else now()
    identity=dict(input_sha256=bindings,collected_utc=acquired,excluded_count=len(excluded),max_download_mb=args.max_download_mb,
        per_asset=args.per_asset,pattern_rules='Exact: native AMD64 10–16 MiB, 8–10 sections, <=1 imported DLL. Adjacent: 8–16 MiB, 6–12 sections, <=4 DLLs. Complete static import parse; no valid CLR.')
    marker=args.output/'collection-inputs.json'
    if marker.is_file():
        if read(marker)!=identity:raise ValueError('Resume exclusions/settings/script changed')
    else:dump(marker,identity)
    completion=args.output/'completion.json'
    if completion.is_file():
        verify(read(completion)['artifact_sha256']);verify(bindings)
        report=read(args.output/'official-native-collection-summary.json')
        print(f'Completed collection verified: {report["unique_new_samples"]} new samples.\nSend official-native-collection-summary.json.',flush=True)
        return
    plan_path=args.output/'release-plan.json'
    if plan_path.is_file():plan=read(plan_path);verify(plan['metadata_sha256'])
    else:
        plan=discover(args.output);dump(plan_path,plan)
    bindings.update(plan['metadata_sha256']);bindings[str(plan_path)]=file_hash(plan_path)
    sources=[];artifacts=[];seen=set();overlaps=set();reports=[];errors=[];budget=args.max_download_mb*1024*1024
    for asset in plan['assets']:
        key=digest(asset['url'].encode())[:16];download_path=args.output/'downloads'/(key+'-'+asset['filename'])
        print(asset['package']+' '+asset['version']+': inspecting '+asset['filename'],flush=True)
        if asset['size']>budget:
            reports.append(dict(asset=asset,status='download_budget_skipped'));continue
        budget-=asset['size']
        try:
            download(asset['url'],download_path,asset['size'],asset['sha256']);bindings[str(download_path)]=asset['sha256']
            selected,old,stats=inspect_asset(asset,download_path,excluded,seen,args.per_asset);overlaps.update(old)
            provenance=dict(package=asset['package'],product_directory=asset['package'],release_version=asset['version'],
                asset_url=asset['url'],asset_sha256=asset['sha256'],checksum_basis=asset['checksum_basis'],checksum_verified=True,
                collected_utc=acquired,acquisition_kind='official_release_archive',development_only=True,
                label_basis='Official project release binary; provenance-based benign candidate, not independently verified',signature_verified=False)
            zip_path=args.output/(key+'-samples.zip');kept=[]
            if selected:
                with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                    for _,name,sha,data,info,kind in selected:
                        if sha in seen:continue
                        seen.add(sha);member='samples/'+sha+Path(name).suffix.lower();item=zipfile.ZipInfo(member,date_time=(1980,1,1,0,0,0));item.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(item,data)
                        kept.append(dict(sha256=sha,label=0,byte_size=len(data),pattern=kind,metadata=info,
                            original_path=asset['url']+'!/'+name,original_member=name,archive_member=member))
                    item=zipfile.ZipInfo('collection-manifest.json',date_time=(1980,1,1,0,0,0));item.compress_type=zipfile.ZIP_DEFLATED
                    archive.writestr(item,json.dumps(dict(provenance=provenance,samples=kept)))
                sources.append(dict(path=str(zip_path.resolve()),label=0,source_id=key,provenance=provenance,acquired_at=provenance['collected_utc'],development_only=True))
                artifacts.append(dict(path=str(zip_path.resolve()),sha256=file_hash(zip_path),sample_count=len(kept),product_cohort=asset['package'],by_pattern=dict(Counter(row['pattern'] for row in kept))))
            reports.append(dict(asset=asset,status='inspected',overlap_count=len(old),**stats))
        except (URLError,OSError,ValueError,tarfile.TarError,zipfile.BadZipFile) as error:
            errors.append(dict(asset=asset,error=type(error).__name__,message=str(error)))
            print('Asset failed; remaining releases will continue: '+str(error),flush=True)
        # Persist useful progress even when another release times out.
        dump(args.output/'official-native-collection-summary.json',dict(complete=False,unique_new_samples=len(seen),assets=reports,errors=errors))
    verify(bindings)
    summary=dict(complete=not errors,role='targeted_benign_development_inventory',training=False,independent_validation=False,
        candidate_count=sum(r.get('eligible_unused',0)+r.get('overlap_count',0) for r in reports),unique_new_samples=len(seen),
        historical_overlaps=len(overlaps),overlap_sha256=sorted(overlaps),product_cohorts=len(artifacts),
        distinct_projects=len({a['product_cohort'] for a in artifacts}),by_pattern=dict(sum((Counter(a['by_pattern']) for a in artifacts),Counter())),artifacts=artifacts)
    dump(args.output/'sources.json',sources);dump(args.output/'targeted-benign-inventory-summary.json',summary)
    dump(args.output/'inputs.json',dict(input_sha256=bindings))
    report=dict(summary,excluded_sha_count=len(excluded),planned_assets=len(plan['assets']),assets=reports,errors=errors,
        discovery_warnings=plan['warnings'],signature_verified=False,model_changes=False,
        limits='Targeted development acquisition; versions from one project are not independent software families. Published checksums verify transfer integrity, not independent benign labels. No samples executed.')
    dump(args.output/'official-native-collection-summary.json',report)
    print(f'New samples: {len(seen)}; exact pattern: {summary["by_pattern"].get("large_native",0)}; adjacent: {summary["by_pattern"].get("large_native_adjacent",0)}\nSend official-native-collection-summary.json.',flush=True)
    if errors:raise ValueError('Some assets failed; resume the printed output directory to retry. Successful downloads are retained.')
    outputs=[args.output/name for name in ('collection-inputs.json','release-plan.json','sources.json','inputs.json','targeted-benign-inventory-summary.json','official-native-collection-summary.json')]
    outputs.extend(Path(a['path']) for a in artifacts)
    dump(completion,dict(complete=True,artifact_sha256={**bindings,**{str(p):file_hash(p) for p in outputs}}))


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--exclude',type=Path,action='append',help='Default: union of all known excluded-sha256.json under validation-data')
    ap.add_argument('--output',type=Path);ap.add_argument('--resume',type=Path)
    ap.add_argument('--max-download-mb',type=int,default=1024);ap.add_argument('--per-asset',type=int,default=8)
    args=ap.parse_args();args.root=root
    if args.output and args.resume:ap.error('Use either --output or --resume')
    if not 1<=args.max_download_mb<=4096 or not 1<=args.per_asset<=32:ap.error('Download budget must be 1–4096 MiB; per-asset limit 1–32')
    args.output=(args.output or root/('reviewer-v8-official-native-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))).resolve()
    if args.resume:args.resume=args.resume.resolve()
    try:run(args)
    except Exception as error:ap.exit(2,f'Official native collection stopped: {error}\n')


if __name__=='__main__':main()
