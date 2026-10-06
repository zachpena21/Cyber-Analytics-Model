#!/usr/bin/env python3
"""Stage installed Windows benign candidates and inventory them on the VM."""
import argparse
from collections import Counter,defaultdict
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import zipfile
import reviewer_v8_pe_metadata as pe

MAX_PE=16*1024*1024
RULES=dict(tiny_managed='Valid CLR metadata; <=8 KiB; <=3 sections; <=1 DLL import.',
    large_native='No valid CLR metadata; 10–16 MiB; 8–10 sections; <=1 DLL import.',
    managed_no_imports='Valid CLR metadata; 64–512 KiB; no DLL imports.',control='Other valid installed PE.')


def now():return datetime.now(timezone.utc).isoformat()
def digest(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def dump(path,data):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(data,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def fresh(path):
    if path.exists() and any(path.iterdir()):raise ValueError('Output directory must be new or empty')
    path.mkdir(parents=True,exist_ok=True)


def category(info):
    if not info['valid_pe'] or not info['imports_complete']:return None
    size=info['byte_size'];clr=info['clr_metadata_valid'];libs=info['imports']
    if clr and size<=8192 and info['section_count']<=3 and len(libs)<=1:return 'tiny_managed'
    if not clr and 10*1024*1024<=size<=MAX_PE and 8<=info['section_count']<=10 and len(libs)<=1:return 'large_native'
    if clr and 64*1024<=size<=512*1024 and not libs:return 'managed_no_imports'
    return 'control'


def candidate_paths(roots):
    seen=set()
    for root in roots:
        root=root.resolve()
        if not root.is_dir():continue
        for directory,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=sorted(d for d in dirs if not (Path(directory)/d).is_symlink()
                and not getattr(Path(directory)/d,'is_junction',lambda:False)())
            for name in sorted(files):
                path=Path(directory)/name
                if path.suffix.lower() not in ('.exe','.dll') or path.is_symlink():continue
                canonical=str(path.resolve()).casefold()
                if canonical in seen:continue
                seen.add(canonical)
                # Product-directory provenance is independent of filename/version claims.
                relative=path.relative_to(root)
                product=relative.parts[0] if len(relative.parts)>1 else root.name
                yield root,product,path


def artifact_name(product):
    return re.sub('[^a-zA-Z0-9._-]+','-',product).strip('-')[:60]+'-'+digest(product.encode())[:10]+'.zip'


def collect(args):
    if os.name!='nt':raise ValueError('collect runs on Windows; use inventory on the VM')
    roots=args.scan_root or [Path(p) for p in dict.fromkeys(os.environ.get(k,'') for k in
        ('ProgramFiles','ProgramFiles(x86)')) if p]
    if not roots:raise ValueError('No scan roots; supply --scan-root')
    if not any(root.is_dir() for root in roots):raise ValueError('No scan roots exist')
    fresh(args.output);started=now();pool=defaultdict(lambda:defaultdict(list));warnings=[];seen=set();scanned=0;last=time.monotonic()
    for root,product,path in candidate_paths(roots):
        scanned+=1
        if time.monotonic()-last>=10:
            print(f'Scanned {scanned} files; eligible candidates {len(seen)}',flush=True);last=time.monotonic()
        try:
            size=path.stat().st_size
            if not 64<=size<=MAX_PE:continue
            likely=size<=8192 or 64*1024<=size<=512*1024 or size>=10*1024*1024
            if not likely and len(pool[product]['control'])>=args.controls_per_product:continue
            data=path.read_bytes()
            if len(data)!=size or len(data)>MAX_PE:raise ValueError('File size changed while reading')
            info=pe.extract(data);kind=category(info)
            if kind is None:continue
            limit=args.controls_per_product if kind=='control' else args.per_pattern_product
            if len(pool[product][kind])>=limit:continue
            sha=digest(data)
            if sha in seen:continue
            seen.add(sha);pool[product][kind].append(dict(sha256=sha,original_path=str(path),original_member=str(path.relative_to(root)),
                byte_size=size,label=0,pattern=kind,metadata=info,scan_root=str(root),product_cohort=product))
        except Exception as e:warnings.append(dict(path=str(path),error=type(e).__name__,message=str(e)))
    # Round-robin by product, targets before controls; sample/budget caps are not score-driven.
    queues={product:[row for kind in ('tiny_managed','large_native','managed_no_imports','control') for row in kinds[kind]]
            for product,kinds in sorted(pool.items())};selected=defaultdict(list);budget=args.max_bytes_mb*1024*1024;count=0
    while any(queues.values()) and count<args.max_samples:
        for product,queue in queues.items():
            if not queue or count>=args.max_samples:continue
            row=queue.pop(0)
            if row['byte_size']>budget:continue
            budget-=row['byte_size'];count+=1;selected[product].append(row)
    artifacts=[]
    for product,rows in selected.items():
        path=args.output/artifact_name(product);members=[]
        provenance=dict(package='installed:'+product,product_directory=product,collected_utc=started,
            acquisition_kind='local_installed_windows',development_only=True,
            label_basis='User-selected installed application roots; provenance-based candidate label, not independently verified',
            metadata_strings_are_unverified=True,signature_verified=False)
        with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED) as archive:
            for row in rows:
                data=Path(row['original_path']).read_bytes()
                if digest(data)!=row['sha256']:raise ValueError('Selected file changed: '+row['original_path'])
                member='samples/'+row['sha256']+Path(row['original_path']).suffix.lower()
                archive.writestr(member,data);members.append(dict(row,archive_member=member))
            archive.writestr('collection-manifest.json',json.dumps(dict(provenance=provenance,samples=members)))
        artifacts.append(dict(path=path.name,sha256=digest(path.read_bytes()),provenance=provenance,
            sample_count=len(members),by_pattern=dict(Counter(r['pattern'] for r in members))))
    summary=dict(complete=True,role='targeted_benign_development_candidates',started_utc=started,finished_utc=now(),
        scanned_files=scanned,candidate_samples=len(seen),sample_count=count,product_cohorts=len(artifacts),artifacts=artifacts,
        by_pattern=dict(Counter(row['pattern'] for rows in selected.values() for row in rows)),
        historical_overlap_checked=False,training=False,pattern_rules=RULES,parser_version=pe.VERSION,
        script_sha256=digest(Path(__file__).read_bytes()),parser_sha256=digest(Path(pe.__file__).read_bytes()),
        scan_roots=[str(root) for root in roots],warning_count=len(warnings))
    dump(args.output/'collection-summary.json',summary);dump(args.output/'collection-warnings.json',warnings)
    print(f'Collected {count} candidates from {len(artifacts)} product directories: {args.output}\nCopy this whole directory to VM validation-data, then run inventory. Historical overlaps have not yet been checked.',flush=True)


def inventory(args):
    exclusions=read(args.exclude)
    if not isinstance(exclusions,list) or any(not isinstance(s,str) or re.fullmatch('[0-9a-f]{64}',s) is None for s in exclusions):
        raise ValueError('Exclusions must be the development excluded-sha256.json list')
    excluded=set(exclusions);prior=read(args.collection/'collection-summary.json')
    if not prior.get('complete') or prior['role']!='targeted_benign_development_candidates':raise ValueError('Incomplete candidate collection')
    fresh(args.output);sources=[];artifacts=[];overlap=[];seen=set();patterns=Counter();hashes={str(args.exclude):digest(args.exclude.read_bytes())}
    for artifact in prior['artifacts']:
        name=artifact['path']
        if Path(name).name!=name:raise ValueError('Collection archive path must be a basename')
        path=args.collection/name
        if digest(path.read_bytes())!=artifact['sha256']:raise ValueError('Collection archive hash mismatch: '+name)
        hashes[str(path)]=artifact['sha256'];kept=[]
        with zipfile.ZipFile(path) as archive:
            manifest=json.loads(archive.read('collection-manifest.json'))
            if manifest['provenance']!=artifact['provenance'] or len(manifest['samples'])!=artifact['sample_count']:
                raise ValueError('Collection manifest mismatch')
            with zipfile.ZipFile(args.output/name,'x',compression=zipfile.ZIP_DEFLATED) as output:
                for row in manifest['samples']:
                    info=archive.getinfo(row['archive_member'])
                    if not 0<info.file_size<=MAX_PE:raise ValueError('Member size exceeds PE limit')
                    data=archive.read(info)
                    if digest(data)!=row['sha256'] or len(data)!=row['byte_size'] or row['label']!=0:raise ValueError('Candidate SHA/size/label mismatch')
                    metadata=pe.extract(data)
                    if category(metadata)!=row['pattern']:raise ValueError('Candidate pattern mismatch')
                    if row['sha256'] in excluded:overlap.append(row['sha256']);continue
                    if row['sha256'] in seen:continue
                    seen.add(row['sha256']);output.writestr(row['archive_member'],data);kept.append(row);patterns[row['pattern']]+=1
                output.writestr('collection-manifest.json',json.dumps(dict(provenance=manifest['provenance'],samples=kept)))
        output_path=args.output/name
        if not kept:output_path.unlink();continue
        provenance=manifest['provenance'];source_id=Path(name).stem
        sources.append(dict(path=str(output_path.resolve()),label=0,source_id=source_id,provenance=provenance,
                            acquired_at=provenance['collected_utc'],development_only=True))
        artifacts.append(dict(path=str(output_path.resolve()),sha256=digest(output_path.read_bytes()),sample_count=len(kept),
            product_cohort=provenance['product_directory'],by_pattern=dict(Counter(row['pattern'] for row in kept))))
    summary=dict(complete=True,role='targeted_benign_development_inventory',training=False,independent_validation=False,
        candidate_count=prior['sample_count'],unique_new_samples=len(seen),historical_overlaps=len(set(overlap)),
        overlap_sha256=sorted(set(overlap)),product_cohorts=len(artifacts),by_pattern=dict(patterns),artifacts=artifacts,
        limits='Product-directory cohorts are acquisition evidence, not verified independent build or software families. Diagnostic static imports must be checked against Docker extraction before training.')
    hashes[str(args.collection/'collection-summary.json')]=digest((args.collection/'collection-summary.json').read_bytes())
    dump(args.output/'sources.json',sources);dump(args.output/'targeted-benign-inventory-summary.json',summary)
    dump(args.output/'inputs.json',dict(input_sha256=hashes,script_sha256=digest(Path(__file__).read_bytes()),parser_sha256=digest(Path(pe.__file__).read_bytes())))
    print(f'New samples: {len(seen)}; historical overlaps: {len(set(overlap))}; product cohorts: {len(artifacts)}\nSend {args.output/"targeted-benign-inventory-summary.json"}.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    c=sub.add_parser('collect');c.add_argument('--scan-root',type=Path,action='append');c.add_argument('--per-pattern-product',type=int,default=10)
    c.add_argument('--controls-per-product',type=int,default=3);c.add_argument('--max-samples',type=int,default=400);c.add_argument('--max-bytes-mb',type=int,default=500)
    c.add_argument('--output',type=Path,default=root/('reviewer-v8-targeted-benign-windows-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')))
    i=sub.add_parser('inventory');i.add_argument('--collection',type=Path,required=True);i.add_argument('--exclude',type=Path,required=True)
    i.add_argument('--output',type=Path,default=root/('reviewer-v8-targeted-benign-inventory-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')))
    args=ap.parse_args()
    if args.command=='collect' and (min(args.per_pattern_product,args.max_samples,args.max_bytes_mb)<1 or args.controls_per_product<0):ap.error('Use positive target/budget limits and nonnegative controls')
    try:(collect if args.command=='collect' else inventory)(args)
    except Exception as e:raise SystemExit(f'Targeted benign workflow stopped: {e}')


if __name__=='__main__':main()
