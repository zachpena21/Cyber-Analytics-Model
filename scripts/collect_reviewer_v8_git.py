#!/usr/bin/env python3
"""Collect SHA-disjoint PEs from official PortableGit archives; never run their binaries."""
import argparse
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

import collect_reviewer_v8_fresh as c
import reviewer_v8_fresh_validation as f

RELEASES='https://api.github.com/repos/git-for-windows/git/releases?per_page=30'


def choose_releases(releases,count):
    chosen=[];minor=set()
    for release in releases:
        if release.get('draft') or release.get('prerelease'):continue
        tag=release['tag_name'];match=re.match(r'v(\d+\.\d+)\.',tag)
        if not match or match[1] in minor:continue
        assets=[a for a in release['assets'] if re.fullmatch(r'PortableGit-[0-9.]+-64-bit\.7z\.exe',a['name'])]
        if not assets:continue
        chosen.append((release,assets[0]));minor.add(match[1])
        if len(chosen)==count:break
    return chosen


def listed_members(text):
    result=[]
    for block in re.split(r'\r?\n\s*\r?\n',text):
        fields=dict(line.split(' = ',1) for line in block.splitlines() if ' = ' in line)
        if fields.get('Folder')=='+' or 'Path' not in fields or 'Size' not in fields:continue
        path=fields['Path'];size=int(fields['Size'])
        if Path(path.replace('\\','/')).suffix.casefold() not in ('.exe','.dll','.sys','.pyd'):continue
        if 0<size<=c.MAX_PE:result.append((path,size))
    return result


def run(args):
    import requests
    tool=shutil.which('7z') or shutil.which('7zz')
    if not tool:raise ValueError('Install the archive reader on the VM: sudo apt-get install p7zip-full')
    bundle,_,excluded=f.load_bundle(args.bundle)
    # Exclude every SHA already used in the frozen fresh evaluation too.
    evaluation=f.read(args.previous/'evaluation-manifest.json')
    if not evaluation.get('complete') or evaluation['freeze_manifest_sha256']!=f.t.digest(args.bundle/'freeze-manifest.json'):
        raise ValueError('Requires complete previous evaluation of this bundle')
    excluded.update(r['sha256'] for r in evaluation['samples'])
    f.fresh_output(args.output);args.output.mkdir(parents=True,exist_ok=True)
    result=dict(complete=False,started_utc=c.now(),freeze_manifest_sha256=f.t.digest(args.bundle/'freeze-manifest.json'),
        previous_evaluation_manifest_sha256=f.t.digest(args.previous/'evaluation-manifest.json'),
        requested_releases=args.releases,artifacts=[],samples=[],overlap_count=0,label=0,
        label_basis='Official Git for Windows release artifacts, SHA-256 verified against publisher release metadata; not independent vetting')
    sources=[]
    with requests.Session() as session:
        releases=json.loads(c.download(session,RELEASES,16*1024*1024,headers={'Accept':'application/vnd.github+json','User-Agent':'reviewer-v8-validation'}))
        choices=choose_releases(releases,args.releases)
        if not choices:raise ValueError('No stable x64 PortableGit assets found')
        for release,asset in choices:
            print(f'Downloading {asset["name"]}',flush=True)
            digest=asset.get('digest') or ''
            if not digest.startswith('sha256:'):
                raise ValueError('Publisher asset digest missing; do not collect unverified release artifacts')
            url=asset['browser_download_url']
            if not url.startswith('https://github.com/git-for-windows/git/releases/download/'):
                raise ValueError('Unexpected PortableGit publisher URL')
            data=c.download(session,url,256*1024*1024)
            if c.sha(data)!=digest[7:]:raise ValueError('PortableGit publisher digest mismatch')
            path=args.output/asset['name'];path.write_bytes(data)
            listing=subprocess.run([tool,'l','-slt','-ba',str(path)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout
            members=listed_members(listing);selected=[]
            for member,size in members:
                payload=subprocess.run([tool,'x','-so',str(path),member],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
                if len(payload)!=size:raise ValueError('Archive member byte size mismatch')
                if not c.is_pe(payload):continue
                sha=c.sha(payload)
                if sha in excluded:result['overlap_count']+=1;continue
                excluded.add(sha);selected.append((member,payload,sha))
            provenance=dict(release_tag=release['tag_name'],release_url=release['html_url'],
                published_at=release.get('published_at'),asset_url=url,asset_sha256=digest[7:],collected_utc=c.now())
            target=args.output/(release['tag_name']+'-selected.zip')
            if selected:
                with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED) as archive:
                    records=[]
                    for member,payload,sha in selected:
                        name='samples/'+sha+Path(member.replace('\\','/')).suffix.casefold()
                        archive.writestr(name,payload);records.append(dict(sha256=sha,label=0,
                            original_member=member,archive_member=name,byte_size=len(payload)))
                    archive.writestr('collection-manifest.json',json.dumps(dict(provenance=provenance,samples=records)))
                result['samples'].extend(records)
                sources.append(dict(path=str(target.resolve()),label=0,source_id='portablegit-'+release['tag_name'],provenance=provenance))
            result['artifacts'].append(dict(provenance=provenance,selected=len(selected),archive_pe_members=len(members)))
            f.w.dump(args.output/'collection-summary.json',result)
    result.update(complete=True,finished_utc=c.now(),unique_pe_count=len(result['samples']),actual_releases=len(choices))
    f.w.dump(args.output/'collection-summary.json',result)
    if not sources:raise ValueError('No SHA-disjoint PortableGit PEs found')
    f.w.dump(args.output/'sources.json',sources)
    print(f'Collected {len(result["samples"])} fresh benign Git/GNU PEs from {len(choices)} stable release lines')
    print(f'Send collection-summary.json from {args.output}')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-frozen-validation')
    ap.add_argument('--previous',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-evaluation')
    ap.add_argument('--output',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-git')
    ap.add_argument('--releases',type=int,default=2);args=ap.parse_args()
    try:
        if args.releases<1:raise ValueError('Release count must be positive')
        run(args)
    except Exception as error:ap.exit(2,f'Fresh Git collection stopped: {error}\n')


if __name__=='__main__':main()
