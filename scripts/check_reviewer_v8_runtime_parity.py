#!/usr/bin/env python3
"""Compare real PE extraction and cascade decisions with the v7 diagnostic reference."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import urllib.request


IMPORTS=('ntoskrnl.exe','hal.dll','ndis.sys','wdfldr.sys','ks.sys')


def request(url,data=None):
    headers={'Content-Type':'application/octet-stream'} if data is not None else {}
    with urllib.request.urlopen(urllib.request.Request(url,data=data,headers=headers),timeout=60) as response:return json.load(response)


def model_score(model,vector):
    # IEEE float32 round-trip without numpy, preserving double split thresholds.
    import struct
    values=[struct.unpack('f',struct.pack('f',float(v)))[0] for v in vector];leaves=[]
    for tree in model['estimators']:
        node=0
        while tree['children_left'][node]>=0:
            node=tree['children_left' if values[tree['feature'][node]]<=tree['threshold'][node] else 'children_right'][node]
        leaves.append(tree['raw_value'][node])
    raw=model['initial_raw_score']+model['learning_rate']*sum(leaves)
    return 1/(1+math.exp(-raw)) if raw>=0 else math.exp(raw)/(1+math.exp(raw))


def compare(old,new,model):
    fields=('benign_probability','adapter_probability','base_trigger_raw','base_trigger_adjusted','signature_checked','signature_verified')
    if old.get('error') or new.get('error'):raise ValueError('A runtime returned classification_failed')
    libraries={s.replace('\\','/').rsplit('/',1)[-1].casefold() for s in old['reviewer_libraries'].split()}
    flags=[float(name in libraries) for name in IMPORTS];vector=old['reviewer_feature_vector']+flags+[sum(flags)]
    names=old['reviewer_feature_names']+['import_library='+name for name in IMPORTS]+['kernel_driver_import_count']
    if names!=model['feature_names'] or new['reviewer_feature_names']!=names:raise ValueError('Reference/candidate feature schemas differ')
    changed=[];maximum=0.
    for name in fields:
        if old[name] is None or new[name] is None:
            if old[name]!=new[name]:changed.append(name)
        elif name in ('benign_probability','adapter_probability'):
            error=abs(float(old[name])-float(new[name]));maximum=max(maximum,error)
            if error>1e-9:changed.append(name)
        elif old[name]!=new[name]:changed.append(name)
    for name,before,after in zip(names,vector,new['reviewer_feature_vector']):
        error=abs(float(before)-float(after));maximum=max(maximum,error)
        if error>1e-9:changed.append(name)
    routed=old['adapter_probability']>=model['route_min'];expected_score=model_score(model,vector)
    expected=int(expected_score>=model['reviewer_threshold']) if routed else int(old['adapter_probability']>=.7)
    if new['result']!=expected:changed.append('result')
    if new['reviewer_routed']!=routed:changed.append('reviewer_routed')
    if routed:
        error=abs(new['reviewer_probability']-expected_score);maximum=max(maximum,error)
        if error>1e-9:changed.append('reviewer_probability')
    return dict(pass_=not changed,max_abs_error=maximum,changed_fields=sorted(set(changed)),expected_result=expected,actual_result=new['result'])


def run(args):
    model=json.loads(args.model.read_text());rows=[];reference=args.reference.rstrip('/');candidate=args.candidate.rstrip('/')
    info=request(candidate+'/model')
    if (not info.get('boundary_reviewer') or info['reviewer_route_min']!=.15 or info['reviewer_threshold']!=model['reviewer_threshold']
            or not info.get('score_endpoint_enabled')):raise ValueError('Candidate diagnostic configuration differs')
    reference_info=request(reference+'/model')
    if not reference_info.get('boundary_reviewer') or not reference_info.get('score_endpoint_enabled'):
        raise ValueError('Original-v7 reference diagnostics are not enabled')
    samples=[]
    for file in args.files:
        if file.is_dir():samples.extend(sorted(file.glob('*.exe'))[:16]);samples.extend(sorted(file.glob('*.dll'))[:16])
        elif file.is_file():samples.append(file)
        else:raise FileNotFoundError(file)
    seen=set()
    for file in samples:
        raw=file.read_bytes();sha=hashlib.sha256(raw).hexdigest()
        if sha in seen:continue
        seen.add(sha)
        if not raw.startswith(b'MZ') or len(raw)>16777216:continue
        try:
            old=request(reference+'/diagnostics/score?include_features=1',raw)
            new=request(candidate+'/diagnostics/score?include_features=1',raw)
            result=compare(old,new,model)
        except Exception as error:
            result=dict(pass_=False,max_abs_error=0.,changed_fields=['request_or_parser_failure'],error=str(error))
        rows.append(dict(path=str(file),sha256=sha,**result))
        print(f'{file.name}: '+('PASS' if result['pass_'] else 'FAIL '+','.join(result['changed_fields'])),flush=True)
    if not rows:raise ValueError('No eligible PE samples')
    report=dict(complete=True,passed=all(r['pass_'] for r in rows),sample_count=len(rows),
        max_abs_error=max(r['max_abs_error'] for r in rows),rows=rows,training=False,
        scope='Raw-PE runtime migration regression check on these supplied samples only; not an accuracy or hidden-grader evaluation.')
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    if not report['passed']:raise ValueError('Runtime parity failed; see '+str(args.output))


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--reference',required=True);ap.add_argument('--candidate',required=True)
    ap.add_argument('--model',type=Path,required=True);ap.add_argument('--files',type=Path,nargs='+',required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();run(args)


if __name__=='__main__':main()
