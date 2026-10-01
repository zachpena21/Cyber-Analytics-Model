#!/usr/bin/env python3
"""Freeze expanded v8 weights, then evaluate new SHA-disjoint acquisitions without tuning."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path

import reviewer_v8_workflow as w
import reviewer_v8_coverage_compare as c
import reviewer_v8_docker_train as t
from defender.models.boundary_reviewer import IMPORT_FEATURES

FIXED_THRESHOLD = .639722991937624
LABELS = dict(v7='v7', v8_import_upper='v8_expanded_calibrated',
              v8_import_midpoint='v8_expanded_fixed_06397')


def fresh_output(path):
    if path.exists() and any(path.iterdir()):
        raise ValueError('Output is not empty; choose a new output directory')


def read(path):return json.loads(path.read_text())


def report_exclusions(directory):
    """Include every SHA recorded in any CSV report, even outside the training pool."""
    excluded=set();hashes={}
    for path in sorted(directory.rglob('*.csv')):
        with path.open(newline='',encoding='utf-8-sig') as stream:
            reader=csv.DictReader(stream)
            if not reader.fieldnames or 'sha256' not in reader.fieldnames:continue
            hashes[str(path.resolve())]=t.digest(path)
            for row in reader:
                sha=row['sha256'].strip().lower()
                if len(sha)!=64 or any(x not in '0123456789abcdef' for x in sha):
                    raise ValueError(f'Invalid SHA in report: {path}')
                excluded.add(sha)
    return excluded,hashes


def freeze(args):
    fresh_output(args.output)
    summary=read(args.training/'training-summary.json')
    inputs=read(args.training/'inputs.json')
    if not summary.get('completed'):raise ValueError('Training has not completed')
    expected=dict(docker_cache_sha256=t.digest(args.audit/'docker-feature-cache.json'),
                  docker_audit_summary_sha256=t.digest(args.audit/'docker-audit-summary.json'),
                  coverage_sha256=t.digest(args.coverage))
    if any(inputs.get(k)!=v for k,v in expected.items()):
        raise ValueError('Training input hashes differ from current Docker audit/coverage')
    original,new,cached,groups,samples,old_candidates=t.load_data(args.audit,args.coverage,args.reports)
    split=read(args.training/'split_manifest.json')
    lists=[split[k] for k in ('original_training','original_calibration','new_training','new_calibration')]
    flattened=[s for part in lists for s in part]
    if len(flattened)!=len(set(flattened)) or set(flattened)!=set(samples):
        raise ValueError('Training split does not match audited SHA pool')
    if len(original)!=summary['original_samples'] or len(new)!=summary['new_samples']:
        raise ValueError('Training summary pool mismatch')
    source=args.training/'expanded_candidate-upper-model.json'
    payload=read(source);model=w.BoundaryReviewer(source)
    policy=summary['models']['expanded_candidate']
    if (payload['format_version']!=8 or model.route_min!=.15 or
        model.threshold!=policy['policies']['upper'] or
        list(model.feature_names)!=list(old_candidates['v7'][0].feature_names)+list(IMPORT_FEATURES) or
        max(policy['export_parity'].values())>1e-10):
        raise ValueError('Expanded candidate schema, policy, or export parity mismatch')
    recorded={r['sha256']:r for r in read(args.training/'development-scores.json')
              if r['model']=='expanded_candidate'}
    if set(recorded)!={r['sha256'] for r in new}:
        raise ValueError('Expanded development scores are incomplete')
    for row in new:
        score=c.reviewer_score(model,w.vector(row,cached[row['sha256']]))
        if abs(score-recorded[row['sha256']]['score'])>1e-10:
            raise ValueError('Saved candidate does not reproduce completed training scores')
    fixed=copy.deepcopy(payload);fixed['reviewer_threshold']=FIXED_THRESHOLD
    fixed_model=w.BoundaryReviewer.__new__(w.BoundaryReviewer);fixed_model._load(fixed)
    # Check threshold-only editing leaves every recorded score unchanged.
    for row in original+new:
        vector=w.vector(row,cached[row['sha256']])
        if c.reviewer_score(model,vector)!=c.reviewer_score(fixed_model,vector):
            raise ValueError('Threshold-only variant changed weights/scores')
    excluded,report_hashes=report_exclusions(args.reports);excluded.update(samples)
    paths=dict(v7='v7-model.json',v8_import_upper='v8-expanded-calibrated-model.json',
               v8_import_midpoint='v8-expanded-fixed-06397-model.json')
    for name,p in zip(c.NAMES,(old_candidates['v7'][1],payload,fixed)):
        w.dump(args.output/paths[name],p)
    w.dump(args.output/'excluded-sha256.json',sorted(excluded))
    manifest=dict(complete=True,role='frozen_validation',threshold_tuning=False,
        models={name:dict(path=paths[name],sha256=t.digest(args.output/paths[name]),
                         label=LABELS[name]) for name in c.NAMES},
        exclusions=dict(path='excluded-sha256.json',sha256=t.digest(args.output/'excluded-sha256.json'),
                        count=len(excluded),development_samples=len(samples)),
        thresholds=dict(v7=old_candidates['v7'][0].threshold,
                        v8_expanded_calibrated=model.threshold,v8_expanded_fixed_06397=FIXED_THRESHOLD),
        inputs=dict(expected,training_summary_sha256=t.digest(args.training/'training-summary.json'),
                    training_inputs_sha256=t.digest(args.training/'inputs.json'),
                    split_manifest_sha256=t.digest(args.training/'split_manifest.json'),
                    candidate_sha256=t.digest(source),additional_csv_reports=report_hashes),
        scope='SHA disjoint from recorded development/reports; this does not prove software-version or malware-family independence.')
    w.dump(args.output/'freeze-manifest.json',manifest)
    print(f'Frozen {len(samples)} development SHAs; total excluded: {len(excluded)}')
    print(f'Thresholds: calibrated={model.threshold:.16g}, fixed={FIXED_THRESHOLD:.16g}')
    print(f'Next: obtain genuinely new acquisitions and run evaluate with --sources; bundle: {args.output}')


def load_bundle(directory):
    manifest=read(directory/'freeze-manifest.json')
    if manifest.get('complete') is not True or manifest.get('threshold_tuning') is not False:
        raise ValueError('Incomplete or invalid freeze manifest')
    candidates={}
    for name in c.NAMES:
        entry=manifest['models'][name];path=directory/entry['path']
        if t.digest(path)!=entry['sha256']:raise ValueError('Frozen model hash changed')
        candidates[name]=(w.BoundaryReviewer(path),read(path))
    entry=manifest['exclusions'];path=directory/entry['path']
    if t.digest(path)!=entry['sha256']:raise ValueError('Frozen exclusions hash changed')
    excluded=set(read(path))
    if len(excluded)!=entry['count']:raise ValueError('Exclusion count mismatch')
    a,b=(candidates[n][1] for n in c.NAMES[1:])
    if {k:v for k,v in a.items() if k!='reviewer_threshold'}!={k:v for k,v in b.items() if k!='reviewer_threshold'}:
        raise ValueError('V8 policies must share identical weights and routing')
    if b['reviewer_threshold']!=FIXED_THRESHOLD:raise ValueError('Fixed threshold changed')
    return manifest,candidates,excluded


def scan_sources(sources_path,excluded,zipclass):
    sources=read(sources_path)
    if not isinstance(sources,list) or not sources:raise ValueError('Sources must be a nonempty JSON array')
    samples={};locations=[];warnings=[];overlaps=set();oversize=set();duplicates=0
    ids=set()
    for source in sources:
        if source['label'] not in (0,1) or not source.get('source_id') or not source.get('provenance'):
            raise ValueError('Each source needs label 0/1, source_id and provenance')
        if source['source_id'] in ids:raise ValueError('Source IDs must be unique')
        ids.add(source['source_id'])
        path=Path(source['path']).expanduser()
        if not path.is_absolute():path=sources_path.resolve().parent/path
        if not path.exists():raise ValueError(f'Source missing: {path}')
        locations.append(str(path.resolve()))
        for bytez in w.payloads(path,zipclass,on_error=warnings.append):
            sha=hashlib.sha256(bytez).hexdigest()
            if sha in samples and samples[sha]['label']!=source['label']:
                raise ValueError(f'Conflicting fresh labels: {sha}')
            if sha in excluded:overlaps.add(sha);continue
            if len(bytez)>16*1024*1024:oversize.add(sha);continue
            if sha in samples:duplicates+=1;continue
            samples[sha]=dict(sha256=sha,label=source['label'],source_id=source['source_id'],
                categories=[],byte_size=len(bytez),input_location=str(path.resolve()),provenance=source['provenance'])
    return samples,dict(sources=sources,input_files=locations,excluded_overlap_sha256=sorted(overlaps),
                        oversize_sha256=sorted(oversize),duplicate_entries=duplicates,archive_warnings=warnings)


def evaluate(args):
    import pyzipper
    import requests
    fresh_output(args.output)
    manifest,candidates,excluded=load_bundle(args.bundle)
    wanted,acquisition=scan_sources(args.sources,excluded,pyzipper.AESZipFile)
    w.dump(args.output/'acquisition-audit.json',acquisition)
    if acquisition['archive_warnings']:
        raise ValueError('Unreadable acquisition entries; inspect acquisition-audit.json and repair sources before evaluating')
    if {r['label'] for r in wanted.values()}!={0,1}:
        raise ValueError('Fresh SHA-disjoint samples must include both benign and malware classes')
    total=len(wanted);rows=[];warnings=[];endpoint=args.service_url.rstrip('/')
    w.dump(args.output/'evaluation-manifest.json',dict(complete=False,samples=list(wanted.values()),
        freeze_manifest_sha256=t.digest(args.bundle/'freeze-manifest.json'),sources_sha256=t.digest(args.sources),
        threshold_tuning=False,role='evaluation'))
    with requests.Session() as session:
        response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status();info=response.json()
        c.validate_service(info,candidates['v7'][0])
        w.dump(args.output/'run-inputs.json',dict(freeze=manifest,service_model=info,service_url=endpoint))
        for location in acquisition['input_files']:
            for bytez in w.payloads(Path(location),pyzipper.AESZipFile,on_error=warnings.append):
                sha=hashlib.sha256(bytez).hexdigest()
                if sha not in wanted:continue
                sample=wanted[sha]
                if len(bytez)!=sample['byte_size']:raise ValueError('Sample bytes changed')
                response=session.post(endpoint+'/diagnostics/score?include_features=1',data=bytez,
                    headers={'Content-Type':'application/octet-stream'},timeout=args.api_timeout)
                response.raise_for_status()
                rows.append(c.compare_one(sample,bytez,response.json(),info,candidates));del wanted[sha]
                if len(rows)%25==0:
                    print(f'Scored {len(rows)}/{total}',flush=True);w.dump(args.output/'partial-scores.json',rows)
            if not wanted:break
        w.dump(args.output/'archive-read-warnings.json',warnings)
        if wanted:
            w.dump(args.output/'missing-sha256.json',sorted(wanted));raise ValueError('Required fresh SHA coverage missing')
        if warnings:raise ValueError('Archive reads failed during scoring')
        response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status()
        if response.json()!=info:raise ValueError('Service configuration changed')
    summary=c.summarize(rows,candidates)
    for name,record in summary['models'].items():
        record['label']=LABELS[name]
        record['by_source']={s:w.metrics([r for r in rows if r['source']==s],
            [r[name+'_prediction'] for r in rows if r['source']==s]) for s in sorted({r['source'] for r in rows})}
    summary.update(complete=True,role='evaluation',threshold_tuning=False,
        scope=manifest['scope'],excluded_overlap_count=len(acquisition['excluded_overlap_sha256']),
        note='Both V8 policies use identical expanded weights. Source provenance is declared, not independently verified. Retain evaluation status only while these results remain unused for tuning.')
    w.dump(args.output/'comparison-scores.json',rows)
    with (args.output/'comparison-scores.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    evaluation=read(args.output/'evaluation-manifest.json');evaluation['complete']=True
    w.dump(args.output/'evaluation-manifest.json',evaluation)
    w.dump(args.output/'comparison-summary.json',summary)
    print(json.dumps(summary,indent=2))
    print(f'Send comparison-summary.json and comparison-scores.csv from {args.output}')


def main():
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    freeze_ap=sub.add_parser('freeze')
    freeze_ap.add_argument('--training',type=Path,default=w.ROOT/'validation-data/reviewer-v8-docker-training-development')
    freeze_ap.add_argument('--audit',type=Path,default=w.ROOT/'validation-data/reviewer-v8-docker-audit')
    freeze_ap.add_argument('--coverage',type=Path,default=w.ROOT/'validation-data/reviewer-v8-coverage-development/coverage-manifest.json')
    freeze_ap.add_argument('--reports',type=Path,default=w.ROOT/'validation-data')
    freeze_ap.add_argument('--output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-frozen-validation')
    eval_ap=sub.add_parser('evaluate')
    eval_ap.add_argument('--bundle',type=Path,default=w.ROOT/'validation-data/reviewer-v8-frozen-validation')
    eval_ap.add_argument('--sources',type=Path,required=True)
    eval_ap.add_argument('--service-url',required=True)
    eval_ap.add_argument('--api-timeout',type=float,default=30.)
    eval_ap.add_argument('--output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-fresh-evaluation')
    args=ap.parse_args()
    try:(freeze if args.command=='freeze' else evaluate)(args)
    except Exception as error:ap.exit(2,f'V8 fresh validation stopped: {error}\n')


if __name__=='__main__':main()
