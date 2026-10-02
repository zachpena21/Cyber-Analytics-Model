#!/usr/bin/env python3
"""Read-only exact-Docker audit of frozen v8 evaluation errors; no training/tuning."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import zipfile
import numpy as np

import reviewer_v8_fresh_validation as f
import reviewer_v8_docker_audit as a

SELECTED=('major_linker_version','minor_linker_version','symbols','has_debug','has_tls',
          'imports','exports','numberof_sections','byte_size','byte_entropy','string_urls','virtual_size')


def provenance(sources):
    result={}
    for source in sources:
        path=Path(source['path'])
        if path.is_dir() and (path/'collection-summary.json').exists():
            document=f.read(path/'collection-summary.json')
            for row in document.get('samples',[]):
                result[row['sha256']]={k:row[k] for k in ('original_member','batch_url','metadata','collected_utc') if k in row}
            continue
        if not path.is_file() or not zipfile.is_zipfile(path):continue
        with zipfile.ZipFile(path) as archive:
            if 'collection-manifest.json' not in archive.namelist():continue
            document=json.loads(archive.read('collection-manifest.json'))
            for row in document.get('samples',[]):
                result[row['sha256']]=dict(original_member=row.get('original_member'),
                    original_path=row.get('original_path'),provenance=document.get('provenance'))
    return result


def neighbors(target,entries,candidate,fit_only=False):
    if not entries:return {}
    names=list(candidate.feature_names[:66]);keys=list(entries)
    X=np.array([entries[k]['feature_vector'][6:] for k in keys],dtype=float)
    X=np.log1p(np.maximum(X,0.));median=np.median(X,axis=0)
    q=np.quantile(X,[.25,.75],axis=0);scale=q[1]-q[0];std=np.std(X,axis=0)
    scale=np.where(scale>1e-12,scale,np.where(std>1e-12,std,1.))
    ref=(X-median)/scale
    tx=(np.log1p(np.maximum(target['feature_vector'][6:],0.))-median)/scale
    distance=np.mean(np.minimum(np.abs(ref-tx),10),axis=1)
    result={}
    for label in (0,1):
        eligible=[i for i,k in enumerate(keys) if k!=target['record']['sha256']
                  and entries[k]['record']['label']==label
                  and entries[k]['record']['v8_import_midpoint_prediction']==label]
        nearest=sorted(eligible,key=lambda i:(distance[i],keys[i]))[:5]
        result[str(label)]=[dict(sha256=keys[i],source=entries[keys[i]]['record']['source'],
            distance=float(distance[i]),score=entries[keys[i]]['record']['v8_import_midpoint_score']) for i in nearest]
    return result


def training_references(bundle,cache_path,split_path,candidate):
    if f.t.digest(cache_path)!=bundle['inputs']['docker_cache_sha256']:
        raise ValueError('Training Docker cache differs from frozen inputs')
    if f.t.digest(split_path)!=bundle['inputs']['split_manifest_sha256']:
        raise ValueError('Training split differs from frozen inputs')
    document=f.read(cache_path)
    if not document.get('complete'):raise ValueError('Training Docker cache is incomplete')
    split=f.read(split_path);result={}
    for i,sha in enumerate(split['original_training']+split['new_training'],1):
        if i%1000==0:print(f'Training neighbor references {i}',flush=True)
        entry=document['samples'][sha];row=entry['record'];v=entry['feature_vector']
        flags=list(a._import_values({'libraries':entry['libraries']}))
        score=f.c.reviewer_score(candidate,v+flags);routed,pred=f.c.verdict(score,candidate,row,.7)
        result[sha]=dict(entry,record=dict(row,v8_import_midpoint_score=score,
            v8_import_midpoint_routed=routed,v8_import_midpoint_prediction=pred))
    return result


def describe(entries,candidates,training):
    fixed=candidates['v8_import_midpoint'][0];names=list(candidates['v7'][0].feature_names)
    errors=[];templates=defaultdict(list)
    for sha,entry in entries.items():
        row=entry['record']
        if row['v8_import_midpoint_prediction']==row['label']:continue
        v=entry['feature_vector'];flags=list(a._import_values({'libraries':entry['libraries']}))
        features={name:v[i] for i,name in enumerate(names) if name in SELECTED}
        key=json.dumps([row['label'],*[features.get(n) for n in ('major_linker_version','minor_linker_version',
            'symbols','has_debug','has_tls','imports','exports','numberof_sections')],entry['libraries']],sort_keys=True)
        templates[key].append(sha)
        errors.append(dict(**row,selected_features=features,libraries=entry['libraries'],
            provenance=entry.get('provenance'),input_location=entry['input_location'],
            tree_paths={name:a.trace(model,v+(flags if name!='v7' else [])) for name,(model,_) in candidates.items()},
            nearest_correct_training_samples=neighbors(entry,training,fixed,True),
            nearest_correct_evaluation_samples=neighbors(entry,entries,fixed)))
    summary=dict(complete=True,error_count=len(errors),benign_errors=sum(r['label']==0 for r in errors),
        malware_errors=sum(r['label']==1 for r in errors),
        by_source=dict(Counter(r['source'] for r in errors)),
        malware_errors_below_route=sum(r['label']==1 and not r['v8_import_midpoint_routed'] for r in errors),
        malware_errors_adapter_positive=sum(r['label']==1 and r['adapter_probability']>=.7 for r in errors),
        repeated_structural_import_templates=[dict(count=len(shas),sha256=shas,template=json.loads(key))
            for key,shas in sorted(templates.items(),key=lambda item:-len(item[1])) if len(shas)>1],
        interpretation='Tree paths are additive model contributions, not causal explanations. Matching structural/import templates and nearest neighbors do not prove malware family identity. Evaluation neighbors are descriptive and are not training data.',
        neighbor_method='Shared 60 structural features only; log1p/median-IQR with std fallback, clipped mean L1. Scaling uses the designated reference pool. Training references include fitting SHAs only; evaluation references include correctly classified fresh samples.',
        threshold_tuning=False,training=False,weights_changed=False)
    return summary,errors


def run(args):
    import requests
    import pyzipper
    bundle,candidates,excluded=f.load_bundle(args.bundle)
    evaluation=f.read(args.comparison/'evaluation-manifest.json')
    summary=f.read(args.comparison/'comparison-summary.json')
    old={r['sha256']:r for r in f.read(args.comparison/'comparison-scores.json')}
    if not summary.get('complete') or not evaluation.get('complete') or evaluation['freeze_manifest_sha256']!=f.t.digest(args.bundle/'freeze-manifest.json'):
        raise ValueError('Requires a complete evaluation of this frozen bundle')
    if evaluation['sources_sha256']!=f.t.digest(args.sources):raise ValueError('Evaluation sources changed')
    wanted={r['sha256']:r for r in evaluation['samples']}
    if set(wanted)!=set(old) or set(wanted)&excluded:raise ValueError('Evaluation SHA pool mismatch/overlap')
    sources=f.read(args.sources);original=provenance(sources)
    bound=dict(freeze_manifest_sha256=f.t.digest(args.bundle/'freeze-manifest.json'),
        evaluation_manifest_sha256=f.t.digest(args.comparison/'evaluation-manifest.json'),
        evaluation_scores_sha256=f.t.digest(args.comparison/'comparison-scores.json'),sources_sha256=f.t.digest(args.sources))
    entries={}
    if args.resume:
        if f.read(args.output/'inputs.json')!=bound:raise ValueError('Resume inputs changed')
        entries=f.read(args.output/'docker-feature-cache.json')['samples']
        if not set(entries)<=set(wanted):raise ValueError('Resume cache contains unknown samples')
    else:f.fresh_output(args.output);f.w.dump(args.output/'inputs.json',bound)
    endpoint=args.service_url.rstrip('/');warnings=[]
    with requests.Session() as session:
        response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status();info=response.json()
        f.c.validate_service(info,candidates['v7'][0])
        if info!=f.read(args.comparison/'run-inputs.json')['service_model']:raise ValueError('Docker configuration changed since evaluation')
        try:
            # Validate reused cache by recomputing every frozen score and gate.
            for sha,entry in entries.items():
                record=entry['record']
                if record['sha256']!=sha or record['label']!=wanted[sha]['label'] or record['source']!=wanted[sha]['source_id']:
                    raise ValueError('Resume SHA/label/source changed')
                if entry['feature_vector'][:6]!=[old[sha][k] for k in f.w.SCORE_FEATURES]:
                    raise ValueError('Resume upstream vector changed')
                flags=list(a._import_values({'libraries':entry['libraries']}))
                for name,(model,_) in candidates.items():
                    score=f.c.reviewer_score(model,entry['feature_vector']+(flags if name!='v7' else []))
                    routed,pred=f.c.verdict(score,model,entry['record'],.7)
                    if abs(score-old[sha][name+'_score'])>1e-9 or pred!=old[sha][name+'_prediction'] or routed!=old[sha][name+'_routed']:
                        raise ValueError('Resume vector does not reproduce evaluation')
            for source in sources:
                path=Path(source['path'])
                if not path.is_absolute():path=args.sources.resolve().parent/path
                for bytez in f.w.payloads(path,pyzipper.AESZipFile,on_error=warnings.append):
                    sha=f.c.hashlib.sha256(bytez).hexdigest()
                    if sha not in wanted or sha in entries:continue
                    response=session.post(endpoint+'/diagnostics/score?include_features=1',data=bytez,
                        headers={'Content-Type':'application/octet-stream'},timeout=args.api_timeout)
                    response.raise_for_status();entry=a.service_vector(wanted[sha],bytez,response.json(),info,candidates)
                    for name in candidates:
                        if (abs(entry['record'][name+'_score']-old[sha][name+'_score'])>1e-9 or
                            entry['record'][name+'_prediction']!=old[sha][name+'_prediction']):
                            raise ValueError('Docker rescore differs from frozen evaluation')
                    entry.update(input_location=str(path),provenance=original.get(sha,wanted[sha].get('provenance')))
                    entries[sha]=entry
                    if len(entries)%25==0:
                        print(f'Audit Docker features {len(entries)}/{len(wanted)}',flush=True)
                        f.w.dump(args.output/'docker-feature-cache.json',dict(complete=False,samples=entries))
                if set(entries)==set(wanted):break
            response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status()
            if response.json()!=info:raise ValueError('Docker service configuration changed during audit')
        finally:
            f.w.dump(args.output/'docker-feature-cache.json',dict(complete=set(entries)==set(wanted),samples=entries))
            f.w.dump(args.output/'archive-read-warnings.json',warnings)
    if set(entries)!=set(wanted):raise ValueError('Required SHA coverage missing; checkpoint saved')
    if warnings:raise ValueError('Archive read errors; inspect warnings')
    training=training_references(bundle,args.training_cache,args.training_split,candidates['v8_import_midpoint'][0])
    summary,errors=describe(entries,candidates,training)
    summary.update(sample_count=len(entries),training_reference_count=len(training))
    f.w.dump(args.output/'error-audit.json',dict(summary=summary,errors=errors))
    f.w.dump(args.output/'audit-summary.json',summary)
    print(json.dumps(summary,indent=2));print(f'Send audit-summary.json and error-audit.json from {args.output}')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--service-url',required=True)
    ap.add_argument('--bundle',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-frozen-validation')
    ap.add_argument('--comparison',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-evaluation')
    ap.add_argument('--sources',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-acquisition/batch-sources.json')
    ap.add_argument('--training-cache',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--training-split',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-docker-training-development/split_manifest.json')
    ap.add_argument('--output',type=Path,default=f.w.ROOT/'validation-data/reviewer-v8-fresh-error-audit')
    ap.add_argument('--api-timeout',type=float,default=30.)
    ap.add_argument('--resume',action='store_true');args=ap.parse_args()
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 fresh error audit stopped: {error}\n')


if __name__=='__main__':main()
