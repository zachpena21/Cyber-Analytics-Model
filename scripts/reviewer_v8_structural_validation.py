#!/usr/bin/env python3
"""Freeze provenance fold 0 primary/comparison, then evaluate untouched acquisitions."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import numpy as np
import reviewer_v8_bounded_upstream as b

q,d,p,a,c,g,s = b.q,b.d,b.p,b.a,b.c,b.g,b.s
f,w = g.f,g.f.w
MODE = 'provenance'
FOLD = 0  # Fixed index, never chosen by held performance.
POLICY = 'software'
PRIMARY = 'structural_primary'
COMPARISON = 'bounded_comparison'
DEPENDENCIES = (b,q,d,p,a,s,c,g)


def find_previous(root):
    paths=[]
    for path in root.glob('reviewer-v8-bounded-upstream-development-*'):
        marker=path/'bounded-upstream-comparison-summary.json'
        if marker.is_file() and f.read(marker).get('complete'):paths.append(path)
    if not paths:raise ValueError('No completed bounded experiment; pass --previous')
    return max(paths,key=lambda x:(x.joinpath('bounded-upstream-comparison-summary.json').stat().st_mtime_ns,str(x)))


def verify_previous(previous):
    if not f.read(previous/'bounded-upstream-comparison-summary.json').get('complete'):
        raise ValueError('Previous bounded experiment incomplete')
    old=f.read(previous/'inputs.json')
    for path,digest in old['input_sha256'].items():
        if g.digest(Path(path))!=digest:raise ValueError('Previous input changed: '+path)
    for module in DEPENDENCIES:
        digest=old['script_sha256'] if module is b else old['dependency_sha256'].get(str(Path(module.__file__)))
        if digest!=g.digest(Path(module.__file__)):raise ValueError('Previous dependency changed: '+module.__name__)
    return old


def check_bounded(entries,names,previous,partial,mode,hashes):
    prior,groups,controls,parity=d.checked_panel(entries,names,partial,mode,hashes)
    summary=f.read(previous/mode/'bounded-upstream-summary.json')
    manifest=f.read(partial/mode/'split-manifest.json')
    if (not summary.get('complete') or summary['configuration']!=b.CONFIG or summary['mode']!=mode
        or f.read(previous/mode/'split-manifest.json')!=manifest or len(summary['folds'])!=5):
        raise ValueError('Bounded summary/split/configuration changed')
    records=f.read(previous/mode/b.VARIANT/'development-scores.json')
    if len(records)!=len(entries) or {r['sha256'] for r in records}!=set(entries):raise ValueError('Bounded held coverage changed')
    lookup={r['sha256']:r for r in records};keys=sorted(entries);index={k:i for i,k in enumerate(keys)}
    rows=[entries[k]['record'] for k in keys];X,_=p.matrices(entries,names)['structural_66'];max_error=0.
    for fold in manifest['folds']:
        n=fold['fold'];path=previous/mode/b.VARIANT/f'fold-{n:02d}-model.json';payload=f.read(path)
        if payload['structural_model']!=f.read(partial/mode/'structural_66'/f'fold-{n:02d}-model.json'):
            raise ValueError('Bounded structural trees differ from original control')
        ids=np.array([index[k] for k in fold['held']]);hr=[rows[i] for i in ids]
        score,offset=b.exported_scores(payload,X[ids],hr)
        for i,row in enumerate(hr):
            saved=lookup[row['sha256']]
            if saved['fold']!=n or saved['group']!=groups[row['sha256']] or any(saved[k]!=row[k] for k in ('label','source')):
                raise ValueError('Bounded held record identity changed')
            max_error=max(max_error,abs(float(score[i])-saved['reviewer_score']))
            if abs(float(offset[i])-saved['logit_correction'])>1e-12:raise ValueError('Bounded correction record changed')
        if max_error>1e-10:raise ValueError('Bounded exported-score parity failed')
        for policy in a.POLICIES:
            threshold=g.REFERENCE_THRESHOLD if policy=='fixed' else summary['folds'][n]['calibration'][policy]['threshold']
            if policy!='fixed' and payload['calibration'][policy]!=summary['folds'][n]['calibration'][policy]:
                raise ValueError('Bounded export calibration differs from summary')
            pred=g.gated(hr,score,threshold)
            if any(int(pred[i])!=lookup[row['sha256']][policy+'_prediction'] for i,row in enumerate(hr)):
                raise ValueError('Bounded predictions changed')
            if d.indexed_rates(hr,pred,groups)!=summary['folds'][n]['held'][policy]:raise ValueError('Bounded fold metrics changed')
        hashes[str(path)]=g.digest(path)
    for policy in a.POLICIES:
        pred=np.array([lookup[k][policy+'_prediction'] for k in keys])
        if d.group_metrics(rows,pred,groups)!=summary['policies'][policy]['all']:raise ValueError('Bounded pooled metrics changed')
        for control in b.CONTROLS:
            before=np.array([controls[control][k][policy+'_prediction'] for k in keys])
            if a.paired(rows,before,pred)!=summary['paired_vs_controls'][control][policy]['all']:
                raise ValueError('Bounded paired metrics changed')
    for filename in ('bounded-upstream-summary.json','split-manifest.json',b.VARIANT+'/development-scores.json'):
        hashes[str(previous/mode/filename)]=g.digest(previous/mode/filename)
    return prior,summary,manifest,dict(controls=parity,bounded=max_error)


def freeze(args):
    f.fresh_output(args.output);args.previous=args.previous or find_previous(w.ROOT/'validation-data')
    print(f'Freezing fixed {MODE} fold {FOLD} from {args.previous}',flush=True)
    old=verify_previous(args.previous)
    if len(args.fresh_audit)!=len(args.fresh_comparison):raise ValueError('Pair fresh audit/evaluation paths')
    entries,names,hashes,_=g.load_inputs(args)
    for path,digest in hashes.items():
        if old['input_sha256'].get(path)!=digest:raise ValueError('Current cache changed')
    partial=Path(old['partial']);checks={};chosen=None
    for mode in c.MODES:
        print(f'Verifying completed controls and correction: {mode}',flush=True)
        prior,summary,manifest,checks[mode]=check_bounded(entries,names,args.previous,partial,mode,hashes)
        if mode==MODE:chosen=(prior,summary,manifest)
    prior,summary,split=chosen;fold=split['folds'][FOLD]
    primary_policy=prior['variants']['structural_66']['folds'][FOLD]['calibration'][POLICY]
    comparison_policy=summary['folds'][FOLD]['calibration'][POLICY]
    if not all(x['eligible_development_policy'] for x in (primary_policy,comparison_policy)):
        raise ValueError('Selected software calibration is ineligible')
    structural=f.read(partial/MODE/'structural_66'/f'fold-{FOLD:02d}-model.json')
    bounded=f.read(args.previous/MODE/b.VARIANT/f'fold-{FOLD:02d}-model.json')
    legacy,_,excluded=f.load_bundle(args.bundle)
    excluded.update(entries);reported,report_hashes=f.report_exclusions(args.reports);excluded.update(reported)
    # Preserve prior exclusion unions as well as the cache and CSV report union.
    for path in sorted(args.reports.rglob('excluded-sha256.json')):
        extra=f.read(path)
        if not isinstance(extra,list) or any(not valid_sha(k) for k in extra):raise ValueError('Invalid exclusion file: '+str(path))
        excluded.update(extra);hashes[str(path)]=g.digest(path)
    artifacts={}
    def save(relative,payload):
        w.dump(args.output/relative,payload);artifacts[relative]=g.digest(args.output/relative)
    def copy_artifact(relative,source):
        target=args.output/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(source.read_bytes());artifacts[relative]=g.digest(target)
    save('structural-primary-model.json',structural);save('bounded-comparison-model.json',bounded)
    save('selected-split.json',dict(mode=MODE,fold=FOLD,roles={k:fold[k] for k in ('fit','calibration','held')},
                                 note='Held rows were already inspected during development and are excluded from untouched validation.'))
    for entry in legacy['models'].values():copy_artifact('legacy/'+entry['path'],args.bundle/entry['path'])
    copy_artifact('legacy/'+legacy['exclusions']['path'],args.bundle/legacy['exclusions']['path'])
    copy_artifact('legacy/freeze-manifest.json',args.bundle/'freeze-manifest.json');save('excluded-sha256.json',sorted(excluded))
    save('freeze-inputs.json',dict(previous=str(args.previous),partial=str(partial),input_sha256=dict(hashes,**report_hashes),
                                  previous_inputs_sha256=g.digest(args.previous/'inputs.json')))
    frozen=dict(complete=True,role='frozen_structural_validation',frozen_at=datetime.now(timezone.utc).isoformat(),
        threshold_tuning=False,primary=PRIMARY,selection=dict(mode=MODE,fold=FOLD,policy=POLICY,
            rule='Fixed provenance fold zero, selected by index rather than held performance; no final refit.'),
        models={PRIMARY:dict(path='structural-primary-model.json',threshold=primary_policy['threshold'],route_min=g.ROUTE),
                COMPARISON:dict(path='bounded-comparison-model.json',threshold=comparison_policy['threshold'],route_min=g.ROUTE)},
        calibration={PRIMARY:primary_policy,COMPARISON:comparison_policy},
        exclusions=dict(path='excluded-sha256.json',count=len(excluded),development_pool=len(entries)),
        artifact_sha256=artifacts,verification=checks,
        script_sha256=g.digest(Path(__file__)),dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in DEPENDENCIES},
        scope='Post-hoc development selected weights. SHA disjointness and declared acquisition dates do not establish family/version independence. Validation is independent only while unused for tuning. Comparison is descriptive, not a replacement chosen after seeing validation.')
    w.dump(args.output/'freeze-manifest.json',frozen)
    load_bundle(args.output)
    print(f'Frozen primary threshold={primary_policy["threshold"]:.16g}; comparison={comparison_policy["threshold"]:.16g}',flush=True)
    print(f'Excluded {len(excluded)} SHAs; bundle: {args.output}',flush=True)
    print('Next: acquire new samples after this freeze; do not reuse previous evaluation batches.',flush=True)


def valid_sha(sha):return isinstance(sha,str) and len(sha)==64 and all(x in '0123456789abcdef' for x in sha)


def load_bundle(directory):
    manifest=f.read(directory/'freeze-manifest.json')
    if (manifest.get('complete') is not True or manifest.get('role')!='frozen_structural_validation'
        or manifest.get('threshold_tuning') is not False or manifest['primary']!=PRIMARY
        or manifest['selection']!=dict(mode=MODE,fold=FOLD,policy=POLICY,rule='Fixed provenance fold zero, selected by index rather than held performance; no final refit.')):
        raise ValueError('Invalid structural freeze')
    if manifest['script_sha256']!=g.digest(Path(__file__)):raise ValueError('Frozen validation script changed')
    for module in DEPENDENCIES:
        if manifest['dependency_sha256'].get(str(Path(module.__file__)))!=g.digest(Path(module.__file__)):
            raise ValueError('Frozen dependency changed: '+module.__name__)
    for relative,digest in manifest['artifact_sha256'].items():
        if g.digest(directory/relative)!=digest:raise ValueError('Frozen artifact changed: '+relative)
    _,legacy,_=f.load_bundle(directory/'legacy')
    structural=f.read(directory/manifest['models'][PRIMARY]['path']);bounded=f.read(directory/manifest['models'][COMPARISON]['path'])
    schema=list(legacy['v7'][0].feature_names)[6:]+list(g.f.t.e.IMPORT_FEATURES)
    if structural['feature_names']!=schema or bounded['structural_model']!=structural:raise ValueError('Frozen structural schema/weights changed')
    if bounded['configuration']!=b.CONFIG or bounded['upstream_features']!=list(b.FEATURES):raise ValueError('Frozen correction configuration changed')
    for name in (PRIMARY,COMPARISON):
        record=manifest['models'][name]
        if record['route_min']!=g.ROUTE or not 0<=record['threshold']<=1 or record['threshold']!=manifest['calibration'][name]['threshold']:
            raise ValueError('Frozen threshold/routing changed')
        if not manifest['calibration'][name]['eligible_development_policy']:raise ValueError('Frozen calibration ineligible')
    if structural['reviewer_threshold']!=manifest['models'][PRIMARY]['threshold'] or bounded['calibration'][POLICY]!=manifest['calibration'][COMPARISON]:
        raise ValueError('Frozen payload thresholds differ')
    excluded=f.read(directory/manifest['exclusions']['path'])
    if len(excluded)!=len(set(excluded)) or len(excluded)!=manifest['exclusions']['count'] or any(not valid_sha(k) for k in excluded):
        raise ValueError('Frozen exclusion coverage invalid')
    return manifest,structural,bounded,legacy,set(excluded)


def acquired_time(value):
    stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
    if stamp.tzinfo is None:raise ValueError('Acquisition timestamps must include a timezone')
    return stamp


def check_acquisitions(sources,frozen):
    for source in sources:
        if not isinstance(source.get('acquired_at'),str):raise ValueError('Each source needs acquired_at after freeze, with timezone')
        stamp=acquired_time(source['acquired_at'])
        if stamp<=acquired_time(frozen) or stamp>datetime.now(timezone.utc):raise ValueError('Source must be acquired after freeze and not in the future')


def compare_one(sample,bytez,details,info,manifest,structural,bounded,legacy):
    row=f.c.compare_one(sample,bytez,details,info,legacy)
    vector=list(map(float,details['reviewer_feature_vector']))[6:]+list(g.f.t.e._import_values({'libraries':details['reviewer_libraries']}))
    base=float(g.exported_scores(structural,[vector])[0]);corrected,offset=b.exported_scores(bounded,[vector],[row])
    for name,score in ((PRIMARY,base),(COMPARISON,float(corrected[0]))):
        threshold=manifest['models'][name]['threshold'];routed=row['adapter_probability']>=g.ROUTE
        row.update({name+'_score':score,name+'_routed':routed,name+'_prediction':int(g.gated([row],[score],threshold)[0])})
    row['bounded_logit_correction']=float(offset[0]);return row


def evaluate(args):
    import pyzipper
    import requests
    f.fresh_output(args.output);manifest,structural,bounded,legacy,excluded=load_bundle(args.bundle)
    check_acquisitions(f.read(args.sources),manifest['frozen_at'])
    wanted,acquisition=f.scan_sources(args.sources,excluded,pyzipper.AESZipFile);w.dump(args.output/'acquisition-audit.json',acquisition)
    if acquisition['archive_warnings']:raise ValueError('Unreadable archive entries; repair sources before scoring')
    labels={r['label'] for r in wanted.values()}
    if labels!=({0} if args.benign_only else {0,1}):raise ValueError('Need both classes, or a nonempty benign-only pool with --benign-only')
    total=len(wanted);rows=[];warnings=[];endpoint=args.service_url.rstrip('/');sources_digest=g.digest(args.sources)
    evaluation=dict(complete=False,role='evaluation',threshold_tuning=False,samples=list(wanted.values()),
                    freeze_manifest_sha256=g.digest(args.bundle/'freeze-manifest.json'),sources_sha256=sources_digest)
    w.dump(args.output/'evaluation-manifest.json',evaluation)
    with requests.Session() as session:
        response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status();info=response.json()
        f.c.validate_service(info,legacy['v7'][0]);w.dump(args.output/'run-inputs.json',dict(freeze=manifest,service_model=info,service_url=endpoint))
        for location in acquisition['input_files']:
            for bytez in w.payloads(Path(location),pyzipper.AESZipFile,on_error=warnings.append):
                sha=hashlib.sha256(bytez).hexdigest()
                if sha not in wanted:continue
                sample=wanted[sha]
                if len(bytez)!=sample['byte_size']:raise ValueError('Sample bytes changed')
                response=session.post(endpoint+'/diagnostics/score?include_features=1',data=bytez,
                    headers={'Content-Type':'application/octet-stream'},timeout=args.api_timeout);response.raise_for_status()
                rows.append(compare_one(sample,bytez,response.json(),info,manifest,structural,bounded,legacy));del wanted[sha]
                if len(rows)%25==0:print(f'Scored {len(rows)}/{total}',flush=True);w.dump(args.output/'partial-scores.json',rows)
            if not wanted:break
        w.dump(args.output/'archive-read-warnings.json',warnings)
        if wanted or warnings:raise ValueError('Required SHA coverage/read integrity failed')
        response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status()
        if response.json()!=info:raise ValueError('Diagnostic service changed')
    load_bundle(args.bundle)
    if g.digest(args.sources)!=sources_digest:raise ValueError('Sources manifest changed during evaluation')
    names=(PRIMARY,COMPARISON,'v7','v8_import_upper');summary=dict(complete=True,role='evaluation',threshold_tuning=False,
        primary=PRIMARY,sample_count=len(rows),scope=manifest['scope'],models={},paired_vs_primary={},
        excluded_overlap_count=len(acquisition['excluded_overlap_sha256']),
        v7_service_parity_max_error=max(r['v7_service_parity_error'] for r in rows))
    for name in names:
        pred=np.array([r[name+'_prediction'] for r in rows])
        summary['models'][name]=dict(overall=w.metrics(rows,pred),
            threshold=manifest['models'][name]['threshold'] if name in manifest['models'] else legacy[name][0].threshold,
            route_min=g.ROUTE if name in manifest['models'] else legacy[name][0].route_min,
            by_source={src:w.metrics([r for r in rows if r['source']==src],[r[name+'_prediction'] for r in rows if r['source']==src]) for src in sorted({r['source'] for r in rows})})
        if name!=PRIMARY:summary['paired_vs_primary'][name]=a.paired(rows,np.array([r[PRIMARY+'_prediction'] for r in rows]),pred)
    w.dump(args.output/'comparison-scores.json',rows)
    with (args.output/'comparison-scores.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    evaluation['complete']=True;w.dump(args.output/'evaluation-manifest.json',evaluation);w.dump(args.output/'comparison-summary.json',summary)
    print(f'Complete untouched evaluation: {args.output}',flush=True)


def main():
    root=w.ROOT/'validation-data';ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    fr=sub.add_parser('freeze');fr.add_argument('--previous',type=Path);fr.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    fr.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    fr.add_argument('--fresh-audit',type=Path,action='append');fr.add_argument('--fresh-comparison',type=Path,action='append')
    fr.add_argument('--reports',type=Path,default=root);fr.add_argument('--output',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ev=sub.add_parser('evaluate');ev.add_argument('--bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ev.add_argument('--sources',type=Path,required=True);ev.add_argument('--service-url',required=True)
    ev.add_argument('--api-timeout',type=float,default=30.);ev.add_argument('--benign-only',action='store_true')
    ev.add_argument('--output',type=Path,default=root/('reviewer-v8-structural-evaluation-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args()
    if args.command=='freeze':
        args.fresh_audit=args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
        args.fresh_comparison=args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:(freeze if args.command=='freeze' else evaluate)(args)
    except Exception as error:ap.exit(2,f'V8 structural validation stopped: {error}\n')


if __name__=='__main__':main()
