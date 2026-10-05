#!/usr/bin/env python3
"""Offline group-weighted recall and changed-group score audit; no fitting."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import reviewer_v8_partial_ablation as p

a, c, g, s = p.a, p.c, p.g, p.s
CLUSTER = '00016478189eadd22a98d8839c685bff5958721101ad08dedfe53bdeb5f826b4'


def find_previous(root):
    candidates=[]
    for path in root.glob('reviewer-v8-partial-ablation-development*'):
        marker=path/'partial-ablation-comparison-summary.json'
        if marker.is_file() and g.f.read(marker).get('complete'):candidates.append(path)
    if not candidates:raise ValueError('No completed partial-ablation run found; pass --previous')
    return max(candidates,key=lambda x:(x.joinpath('partial-ablation-comparison-summary.json').stat().st_mtime_ns,str(x)))


def distribution(values):
    values=np.asarray(values,dtype=float)
    if not len(values):return dict(count=0,min=None,p10=None,median=None,p90=None,max=None)
    return dict(count=len(values),min=float(values.min()),p10=float(np.quantile(values,.1)),
                median=float(np.median(values)),p90=float(np.quantile(values,.9)),max=float(values.max()))


def group_metrics(rows,pred,groups):
    bins=defaultdict(list)
    for i,r in enumerate(rows):bins[groups[r['sha256']]].append(i)
    malware=[];benign=[]
    for ids in bins.values():
        mid=[i for i in ids if rows[i]['label']==1];bid=[i for i in ids if rows[i]['label']==0]
        if mid:malware.append(float(np.mean(pred[mid])))
        if bid:benign.append(float(np.mean(pred[bid])))
    return dict(sample_metrics=g.f.w.metrics(rows,pred),malware_groups=len(malware),
                equal_weight_malware_group_recall=float(np.mean(malware)) if malware else None,
                malware_groups_zero_recall=sum(x==0 for x in malware),malware_groups_full_recall=sum(x==1 for x in malware),
                benign_groups=len(benign),equal_weight_benign_group_fpr=float(np.mean(benign)) if benign else None)


def indexed_rates(rows,pred,groups):
    result=dict(overall=g.f.w.metrics(rows,pred),by_source={},by_group={})
    for field in ('source','group'):
        bins=defaultdict(list)
        for i,r in enumerate(rows):bins[r['source'] if field=='source' else groups[r['sha256']]].append(i)
        for key,ids in bins.items():result['by_'+field][key]=g.f.w.metrics([rows[i] for i in ids],pred[ids])
    return result


def checked_panel(entries,names,previous,mode,hashes):
    summary=g.f.read(previous/mode/'partial-ablation-summary.json');manifest=g.f.read(previous/mode/'split-manifest.json')
    groups=s.stable_groups(entries,names,mode)
    if (not summary.get('complete') or summary['mode']!=mode or manifest.get('mode')!=mode or manifest['groups']!=groups
            or summary['configuration']!=g.f.w.CONFIG or summary['seed']!=g.SEED):
        raise ValueError('Completed panel/group/configuration mismatch: '+mode)
    keys=sorted(entries);index={sha:i for i,sha in enumerate(keys)};rows=[entries[k]['record'] for k in keys]
    if len(manifest['folds'])!=5:raise ValueError('Expected five outer folds')
    held_all=[]
    for n,f in enumerate(manifest['folds']):
        if f['fold']!=n:raise ValueError('Fold order changed')
        for role in ('fit','calibration','held'):
            if len(f[role])!=len(set(f[role])) or not set(f[role])<=set(entries):raise ValueError('Invalid split SHA list')
        c.assert_split(rows,groups,[np.array([index[k] for k in f[role]]) for role in ('fit','calibration','held')])
        held_all.extend(f['held'])
    if len(held_all)!=len(entries) or set(held_all)!=set(entries):raise ValueError('Held SHA coverage changed')
    data=p.matrices(entries,names);records={};parity={}
    for variant in p.VARIANTS:
        rec=g.f.read(previous/mode/variant/'development-scores.json');v=summary['variants'][variant]
        X,schema=data[variant]
        if not v.get('complete') or v['features']!=schema or len(rec)!=len(entries) or {r['sha256'] for r in rec}!=set(entries):
            raise ValueError('Variant feature/score coverage mismatch: '+variant)
        lookup={r['sha256']:r for r in rec};error=0.
        for n,f in enumerate(manifest['folds']):
            model_path=previous/mode/variant/f'fold-{n:02d}-model.json';model=g.f.read(model_path)
            if model['feature_names']!=schema:raise ValueError('Export schema mismatch')
            ids=np.array([index[k] for k in f['held']]);hr=[rows[i] for i in ids]
            expected=np.array([lookup[r['sha256']]['reviewer_score'] for r in hr],dtype=float)
            if not np.isfinite(expected).all() or np.any((expected<0)|(expected>1)):raise ValueError('Invalid score')
            scored=g.exported_scores(model,X[ids]);err=float(np.max(np.abs(scored-expected)));error=max(error,err)
            if err>1e-10:raise ValueError(f'Previous exported-score parity failed: {mode}/{variant}/{n}, max_abs={err}')
            for r in hr:
                saved=lookup[r['sha256']]
                if saved['fold']!=n or saved['group']!=groups[r['sha256']] or any(saved[k]!=r[k] for k in ('label','source')):
                    raise ValueError('Held score record changed')
            for policy in a.POLICIES:
                threshold=g.REFERENCE_THRESHOLD if policy=='fixed' else v['folds'][n]['calibration'][policy]['threshold']
                pred=g.gated(hr,expected,threshold)
                if any(int(pred[i])!=lookup[r['sha256']][policy+'_prediction'] for i,r in enumerate(hr)):
                    raise ValueError('Stored predictions do not match scores, gates and thresholds')
                if g.f.w.metrics(hr,pred)!=v['folds'][n]['held'][policy]['overall']:raise ValueError('Fold metrics mismatch')
            hashes[str(model_path)]=g.digest(model_path)
        ordered=[lookup[k] for k in keys]
        for policy in a.POLICIES:
            pred=np.array([r[policy+'_prediction'] for r in ordered])
            if indexed_rates(rows,pred,groups)!=v['pooled'][policy]:raise ValueError('Pooled source/group metrics mismatch')
        records[variant]=lookup;parity[variant]=error
        score_path=previous/mode/variant/'development-scores.json';hashes[str(score_path)]=g.digest(score_path)
    for filename in ('partial-ablation-summary.json','split-manifest.json'):
        hashes[str(previous/mode/filename)]=g.digest(previous/mode/filename)
    return summary,groups,records,parity


def changed_groups(entries,groups,before,after,before_summary,after_summary,policy):
    bins=defaultdict(list)
    for sha in sorted(entries):bins[groups[sha]].append(sha)
    changed=[]
    for group,shas in bins.items():
        members=[sha for sha in shas if before[sha][policy+'_prediction']!=after[sha][policy+'_prediction']]
        if not members:continue
        fold=before[shas[0]]['fold']
        thresholds={name:(g.REFERENCE_THRESHOLD if policy=='fixed' else summary['folds'][fold]['calibration'][policy]['threshold'])
                    for name,summary in [('before',before_summary),('after',after_summary)]}
        labels={}
        for label,name in ((0,'benign'),(1,'malware')):
            subset=[sha for sha in shas if entries[sha]['record']['label']==label]
            labels[name]=dict(count=len(subset),rescued=sum(before[k][policy+'_prediction']!=label and after[k][policy+'_prediction']==label for k in subset),
                regressed=sum(before[k][policy+'_prediction']==label and after[k][policy+'_prediction']!=label for k in subset),
                before_scores=distribution([before[k]['reviewer_score'] for k in subset]),after_scores=distribution([after[k]['reviewer_score'] for k in subset]))
        changed.append(dict(group=group,count=len(shas),fold=fold,thresholds=thresholds,labels=labels,
            source_counts={src:sum(entries[k]['record']['source']==src for k in shas) for src in sorted({entries[k]['record']['source'] for k in shas})},
            changed_samples=[dict(sha256=k,label=entries[k]['record']['label'],source=entries[k]['record']['source'],
                before_score=before[k]['reviewer_score'],after_score=after[k]['reviewer_score'],
                before_prediction=before[k][policy+'_prediction'],after_prediction=after[k][policy+'_prediction']) for k in members]))
    return sorted(changed,key=lambda r:(-len(r['changed_samples']),r['group']))


def diagnose(entries,summary,groups,records,output,cluster=CLUSTER):
    keys=sorted(entries);cluster_shas=[k for k in keys if groups[k]==cluster]
    if len(cluster_shas)!=76 or any(entries[k]['record']['label']!=1 for k in cluster_shas):
        raise ValueError('Expected preidentified 76-malware group; pool/group identity changed')
    other=[k for k in keys if k not in set(cluster_shas)]
    result=dict(complete=True,role='descriptive_development_group_diagnostics',mode=summary['mode'],
        cluster=dict(group=cluster,count=76),variants={},changed_vs_full={},
        interpretation='Equal-weight group metrics describe this split definition, not verified malware families. Excluding the preidentified cluster is a sensitivity analysis, not a replacement headline metric or sample removal. Score contrasts are descriptive; no thresholds are selected here.')
    for variant in p.VARIANTS:
        lookup=records[variant];v=summary['variants'][variant];policies={}
        for policy in a.POLICIES:
            metrics={}
            for name,shas in [('all',keys),('excluding_cluster',other),('cluster_only',cluster_shas)]:
                rows=[entries[k]['record'] for k in shas];pred=np.array([lookup[k][policy+'_prediction'] for k in shas])
                metrics[name]=group_metrics(rows,pred,groups)
            policies[policy]=metrics
        fold=lookup[cluster_shas[0]]['fold']
        result['variants'][variant]=dict(policies=policies,cluster_scores=distribution([lookup[k]['reviewer_score'] for k in cluster_shas]),
            cluster_fold=fold,cluster_thresholds={k:(g.REFERENCE_THRESHOLD if k=='fixed' else v['folds'][fold]['calibration'][k]['threshold']) for k in a.POLICIES})
        if variant=='full_72':continue
        result['changed_vs_full'][variant]={}
        for policy in a.POLICIES:
            changed=changed_groups(entries,groups,records['full_72'],lookup,summary['variants']['full_72'],v,policy)
            g.f.w.dump(output/f'{variant}-{policy}-changed-groups.json',dict(role='descriptive_development',groups=changed))
            totals={label:dict(rescued=sum(r['labels'][label]['rescued'] for r in changed),regressed=sum(r['labels'][label]['regressed'] for r in changed)) for label in ('benign','malware')}
            expected=summary['paired_vs_full'][variant][policy]['overall']
            for label in totals:
                if any(totals[label][k]!=expected[label][k] for k in ('rescued','regressed')):raise ValueError('Changed-group pairs disagree with completed experiment')
            result['changed_vs_full'][variant][policy]=dict(changed_groups=len(changed),paired=totals,
                malware_groups_improved=sum(r['labels']['malware']['rescued']>r['labels']['malware']['regressed'] for r in changed),
                malware_groups_worsened=sum(r['labels']['malware']['rescued']<r['labels']['malware']['regressed'] for r in changed),
                largest_changes=[{k:v for k,v in r.items() if k!='changed_samples'} for r in changed[:8]])
    g.f.w.dump(output/'group-diagnostic-summary.json',result)
    return result


def main():
    root=g.f.w.ROOT/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit',type=Path,action='append');ap.add_argument('--fresh-comparison',type=Path,action='append')
    ap.add_argument('--previous',type=Path,help='Completed partial-ablation run; default latest completed')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-group-diagnostics-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.fresh_audit=args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison=args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        args.previous=args.previous or find_previous(root);print(f'Auditing completed partial ablation: {args.previous}',flush=True)
        if not g.f.read(args.previous/'partial-ablation-comparison-summary.json').get('complete'):raise ValueError('Previous comparison incomplete')
        old=g.f.read(args.previous/'inputs.json')
        for path,digest in old['input_sha256'].items():
            if g.digest(Path(path))!=digest:raise ValueError('Previous input changed: '+path)
        for module in (p,a,s,c,g):
            digest=old['script_sha256'] if module is p else old['dependency_sha256'].get(str(Path(module.__file__)))
            if digest!=g.digest(Path(module.__file__)):raise ValueError('Previous dependency changed: '+module.__name__)
        if len(args.fresh_audit)!=len(args.fresh_comparison):raise ValueError('Pair fresh audits and evaluations')
        g.f.fresh_output(args.output);entries,names,hashes,converted=g.load_inputs(args)
        for path,digest in hashes.items():
            if old['input_sha256'].get(path)!=digest:raise ValueError('Current cache differs from previous experiment')
        combined=dict(complete=False,role='descriptive_development_group_diagnostics',modes={})
        for mode in c.MODES:
            print(f'Checking stored exports, scores and gates: {mode}',flush=True)
            summary,groups,records,parity=checked_panel(entries,names,args.previous,mode,hashes)
            result=diagnose(entries,summary,groups,records,args.output/mode)
            combined['modes'][mode]=dict(export_score_max_error=parity,cluster=result['cluster'],
                variants=result['variants'],changed_group_counts={v:{k:{field:r[field] for field in ('changed_groups','paired','malware_groups_improved','malware_groups_worsened')} for k,r in policies.items()} for v,policies in result['changed_vs_full'].items()})
            g.f.w.dump(args.output/'group-diagnostic-comparison-summary.json',combined)
        combined['complete']=True;g.f.w.dump(args.output/'group-diagnostic-comparison-summary.json',combined)
        hashes[str(args.previous/'inputs.json')]=g.digest(args.previous/'inputs.json')
        g.f.w.dump(args.output/'inputs.json',dict(previous=str(args.previous),input_sha256=hashes,script_sha256=g.digest(Path(__file__)),
            dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in (p,a,s,c,g)},former_evaluation_shas_now_development=converted))
        _,_,exclusions=g.f.load_bundle(args.bundle);g.f.w.dump(args.output/'excluded-sha256.json',sorted(exclusions|set(entries)))
        print(f'Outputs: {args.output}',flush=True)
    except Exception as error:ap.exit(2,f'V8 group diagnostics stopped: {error}\n')


if __name__=='__main__':main()
