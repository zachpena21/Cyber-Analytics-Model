#!/usr/bin/env python3
"""Read-only saved-model audit of targeted coverage regressions and benign misses."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import reviewer_v8_targeted_coverage_experiment as t
import reviewer_v8_rich_blocker_profile as p

r,cache=t.r,t.r.cache


def latest(root):
    paths=[d for d in root.glob('reviewer-v8-targeted-coverage-development-*')
           if (d/'targeted-coverage-summary.json').is_file()
           and cache.read(d/'targeted-coverage-summary.json').get('complete') is True]
    if not paths:raise ValueError('No completed targeted coverage run; pass --run')
    return max(paths,key=lambda d:((d/'targeted-coverage-summary.json').stat().st_mtime_ns,str(d)))


def traced_path(payload, vector, tree_id):
    # Convert float32 values back to Python floats before comparing against
    # the tree's double thresholds, matching runtime/C++ branch semantics.
    values=np.asarray(vector,dtype=np.float32).tolist();tree=payload['estimators'][tree_id];node=0;steps=[]
    while tree['children_left'][node]>=0:
        f=tree['feature'][node];left=values[f]<=tree['threshold'][node]
        steps.append(dict(node=node,feature=payload['feature_names'][f],value=values[f],
                          threshold=tree['threshold'][node],branch='left' if left else 'right'))
        node=tree['children_left' if left else 'children_right'][node]
    return dict(leaf=node,raw_value=tree['raw_value'][node],steps=steps)


def training_order_scores(payload, X):
    from scipy.special import expit
    values=np.asarray(X,dtype=np.float32).tolist();raw=np.full(len(values),float(payload['initial_raw_score']))
    for tree in payload['estimators']:
        leaves=[]
        for vector in values:
            node=0
            while tree['children_left'][node]>=0:
                left=vector[tree['feature'][node]]<=tree['threshold'][node]
                node=tree['children_left' if left else 'children_right'][node]
            leaves.append(tree['raw_value'][node])
        raw+=float(payload['learning_rate'])*np.asarray(leaves)
    return expit(raw)


def tree_changes(before,after,vector,limit=5):
    if before['feature_names']!=after['feature_names'] or len(before['estimators'])!=len(after['estimators']):
        raise ValueError('Model schemas/tree counts differ')
    changes=[];total=float(after['initial_raw_score']-before['initial_raw_score'])
    for j in range(len(before['estimators'])):
        left=traced_path(before,vector,j);right=traced_path(after,vector,j)
        delta=float(after['learning_rate']*right['raw_value']-before['learning_rate']*left['raw_value'])
        total+=delta
        changes.append(dict(tree=j,raw_contribution_change=delta,before_path=left,after_path=right))
    changes.sort(key=lambda x:(-abs(x['raw_contribution_change']),x['tree']))
    return dict(initial_raw_change=float(after['initial_raw_score']-before['initial_raw_score']),
                total_raw_change=total,trees_with_changed_contribution=sum(x['raw_contribution_change']!=0 for x in changes),
                largest_contribution_changes=changes[:limit])


def change_groups(keys,rows,groups,before,after,threshold_before,threshold_after):
    out={};bins=defaultdict(list)
    for i,k in enumerate(keys):bins[groups[k]].append(i)
    for group,ids in bins.items():
        label=rows[ids[0]]['label']
        if any(rows[i]['label']!=label for i in ids):label='mixed'
        out[group]=dict(count=len(ids),label=label,sha256=[keys[i] for i in ids],
            before_score_range=[float(min(before[ids])),float(max(before[ids]))],
            after_score_range=[float(min(after[ids])),float(max(after[ids]))],
            median_score_change=float(np.median(after[ids]-before[ids])))
    return sorted([dict(group=k,**v) for k,v in out.items()],key=lambda x:(-x['count'],x['group']))


def replay(entries,names,features,new,run,summary,manifest):
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)};rows=[entries[k]['record'] for k in keys]
    groups=manifest['groups'];data=r.matrices(entries,names,features)
    if groups!=r.matched_groups(entries,names,features,'template'):raise ValueError('Saved joint groups differ')
    if len(manifest['folds'])!=5 or {f['fold'] for f in manifest['folds']}!=set(range(5)):raise ValueError('Need all five folds')
    allheld=[]
    for fold in manifest['folds']:
        for role in ('prior_fit','expanded_fit','calibration','held','excluded_new_calibration','prior_held','targeted_held'):
            if len(fold[role])!=len(set(fold[role])) or not set(fold[role])<=set(keys):raise ValueError('Invalid split SHA coverage')
        if (set(fold['prior_fit'])!=set(fold['expanded_fit'])-new or set(fold['calibration'])&new
                or set(fold['excluded_new_calibration'])-new
                or set(fold['prior_held'])!=set(fold['held'])-new or set(fold['targeted_held'])!=set(fold['held'])&new):
            raise ValueError('Matched arm role separation differs')
        r.c.assert_split(rows,groups,[[index[k] for k in fold[role]] for role in ('expanded_fit','held')]+
                         [[index[k] for k in fold['calibration']+fold['excluded_new_calibration']]])
        allheld.extend(fold['held'])
    if len(allheld)!=len(keys) or set(allheld)!=set(keys):raise ValueError('Every SHA must be held once')
    result={};models={};hashes={};maximum=0.
    for variant in t.VARIANTS:
        X,schema=data[variant]
        for arm in t.ARMS:
            tag=variant+'/'+arm;detail=summary['arms'][tag];file=run/tag/'development-scores.json'
            hashes[str(file)]=cache.digest(file);records=cache.read(file);lookup={rec['sha256']:rec for rec in records}
            if len(records)!=len(keys) or set(lookup)!=set(keys):raise ValueError('Saved held score coverage differs')
            folds={f['fold']:f for f in detail['folds']}
            for fold in manifest['folds']:
                n=fold['fold'];saved=folds[n];model_path=run/tag/f'fold-{n:02d}-model.json'
                hashes[str(model_path)]=cache.digest(model_path);model=cache.read(model_path)
                if model['feature_names']!=schema or model.get('development_only') is not True:raise ValueError('Saved model/schema differs')
                fit=fold['prior_fit' if arm=='prior_only' else 'expanded_fit']
                threshold=saved['calibration']['threshold']
                if saved['fit_count']!=len(fit) or saved['added_fit_count']!=len(set(fit)&new) or model['reviewer_threshold']!=threshold:
                    raise ValueError('Saved model/fit counts/threshold differ')
                models[(tag,n)]=model
                for role in ('calibration','held'):
                    ids=[index[k] for k in fold[role]];selected=[rows[i] for i in ids]
                    scores=training_order_scores(model,X[ids]);pred=r.g.gated(selected,scores,threshold)
                    if role=='calibration':
                        if r.g.f.w.metrics(selected,pred)!=saved['calibration']['overall']:raise ValueError('Calibration replay differs')
                        for cohort,ci in r.s.software_ids(selected,entries).items():
                            expected=saved['calibration']['software_benign'][cohort]
                            if expected['count']!=len(ci) or expected['fp']!=int(pred[ci].sum()):raise ValueError('Calibration cohort replay differs')
                    else:
                        fixed=r.g.gated(selected,scores,r.g.REFERENCE_THRESHOLD)
                        for i,k in enumerate(fold[role]):
                            rec=lookup[k];error=abs(float(scores[i])-rec['reviewer_score']);maximum=max(maximum,error)
                            if (error>1e-9 or any(rec[field]!=entries[k]['record'][field] for field in ('label','source'))
                                    or rec['fold']!=n or rec['targeted']!=(k in new)
                                    or rec['software_prediction']!=int(pred[i]) or rec['fixed_prediction']!=int(fixed[i])):
                                raise ValueError('Held score/gate replay differs: '+k)
                for population,shas in (('prior',fold['prior_held']),('targeted',fold['targeted_held'])):
                    for policy in t.POLICIES:
                        actual=r.d.group_metrics([entries[k]['record'] for k in shas],np.asarray([lookup[k][policy+'_prediction'] for k in shas]),groups) if shas else None
                        if actual!=saved['held'][population][policy]:raise ValueError('Fold summary replay differs')
            for population,shas in (('prior',[k for k in keys if k not in new]),('targeted',sorted(new))):
                for policy in t.POLICIES:
                    actual=r.d.group_metrics([entries[k]['record'] for k in shas],np.asarray([lookup[k][policy+'_prediction'] for k in shas]),groups)
                    if actual!=detail['pooled'][population][policy]:raise ValueError('Pooled summary replay differs')
            result[tag]=lookup
    return result,models,hashes,maximum


def analyze(entries,names,features,new,summary,manifest,records,models):
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)};groups=manifest['groups'];X,schema=r.matrices(entries,names,features)['plus_imports']
    before='plus_imports/prior_only';after='plus_imports/targeted_fit_added';fold_details=[]
    for fold in manifest['folds']:
        n=fold['fold'];shas=fold['prior_held'];rows=[entries[k]['record'] for k in shas]
        bp=np.asarray([records[before][k]['reviewer_score'] for k in shas]);ap=np.asarray([records[after][k]['reviewer_score'] for k in shas])
        bt=next(f for f in summary['arms'][before]['folds'] if f['fold']==n)['calibration']['threshold'];at=next(f for f in summary['arms'][after]['folds'] if f['fold']==n)['calibration']['threshold']
        lost=[k for k in shas if entries[k]['record']['label']==1 and records[before][k]['software_prediction']==1 and records[after][k]['software_prediction']==0]
        rescued=[k for k in shas if entries[k]['record']['label']==1 and records[before][k]['software_prediction']==0 and records[after][k]['software_prediction']==1]
        lp=np.asarray([records[before][k]['reviewer_score'] for k in lost]);la=np.asarray([records[after][k]['reviewer_score'] for k in lost])
        detail=dict(fold=n,threshold_before=bt,threshold_after=at,malware_regressed=lost,malware_rescued=rescued,
            regression_groups=change_groups(lost,[entries[k]['record'] for k in lost],groups,lp,la,bt,at) if lost else [],
            descriptive_threshold_swap=dict(old_model_old_threshold=r.g.f.w.metrics(rows,r.g.gated(rows,bp,bt)),
                old_model_new_threshold=r.g.f.w.metrics(rows,r.g.gated(rows,bp,at)),
                new_model_old_threshold=r.g.f.w.metrics(rows,r.g.gated(rows,ap,bt)),
                new_model_new_threshold=r.g.f.w.metrics(rows,r.g.gated(rows,ap,at))))
        fold_details.append(detail)
    targets=[]
    fold4=next(x for x in fold_details if x['fold']==4)
    for group in fold4['regression_groups'][:12]:targets.append(min(group['sha256'],key=lambda k:records[after][k]['reviewer_score']-records[before][k]['reviewer_score']))
    targets.extend(k for k in sorted(new) if records[after][k]['software_prediction']==1)
    profiles=[]
    for k in dict.fromkeys(targets):
        n=records[after][k]['fold'];fold=next(f for f in manifest['folds'] if f['fold']==n);added=sorted(set(fold['expanded_fit'])&new)
        fit=[index[s] for s in fold['prior_fit']];parameters=p.normalizer(X[fit]);scaled=p.transform(X,parameters)
        nearest=sorted(added,key=lambda s:(float(np.mean(abs(scaled[index[k]]-scaled[index[s]]))),s))[:3]
        info=entries[k];vector=X[index[k]];changes=tree_changes(models[(before,n)],models[(after,n)],vector)
        profiles.append(dict(sha256=k,fold=n,label=info['record']['label'],source=info['record']['source'],group=groups[k],
            before_score=records[before][k]['reviewer_score'],after_score=records[after][k]['reviewer_score'],
            libraries=info['libraries'],provenance=info.get('provenance'),features=dict(zip(schema,map(float,vector))),
            tree_changes=changes,nearest_added_fit=[dict(sha256=s,source=entries[s]['record']['source'],
                provenance=entries[s].get('provenance'),mean_normalized_feature_distance=float(np.mean(abs(scaled[index[k]]-scaled[index[s]]))),
                differing_features=[dict(feature=schema[j],target_value=float(vector[j]),added_value=float(X[index[s],j]))
                    for j in np.flatnonzero(vector!=X[index[s]])]) for s in nearest]))
    return dict(folds=fold_details,profiles=profiles,targeted_false_positives=[k for k in sorted(new) if records[after][k]['software_prediction']==1])


def run(args):
    directory=(args.run or latest(args.root)).resolve();identity=cache.read(directory/'inputs.json')
    cache.verify_hashes(identity['input_sha256'])
    if identity['input_sha256'].get(str(Path(t.__file__).resolve()))!=cache.digest(t.__file__):raise ValueError('Original experiment script binding differs')
    def bound(name):
        paths=[Path(s) for s in identity['input_sha256'] if Path(s).name==name]
        if len(paths)!=1:raise ValueError('Expected one bound '+name)
        return paths[0].parent
    args2=SimpleNamespace(root=args.root,prior_cache=bound('rich-feature-summary.json'),targeted_cache=bound('targeted-feature-summary.json'),structural_bundle=args.structural_bundle)
    entries,names,features,new,hashes=t.load_inputs(args2);hashes.update(identity['input_sha256'])
    summary=cache.read(directory/'targeted-coverage-summary.json');manifest=cache.read(directory/'split-manifest.json')
    if (summary.get('complete') is not True or summary.get('independent_validation') is not False
            or summary['sample_count']!=len(entries) or summary['targeted_count']!=len(new)):
        raise ValueError('Completed development experiment required')
    for name in ('inputs.json','split-manifest.json','targeted-coverage-summary.json'):
        path=directory/name;hashes[str(path)]=cache.digest(path)
    print('Replaying 20 saved models and original calibration/held decisions...',flush=True)
    records,models,model_hashes,maximum=replay(entries,names,features,new,directory,summary,manifest);hashes.update(model_hashes)
    result=analyze(entries,names,features,new,summary,manifest,records,models)
    result.update(complete=True,training=False,threshold_tuning=False,model_changes=False,held_threshold_search=False,
        role='posthoc_targeted_coverage_descriptive_audit',source_run=str(directory),replay_max_abs_error=maximum,
        limitations='Threshold swaps are fixed descriptive contrasts, not proposed policies. Representation groups and nearest files are not verified families or causal training influence. Fit-only normalization; no fitting or source edits.')
    for module in (t,p,p.a,r,cache):hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__);cache.verify_hashes(hashes)
    r.g.f.fresh_output(args.output);cache.dump(args.output/'inputs.json',dict(input_sha256=hashes,source_run=str(directory)))
    cache.dump(args.output/'targeted-coverage-audit-summary.json',result)
    print(f'Complete: {args.output}\nSend targeted-coverage-audit-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default: newest completed targeted coverage experiment')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-targeted-coverage-audit-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.root=root;args.structural_bundle=args.structural_bundle.resolve()
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 targeted coverage audit stopped: {error}\n')


if __name__=='__main__':main()
