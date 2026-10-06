#!/usr/bin/env python3
"""Profile calibration blockers using cached features and saved tree paths only."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import traceback
import numpy as np
import reviewer_v8_rich_calibration_audit as a

r,g,cache=a.r,a.g,a.cache


def leaf_matrix(payload,X):
    X=np.asarray(X,dtype=np.float32);result=np.empty((len(X),len(payload['estimators'])),dtype=int)
    for j,tree in enumerate(payload['estimators']):
        for i,vector in enumerate(X):
            node=0
            while tree['children_left'][node]>=0:
                left=vector[tree['feature'][node]]<=tree['threshold'][node]
                node=tree['children_left' if left else 'children_right'][node]
            result[i,j]=node
    return result


def normalizer(X):
    X=np.asarray(X,dtype=float)
    log=(X.min(axis=0)>=0)&(X.max(axis=0)>1)
    Y=X.copy();Y[:,log]=np.log1p(Y[:,log])
    center=np.median(Y,axis=0);scale=np.quantile(Y,.75,axis=0)-np.quantile(Y,.25,axis=0)
    scale=np.where(scale>1e-12,scale,np.std(Y,axis=0));scale=np.where(scale>1e-12,scale,1.)
    return log,center,scale


def transform(X,parameters):
    log,center,scale=parameters;Y=np.asarray(X,dtype=float).copy()
    # Fit rows alone choose transforms; clamp nonnegative-log columns at zero.
    Y[:,log]=np.log1p(np.maximum(Y[:,log],0))
    return np.clip((Y-center)/scale,-20,20)


def path(payload,vector,tree_id):
    tree=payload['estimators'][tree_id];vector=np.asarray(vector,dtype=np.float32);node=0;steps=[]
    while tree['children_left'][node]>=0:
        f=tree['feature'][node];left=vector[f]<=tree['threshold'][node]
        steps.append(dict(node=node,feature=payload['feature_names'][f],value=float(vector[f]),
                          threshold=tree['threshold'][node],branch='left' if left else 'right'))
        node=tree['children_left' if left else 'children_right'][node]
    return dict(leaf=node,raw_value=tree['raw_value'][node],steps=steps)


def compare(payload,left,right,left_leaves,right_leaves,full_left,full_right,schema,scaled_left,scaled_right):
    changed=np.flatnonzero(left_leaves!=right_leaves)
    trees=[]
    for j in changed:
        tree=payload['estimators'][j]
        delta=payload['learning_rate']*(tree['raw_value'][int(right_leaves[j])]-tree['raw_value'][int(left_leaves[j])])
        trees.append((abs(delta),int(j),float(delta)))
    trees.sort(reverse=True)
    features=[];used=set(payload['feature_names'])
    for j in np.flatnonzero(full_left!=full_right):
        features.append(dict(feature=schema[j],benign_value=float(full_left[j]),comparison_value=float(full_right[j]),
                             normalized_difference=float(abs(scaled_left[j]-scaled_right[j])),used_by_model=schema[j] in used))
    features.sort(key=lambda x:(-x['normalized_difference'],x['feature']))
    return dict(different_leaf_count=len(changed),same_all_model_features=bool(np.array_equal(np.asarray(left,dtype=np.float32),np.asarray(right,dtype=np.float32))),
                differing_feature_count=len(features),feature_differences=features,
                largest_tree_contribution_differences=[dict(tree=j,comparison_minus_benign_raw_contribution=delta,
                    benign_path=path(payload,left,j),comparison_path=path(payload,right,j)) for _,j,delta in trees[:5]])


def latest_audit(root):
    paths=[p for p in root.glob('reviewer-v8-rich-calibration-audit-*')
           if (p/'rich-calibration-audit-summary.json').is_file()
           and cache.read(p/'rich-calibration-audit-summary.json').get('complete') is True]
    if not paths:raise ValueError('No completed calibration audit; supply --audit')
    return max(paths,key=lambda p:((p/'rich-calibration-audit-summary.json').stat().st_mtime_ns,str(p)))


def run(args):
    audit=(args.audit or latest_audit(args.root)).resolve();audit_inputs=cache.read(audit/'inputs.json')
    cache.verify_hashes(audit_inputs['input_sha256']);cache.verify_hashes(audit_inputs['original_input_sha256'])
    report=cache.read(audit/'rich-calibration-audit-summary.json')
    if report.get('complete') is not True or report.get('held_threshold_search') is not False:
        raise ValueError('Requires completed calibration-only audit')
    source=Path(audit_inputs['source_run']);identity=cache.read(source/'inputs.json')
    cache.verify_hashes(identity['input_sha256'])
    directory=Path(identity['rich_cache']);baseline=cache.read(directory/'development-input-cache.json')
    entries,names=baseline['samples'],baseline['feature_names']
    features,_=r.validate_cache(directory,entries,names,identity['converted_acquisition_sha256'])
    matrices=r.matrices(entries,names,features);full,full_names=matrices['plus_all']
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)}
    panel=source/report['mode'];manifest=cache.read(panel/'split-manifest.json')
    summary=cache.read(panel/'rich-ablation-summary.json')
    if not summary.get('complete') or set(manifest['groups'])!=set(keys):raise ValueError('Incomplete panel/manifest')
    hashes={str(audit/'inputs.json'):cache.digest(audit/'inputs.json'),
            str(audit/'rich-calibration-audit-summary.json'):cache.digest(audit/'rich-calibration-audit-summary.json'),
            str(Path(__file__)):cache.digest(__file__)}
    g.f.fresh_output(args.output)
    result=dict(complete=False,role='calibration_blocker_development_profile',mode=report['mode'],training=False,
                threshold_tuning=False,model_changes=False,held_samples_profiled=False,variants={},samples={},
                limitations='Inherited labels and cached provenance are not independent ground-truth verification. Equal tree leaves do not establish equal features or sample families. Paths and neighbors are descriptive, not causal. Normalization is fixed from each original fit split only.')
    def sample(sha):
        e=entries[sha];record=e['record'];feature=features[sha]
        if sha not in result['samples']:
            result['samples'][sha]=dict(sha256=sha,label=record['label'],source=record['source'],
                software=g.software_group(e),original_path=e.get('original_path'),recorded_path=record.get('path') or record.get('input_path') or record.get('original_path'),input_location=e.get('input_location'),
                recovered_location=feature.get('location'),byte_size=feature['byte_size'],libraries=e['libraries'],
                provenance=e.get('provenance'),label_status='inherited; not independently verified',
                rich_parse_status=feature['status'],features=dict(zip(full_names,map(float,full[index[sha]]))))
        return sha
    for variant in args.variant:
        if variant not in report['variants']:raise ValueError(f'Variant absent from audited run: {variant}')
        X,schema=matrices[variant];result['variants'][variant]=[]
        audits={f['fold']:f for f in report['variants'][variant]}
        for fold in manifest['folds']:
            n=fold['fold'];print(f'Profiling {variant} calibration fold {n+1}/5',flush=True)
            roles=[[index[k] for k in fold[role]] for role in ('fit','calibration','held')]
            r.c.assert_split([entries[k]['record'] for k in keys],manifest['groups'],roles)
            fi,ci,_=roles;cr=[entries[keys[i]]['record'] for i in ci]
            model_path=panel/variant/f'fold-{n:02d}-model.json';payload=cache.read(model_path)
            hashes[str(model_path)]=cache.digest(model_path)
            if payload['feature_names']!=schema or payload.get('development_only') is not True:
                raise ValueError('Saved model/schema mismatch')
            cp=a.training_order_scores(payload,X[ci]);leaves=leaf_matrix(payload,X[ci])
            audited=audits[n]['policies']['software'];selected=audited['selected'];lower=audited['next_lower_threshold_increasing_recall']
            pred=g.gated(cr,cp,selected['threshold']);metrics=g.f.w.metrics(cr,pred)
            if (metrics['fp'],metrics['malicious']-metrics['fn'])!=(selected['fp'],selected['tp']):
                raise ValueError('Selected calibration counts differ from audit')
            targets=set();violations=[]
            if lower is not None:
                next_pred=g.gated(cr,cp,lower['threshold']);next_metrics=g.f.w.metrics(cr,next_pred)
                if (next_metrics['fp'],next_metrics['malicious']-next_metrics['fn'])!=(lower['fp'],lower['tp']):
                    raise ValueError('Next-recall calibration counts differ from audit')
                new_fp={i for i,x in enumerate(cr) if x['label']==0 and next_pred[i] and not pred[i]}
                for name,ids in a.constraints(cr,entries,'software'):
                    if next_pred[ids].mean()>.01+1e-15:
                        targets.update(new_fp&set(ids));violations.append(name)
            model_scaled=transform(X[ci],normalizer(X[fi]));full_scaled=transform(full[ci],normalizer(full[fi]))
            grouped=defaultdict(list)
            for i in sorted(targets,key=lambda j:cr[j]['sha256']):grouped[tuple(leaves[i])].append(i)
            profiles=[]
            for signature,ids in sorted(grouped.items(),key=lambda z:(-len(z[1]),cr[z[1][0]]['sha256'])):
                b=ids[0];same=[i for i in range(len(cr)) if tuple(leaves[i])==signature]
                missed=[i for i,x in enumerate(cr) if x['label']==1 and x['adapter_probability']>=g.ROUTE and not pred[i]]
                benign=[i for i,x in enumerate(cr) if x['label']==0 and x['adapter_probability']>=g.ROUTE and not pred[i] and i not in targets]
                # Descriptive deterministic nearest neighbors; calibration only.
                def neighbors(pool):
                    nearest=sorted(pool,key=lambda i:(float(np.abs(model_scaled[b]-model_scaled[i]).mean()),cr[i]['sha256']))[:args.neighbors]
                    output=[]
                    for i in nearest:
                        sha=sample(cr[i]['sha256']);comparison=compare(payload,X[ci[b]],X[ci[i]],leaves[b],leaves[i],
                            full[ci[b]],full[ci[i]],full_names,full_scaled[b],full_scaled[i])
                        output.append(dict(sha256=sha,reviewer_score=float(cp[i]),
                            normalized_model_feature_distance=float(np.abs(model_scaled[b]-model_scaled[i]).mean()),**comparison))
                    return output
                representative_paths=[path(payload,X[ci[b]],j) for j in range(len(payload['estimators']))]
                positive=sorted(range(len(representative_paths)),key=lambda j:(-representative_paths[j]['raw_value'],j))
                split_counts=Counter(step['feature'] for tree in representative_paths for step in tree['steps'])
                profiles.append(dict(representative_sha256=sample(cr[b]['sha256']),reviewer_score=float(cp[b]),
                    most_used_path_features=dict(split_counts.most_common(15)),
                    largest_positive_tree_contributions=[dict(tree=j,raw_contribution=payload['learning_rate']*representative_paths[j]['raw_value'],path=representative_paths[j]) for j in positive[:5] if representative_paths[j]['raw_value']>0],
                    blocker_sha256=[sample(cr[i]['sha256']) for i in ids],blocker_count=len(ids),
                    blocker_unique_model_vectors=len({tuple(np.asarray(X[ci[i]],dtype=np.float32)) for i in ids}),
                    calibration_same_leaf_count=len(same),calibration_same_leaf_labels=dict(Counter(str(cr[i]['label']) for i in same)),
                    calibration_same_leaf_sources=dict(Counter(cr[i]['source'] for i in same)),
                    nearest_missed_calibration_malware=neighbors(missed),nearest_correct_calibration_benign=neighbors(benign)))
            result['variants'][variant].append(dict(fold=n,selected_threshold=selected['threshold'],
                next_recall_threshold=lower['threshold'] if lower else None,violated_constraints=violations,
                blocking_benign_count=len(targets),leaf_profile_count=len(profiles),profiles=profiles))
            cache.dump(args.output/'rich-blocker-profile-summary.json',result)
    result['complete']=True;result['unique_profiled_samples']=len(result['samples'])
    cache.dump(args.output/'rich-blocker-profile-summary.json',result)
    cache.dump(args.output/'inputs.json',dict(audit=str(audit),source_run=str(source),input_sha256=hashes,
        original_input_sha256=identity['input_sha256'],variants=args.variant,neighbors=args.neighbors,
        distance='Fit-only log1p for nonnegative columns above 1; median/IQR, std fallback, clip standardized values to [-20,20]; mean L1.'))
    print(f'Complete: {args.output}\nSend rich-blocker-profile-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--audit',type=Path,help='Default newest completed rich calibration audit')
    ap.add_argument('--variant',choices=r.VARIANTS,action='append',help='Default plus_imports')
    ap.add_argument('--neighbors',type=int,default=3)
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-rich-blocker-profile-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    ap.add_argument('--debug',action='store_true');args=ap.parse_args();args.root=root;args.variant=args.variant or ['plus_imports']
    if not 1<=args.neighbors<=10 or len(set(args.variant))!=len(args.variant):ap.error('Use 1–10 neighbors and unique variants')
    try:run(args)
    except Exception as e:
        if args.debug:traceback.print_exc()
        raise SystemExit(f'V8 rich blocker profile stopped: {e}')


if __name__=='__main__':main()
