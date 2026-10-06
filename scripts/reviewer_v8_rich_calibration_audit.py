#!/usr/bin/env python3
"""Read-only replay of completed rich ablation calibration; no held threshold search."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
from pathlib import Path
import traceback

import numpy as np
from scipy.special import expit
import reviewer_v8_rich_ablation as r

g, s, cache = r.g, r.s, r.cache


def training_order_scores(payload, X):
    """Match sklearn's sequential raw-score accumulation, without fitting."""
    X = np.asarray(X, dtype=np.float32)
    raw = np.full(len(X), float(payload['initial_raw_score']))
    for tree in payload['estimators']:
        leaves = []
        for vector in X:
            node = 0
            while tree['children_left'][node] >= 0:
                left = vector[tree['feature'][node]] <= tree['threshold'][node]
                node = tree['children_left' if left else 'children_right'][node]
            leaves.append(tree['raw_value'][node])
        raw += float(payload['learning_rate']) * np.asarray(leaves)
    return expit(raw)


def constraints(rows, entries, policy):
    benign = np.array([x['label'] == 0 for x in rows])
    result = [('overall', np.flatnonzero(benign))]
    for source in sorted({x['source'] for x in rows}):
        ids = np.array([i for i,x in enumerate(rows) if x['label']==0 and x['source']==source], dtype=int)
        if len(ids) >= 100:
            result.append(('source:'+source, ids))
    if policy == 'software':
        result.extend((k,v) for k,v in sorted(s.software_ids(rows,entries).items()) if len(v)>=s.MIN_SOFTWARE_BENIGN)
    return result


def threshold_table(rows, scores, entries, policy):
    """Vectorized exact candidate grid and the original lexicographic objective."""
    scores = np.asarray(scores, dtype=float)
    if not np.isfinite(scores).all():
        raise ValueError('Nonfinite scores')
    labels = np.array([x['label'] for x in rows])
    if set(labels) != {0,1}:
        raise ValueError('Both calibration classes required')
    routed = np.array([x['adapter_probability'] >= g.ROUTE for x in rows])
    fixed = np.array([x['adapter_probability'] >= g.ADAPTER_THRESHOLD for x in rows]) & ~routed
    unique = np.unique(scores)
    thresholds = np.unique(np.r_[unique,np.nextafter(unique,np.inf),1.])
    thresholds = thresholds[(thresholds>0)&(thresholds<=1)]
    def positives(ids):
        ordered = np.sort(scores[ids[routed[ids]]])
        return len(ordered)-np.searchsorted(ordered,thresholds,side='left')+int(fixed[ids].sum())
    ids = np.flatnonzero(labels==1)
    tp = positives(ids)
    cons = constraints(rows,entries,policy)
    fps = np.asarray([positives(ids) for _,ids in cons])
    rates = fps / np.asarray([len(ids) for _,ids in cons])[:,None]
    worst = rates[1:].max(axis=0) if len(cons)>1 else np.zeros(len(thresholds))
    feasible = (rates.max(axis=0)<=.01+1e-15)
    candidates = np.flatnonzero(feasible)
    if not len(candidates):
        raise ValueError('No feasible calibration policy')
    best = max(candidates,key=lambda i:(int(tp[i]),-float(worst[i]),-int(fps[0,i]),float(thresholds[i])))
    return dict(thresholds=thresholds,tp=tp,fps=fps,rates=rates,worst=worst,
                feasible=feasible,best=int(best),constraints=cons,
                benign=int(sum(labels==0)),malicious=len(ids))


def audit_policy(rows, scores, entries, policy, saved, detail_limit=100):
    t = threshold_table(rows,scores,entries,policy)
    best = t['best']; thresholds=t['thresholds']; tp=t['tp']; fps=t['fps']
    if abs(float(thresholds[best])-saved['threshold'])>1e-10:
        raise ValueError(f'{policy} selected threshold does not reproduce')
    expected=saved['overall']
    if (int(tp[best]),int(fps[0,best]),t['benign'],t['malicious']) != (
            expected['malicious']-expected['fn'],expected['fp'],expected['benign'],expected['malicious']):
        raise ValueError(f'{policy} calibration counts do not reproduce')
    def point(i):
        return dict(threshold=float(thresholds[i]),tp=int(tp[i]),fp=int(fps[0,i]),
                    tpr=float(tp[i]/t['malicious']),fpr=float(fps[0,i]/t['benign']),
                    feasible=bool(t['feasible'][i]),worst_constrained_cohort_fpr=float(t['worst'][i]),
                    constraints=[dict(name=name,count=len(ids),fp=int(fps[n,i]),
                                      fpr=float(t['rates'][n,i]),violates_cap=bool(t['rates'][n,i]>.01+1e-15))
                                 for n,(name,ids) in enumerate(t['constraints'])])
    # All alternatives use calibration labels only. No held predictions generated.
    plateau=np.flatnonzero(t['feasible'] & (tp==tp[best]))
    same_rank=plateau[(t['worst'][plateau]==t['worst'][best]) & (fps[0,plateau]==fps[0,best])]
    higher=np.flatnonzero((thresholds<thresholds[best]) & (tp>tp[best]))
    next_recall=int(higher[-1]) if len(higher) else None
    chosen=g.gated(rows,scores,float(thresholds[best]))
    details=[]
    if next_recall is not None:
        pred=g.gated(rows,scores,float(thresholds[next_recall]))
        new_fp=set(np.flatnonzero((pred>chosen) & np.array([x['label']==0 for x in rows])))
        for n,(name,ids) in enumerate(t['constraints']):
            if t['rates'][n,next_recall] <= .01+1e-15:
                continue
            additions=sorted(new_fp & set(ids),key=lambda i:(-scores[i],rows[i]['sha256']))
            details.append(dict(constraint=name,new_error_count=len(additions),truncated=len(additions)>detail_limit,
                new_errors=[dict(sha256=rows[i]['sha256'],source=rows[i]['source'],
                    software=g.software_group(entries[rows[i]['sha256']]),score=float(scores[i]))
                            for i in additions[:detail_limit]]))
    reference=g.REFERENCE_THRESHOLD
    pred=g.gated(rows,scores,reference)
    reference_metrics=g.f.w.metrics(rows,pred)
    reference_constraints=[dict(name=name,count=len(ids),fp=int(pred[ids].sum()),fpr=float(pred[ids].mean()),
        violates_cap=bool(pred[ids].mean()>.01+1e-15)) for name,ids in t['constraints']]
    return dict(saved_threshold=saved['threshold'],reproduced=True,selected=point(best),
        lowest_feasible_same_recall=point(int(plateau[0])),
        lowest_threshold_same_full_rank=point(int(same_rank[0])),
        same_recall_plateau_candidate_count=len(plateau),
        pure_threshold_tiebreak_candidate_count=len(same_rank),
        next_lower_threshold_increasing_recall=point(next_recall) if next_recall is not None else None,
        limiting_sample_details=details,
        fixed_reference_calibration=dict(threshold=reference,metrics=reference_metrics,constraints=reference_constraints),
        held_alternative_thresholds_evaluated=False)


def latest_run(root,mode):
    paths=[]
    for path in root.glob('reviewer-v8-rich-ablation-development-*'):
        marker=path/mode/'rich-ablation-summary.json'
        if marker.is_file() and cache.read(marker).get('complete') is True:
            paths.append(path)
    if not paths:
        raise ValueError(f'No completed {mode} rich ablation; supply --run')
    return max(paths,key=lambda p:((p/mode/'rich-ablation-summary.json').stat().st_mtime_ns,str(p)))


def run(args):
    source=(args.run or latest_run(args.root,args.mode)).resolve()
    identity=cache.read(source/'inputs.json')
    cache.verify_hashes(identity['input_sha256'])
    directory=Path(identity['rich_cache'])
    baseline=cache.read(directory/'development-input-cache.json')
    entries,names=baseline['samples'],baseline['feature_names']
    converted=identity['converted_acquisition_sha256']
    features,_=r.validate_cache(directory,entries,names,converted)
    data=r.matrices(entries,names,features)
    panel=source/args.mode
    summary=cache.read(panel/'rich-ablation-summary.json')
    manifest=cache.read(panel/'split-manifest.json')
    if (summary.get('complete') is not True or summary['mode']!=args.mode
            or summary['sample_count']!=len(entries) or manifest['mode']!=args.mode):
        raise ValueError('Completed panel/manifest mismatch')
    keys=sorted(entries); index={k:i for i,k in enumerate(keys)}
    rows=[entries[k]['record'] for k in keys]
    seen=[]
    for fold in manifest['folds']:
        roles=[[index[k] for k in fold[role]] for role in ('fit','calibration','held')]
        r.c.assert_split(rows,manifest['groups'],roles)
        seen.extend(fold['held'])
    if len(seen)!=len(keys) or set(seen)!=set(keys):
        raise ValueError('Held SHA coverage mismatch')
    g.f.fresh_output(args.output)
    hashes={str(source/'inputs.json'):cache.digest(source/'inputs.json'),
            str(panel/'rich-ablation-summary.json'):cache.digest(panel/'rich-ablation-summary.json'),
            str(panel/'split-manifest.json'):cache.digest(panel/'split-manifest.json'),
            str(Path(__file__)):cache.digest(__file__)}
    report=dict(complete=False,role='read_only_development_calibration_audit',mode=args.mode,
                training=False,model_changes=False,held_threshold_search=False,independent_validation=False,
                variants={},limitations='Calibration-only alternatives are descriptive, not approved replacement policies. Held scores are checked only for saved-model parity. Conservative groups are not verified malware families.')
    for variant in args.variant:
        X,schema=data[variant]; old=summary['variants'][variant]
        if old.get('complete') is not True or old['features']!=schema:
            raise ValueError('Variant schema/incomplete fit mismatch')
        saved_scores_path=panel/variant/'development-scores.json'
        saved_records=cache.read(saved_scores_path)
        saved={x['sha256']:x for x in saved_records}
        if len(saved_records)!=len(keys) or set(saved)!=set(keys):
            raise ValueError('Saved score coverage mismatch')
        hashes[str(saved_scores_path)]=cache.digest(saved_scores_path)
        report['variants'][variant]=[]
        folds_by_id={f['fold']:f for f in old['folds']}
        for fold in manifest['folds']:
            n=fold['fold']; print(f'Auditing {variant} fold {n+1}/5',flush=True)
            path=panel/variant/f'fold-{n:02d}-model.json';payload=cache.read(path)
            hashes[str(path)]=cache.digest(path)
            if (payload['feature_names']!=schema or payload.get('development_only') is not True
                    or payload['route_min']!=g.ROUTE
                    or payload['reviewer_threshold']!=folds_by_id[n]['calibration']['software']['threshold']):
                raise ValueError('Saved model metadata mismatch')
            ci=[index[k] for k in fold['calibration']];hi=[index[k] for k in fold['held']]
            cp=training_order_scores(payload,X[ci]);hp=training_order_scores(payload,X[hi])
            parity=max(abs(float(hp[i])-saved[k]['reviewer_score']) for i,k in enumerate(fold['held']))
            if parity>1e-10:
                raise ValueError(f'Saved held scores differ: {parity}')
            for i,k in enumerate(fold['held']):
                rec=saved[k]
                if rec['fold']!=n or rec['label']!=entries[k]['record']['label'] or rec['source']!=entries[k]['record']['source']:
                    raise ValueError('Saved held row mismatch')
            cr=[rows[i] for i in ci]
            audits={policy:audit_policy(cr,cp,entries,policy,folds_by_id[n]['calibration'][policy])
                    for policy in ('ordinary','software')}
            item=dict(fold=n,calibration_count=len(ci),saved_held_score_parity=parity,policies=audits)
            report['variants'][variant].append(item)
            cache.dump(args.output/'rich-calibration-audit-summary.json',report)
    cache.dump(args.output/'inputs.json',dict(source_run=str(source),input_sha256=hashes,
        original_input_sha256=identity['input_sha256'],variants=args.variant,
        dependency_versions={n:importlib.metadata.version(n) for n in ('numpy','scipy','scikit-learn')}))
    report['complete']=True
    cache.dump(args.output/'rich-calibration-audit-summary.json',report)
    print(f'Complete: {args.output}\nSend rich-calibration-audit-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data'
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default newest completed rich ablation for requested mode')
    ap.add_argument('--mode',choices=('template','provenance'),default='template')
    ap.add_argument('--variant',choices=r.VARIANTS,action='append',help='Default control and imports')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-rich-calibration-audit-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    ap.add_argument('--debug',action='store_true')
    args=ap.parse_args();args.root=root;args.variant=args.variant or ['structural_control','plus_imports']
    if len(args.variant)!=len(set(args.variant)):
        ap.error('Do not repeat variants')
    try:
        run(args)
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        raise SystemExit(f'V8 rich calibration audit stopped: {e}')


if __name__=='__main__':
    main()
