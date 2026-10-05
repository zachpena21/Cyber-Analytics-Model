#!/usr/bin/env python3
"""Matched development experiment: bounded upstream correction to structural scores."""
import argparse
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit
from sklearn.utils.class_weight import compute_sample_weight
import reviewer_v8_sample_diagnostics as q

d,p,a,c,g,s = q.d,q.p,q.a,q.c,q.g,q.s
VARIANT = 'bounded_upstream'
FEATURES = ('benign_probability','adapter_probability','signature_checked','signature_verified')
CONFIG = dict(total_logit_budget=.5,per_coefficient_bound=.125,l2=.01,
              probability_clip=1e-12,optimizer='L-BFGS-B',max_iterations=1000)
CONTROLS = ('full_72','structural_66','without_adapter_71')


def find_previous(root):
    paths=[]
    for path in root.glob('reviewer-v8-sample-diagnostics-*'):
        marker=path/'sample-diagnostic-comparison-summary.json'
        if marker.is_file() and g.f.read(marker).get('complete'):paths.append(path)
    if not paths:raise ValueError('No completed sample diagnostics found; pass --previous')
    return max(paths,key=lambda x:(x.joinpath('sample-diagnostic-comparison-summary.json').stat().st_mtime_ns,str(x)))


def upstream(rows):
    X=np.asarray([[r[n] for n in FEATURES] for r in rows],dtype=float)
    if not np.isfinite(X).all() or np.any((X<0)|(X>1)):
        raise ValueError('Upstream probabilities/signature indicators must be finite within [0,1]')
    # Center probabilities/indicators within [-1,1]. Base probability is benign,
    # so reverse its direction; the learned signs are otherwise unconstrained.
    X=2*X-1;X[:,0]*=-1
    return X


def logits(scores):
    x=np.asarray(scores,dtype=float)
    if not np.isfinite(x).all() or np.any((x<0)|(x>1)):raise ValueError('Invalid structural score')
    x=np.clip(x,CONFIG['probability_clip'],1-CONFIG['probability_clip'])
    return np.log(x)-np.log1p(-x)


def correct(scores,Z,coefficients):
    beta=np.asarray(coefficients,dtype=float)
    if beta.shape!=(len(FEATURES),) or not np.isfinite(beta).all():raise ValueError('Invalid correction coefficients')
    if np.any(np.abs(beta)>CONFIG['per_coefficient_bound']+1e-12):raise ValueError('Correction coefficient exceeds bound')
    if not np.isfinite(Z).all() or np.any(np.abs(Z)>1):raise ValueError('Invalid centered upstream values')
    offset=Z@beta
    if np.any(np.abs(offset)>CONFIG['total_logit_budget']+1e-12):raise ValueError('Correction exceeds total logit budget')
    return expit(logits(scores)+offset),offset


def fit_correction(rows,scores):
    ids=np.array([i for i,r in enumerate(rows) if r['adapter_probability']>=g.ROUTE],dtype=int)
    y=np.array([rows[i]['label'] for i in ids],dtype=float)
    if set(y)!={0,1}:raise ValueError('Both labels required in routed correction fitting rows')
    Z=upstream(rows)[ids];base=logits(np.asarray(scores)[ids]);weights=compute_sample_weight('balanced',y)
    weights=weights/weights.sum()
    def objective(beta):
        z=base+Z@beta
        loss=float(np.sum(weights*(np.logaddexp(0,z)-y*z))+.5*CONFIG['l2']*(beta@beta))
        grad=Z.T@(weights*(expit(z)-y))+CONFIG['l2']*beta
        return loss,grad
    bound=CONFIG['per_coefficient_bound']
    result=minimize(objective,np.zeros(len(FEATURES)),jac=True,method='L-BFGS-B',
                    bounds=[(-bound,bound)]*len(FEATURES),
                    options=dict(maxiter=CONFIG['max_iterations'],ftol=1e-14,gtol=1e-10))
    if not result.success:raise ValueError('Correction optimizer failed: '+str(result.message))
    if result.fun>objective(np.zeros(len(FEATURES)))[0]+1e-10:raise ValueError('Correction increased fitting objective')
    return result.x,dict(routed_fit_count=len(ids),routed_fit_benign=int(sum(y==0)),routed_fit_malware=int(sum(y==1)),
                        objective=float(result.fun),zero_correction_objective=objective(np.zeros(len(FEATURES)))[0],
                        iterations=int(result.nit),converged=bool(result.success),
                        coefficients=dict(zip(FEATURES,map(float,result.x))))


def exported_scores(payload,X,rows):
    if payload['format_version']!='bounded_upstream_development_v1' or payload['configuration']!=CONFIG or payload['upstream_features']!=list(FEATURES):
        raise ValueError('Unsupported bounded-correction export')
    base=g.exported_scores(payload['structural_model'],X)
    return correct(base,upstream(rows),payload['coefficients'])


def experiment_panel(entries,names,partial,output,mode,hashes):
    prior,groups,controls,control_parity=d.checked_panel(entries,names,partial,mode,hashes)
    manifest=g.f.read(partial/mode/'split-manifest.json');keys=sorted(entries);index={k:i for i,k in enumerate(keys)}
    rows=[entries[k]['record'] for k in keys];X,schema=p.matrices(entries,names)['structural_66'];Z=upstream(rows)
    g.f.w.dump(output/'split-manifest.json',manifest)
    result=dict(complete=False,mode=mode,role='bounded_upstream_development',configuration=CONFIG,
                structural_configuration=g.f.w.CONFIG,seed=g.SEED,control_export_max_error=control_parity,
                controls={k:prior['variants'][k]['pooled'] for k in CONTROLS},folds=[],
                limitations='Post-hoc development. Fixed trees plus four-parameter fit-only correction; structural fitting predictions are in-sample. Correction calibration may move thresholds beyond the score-shift bound. No learned category gate, new trees, adapter retraining, production export or untouched validation.')
    records=[]
    for fold in manifest['folds']:
        n=fold['fold'];print(f'{mode} bounded correction fold {n+1}/5',flush=True)
        ids={role:np.array([index[k] for k in fold[role]],dtype=int) for role in ('fit','calibration','held')}
        base_model=g.f.read(partial/mode/'structural_66'/f'fold-{n:02d}-model.json')
        base=g.exported_scores(base_model,X)
        fr=[rows[i] for i in ids['fit']];cr=[rows[i] for i in ids['calibration']];hr=[rows[i] for i in ids['held']]
        beta,fit=fit_correction(fr,base[ids['fit']]);scores,offsets=correct(base,Z,beta)
        cp=scores[ids['calibration']];hp=scores[ids['held']]
        policies=dict(ordinary=g.calibration(cr,cp,lambda t:g.gated(cr,cp,t)),software=s.software_calibration(cr,cp,entries))
        policies={k:c.assess_policy(v,fold['calibration_diversity']) for k,v in policies.items()}
        pred={k:g.gated(hr,hp,v['threshold']) for k,v in policies.items()};pred['fixed']=g.gated(hr,hp,g.REFERENCE_THRESHOLD)
        payload=dict(format_version='bounded_upstream_development_v1',development_only=True,runtime_supported=False,
                     configuration=CONFIG,upstream_features=list(FEATURES),coefficients=list(map(float,beta)),
                     structural_model=base_model,route_min=g.ROUTE,calibration=policies)
        path=output/VARIANT/f'fold-{n:02d}-model.json';g.f.w.dump(path,payload)
        exported,exported_offset=exported_scores(g.f.read(path),X,rows)
        error=float(np.max(np.abs(exported-scores)))
        if error>1e-10 or np.max(np.abs(exported_offset-offsets))>1e-12:raise ValueError('Bounded export parity failed')
        result['folds'].append(dict(fold=n,fit=fit,calibration=policies,export_max_error=error,
            held={k:d.indexed_rates(hr,v,groups) for k,v in pred.items()},
            held_correction=d.distribution(offsets[ids['held']]),max_abs_logit_correction=float(np.max(np.abs(offsets)))))
        for i,row in enumerate(hr):
            records.append(dict(sha256=row['sha256'],label=row['label'],source=row['source'],group=groups[row['sha256']],fold=n,
                structural_score=float(base[ids['held'][i]]),reviewer_score=float(hp[i]),logit_correction=float(offsets[ids['held'][i]]),
                **{k+'_prediction':int(v[i]) for k,v in pred.items()}))
        g.f.w.dump(output/'bounded-upstream-summary.json',result)
        g.f.w.dump(output/VARIANT/'development-scores.json',records)
        hashes[str(path)]=g.digest(path)
    if len(records)!=len(entries) or {r['sha256'] for r in records}!=set(entries):raise ValueError('Candidate held coverage failed')
    lookup={r['sha256']:r for r in records};result['policies']={};result['paired_vs_controls']={}
    for policy in a.POLICIES:
        pred=np.array([lookup[k][policy+'_prediction'] for k in keys])
        cluster=[k for k in keys if groups[k]==d.CLUSTER]
        if len(cluster)!=76 or any(entries[k]['record']['label']!=1 for k in cluster):
            raise ValueError('Preidentified 76-malware cluster changed')
        keep=np.array([i for i,k in enumerate(keys) if groups[k]!=d.CLUSTER])
        result['policies'][policy]=dict(all=d.group_metrics(rows,pred,groups),
            excluding_cluster=d.group_metrics([rows[i] for i in keep],pred[keep],groups),
            by_source=d.indexed_rates(rows,pred,groups)['by_source'])
        for control in CONTROLS:
            before=np.array([controls[control][k][policy+'_prediction'] for k in keys])
            result['paired_vs_controls'].setdefault(control,{})[policy]=dict(all=a.paired(rows,before,pred),
                excluding_cluster=a.paired([rows[i] for i in keep],before[keep],pred[keep]))
    result['all_policies_eligible']={k:all(f['calibration'][k]['eligible_development_policy'] for f in result['folds']) for k in ('ordinary','software')}
    result['complete']=True;g.f.w.dump(output/'bounded-upstream-summary.json',result)
    return result


def main():
    root=g.f.w.ROOT/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--previous',type=Path,help='Completed sample-diagnostic run; default latest completed')
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit',type=Path,action='append');ap.add_argument('--fresh-comparison',type=Path,action='append')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-bounded-upstream-development-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.fresh_audit=args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison=args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        args.previous=args.previous or find_previous(root);print(f'Using completed sample diagnostics: {args.previous}',flush=True)
        old=g.f.read(args.previous/'inputs.json')
        if not g.f.read(args.previous/'sample-diagnostic-comparison-summary.json').get('complete'):raise ValueError('Previous diagnostics incomplete')
        for path,digest in old['input_sha256'].items():
            if g.digest(Path(path))!=digest:raise ValueError('Previous input changed: '+path)
        for module in (q,d,p,a,s,c,g):
            expected=old['script_sha256'] if module is q else old['dependency_sha256'].get(str(Path(module.__file__)))
            if expected!=g.digest(Path(module.__file__)):raise ValueError('Previous dependency changed: '+module.__name__)
        if len(args.fresh_audit)!=len(args.fresh_comparison):raise ValueError('Pair fresh audits and evaluations')
        g.f.fresh_output(args.output);entries,names,hashes,converted=g.load_inputs(args)
        for path,digest in hashes.items():
            if old['input_sha256'].get(path)!=digest:raise ValueError('Current cache differs from previous diagnostics')
        group_inputs=g.f.read(Path(old['previous'])/'inputs.json');partial=Path(group_inputs['previous'])
        combined=dict(complete=False,role='bounded_upstream_development',configuration=CONFIG,modes={})
        for mode in c.MODES:
            panel=experiment_panel(entries,names,partial,args.output/mode,mode,hashes)
            combined['modes'][mode]={k:panel[k] for k in ('control_export_max_error','controls','policies','paired_vs_controls','all_policies_eligible')}
            combined['modes'][mode]['fold_corrections']=[{k:f[k] for k in ('fold','fit','calibration','export_max_error','held_correction','max_abs_logit_correction')} for f in panel['folds']]
            g.f.w.dump(args.output/'bounded-upstream-comparison-summary.json',combined)
        hashes[str(args.previous/'inputs.json')]=g.digest(args.previous/'inputs.json')
        g.f.w.dump(args.output/'inputs.json',dict(previous=str(args.previous),partial=str(partial),input_sha256=hashes,
            script_sha256=g.digest(Path(__file__)),dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in (q,d,p,a,s,c,g)},
            former_evaluation_shas_now_development=converted))
        _,_,excluded=g.f.load_bundle(args.bundle);g.f.w.dump(args.output/'excluded-sha256.json',sorted(excluded|set(entries)))
        combined['complete']=True;g.f.w.dump(args.output/'bounded-upstream-comparison-summary.json',combined)
        print(f'Outputs: {args.output}',flush=True)
    except Exception as error:ap.exit(2,f'V8 bounded upstream experiment stopped: {error}\n')


if __name__=='__main__':main()
