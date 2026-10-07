#!/usr/bin/env python3
"""Read-only calibration blockers and coverage score shifts for five-seed ensembles."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace

import numpy as np
import reviewer_v8_targeted_seed_ensemble as e
import reviewer_v8_rich_calibration_audit as c

s,t,r,cache,audit=e.s,e.t,e.r,e.cache,e.audit


def latest(root):
    paths=[p.parent for p in root.glob('reviewer-v8-targeted-seed-ensemble-*/targeted-seed-ensemble-summary.json') if cache.read(p).get('complete')]
    if not paths:raise ValueError('No completed five-seed ensemble run')
    return max(paths,key=lambda p:(p.stat().st_mtime_ns,str(p)))


def score_stats(values):
    values=np.asarray(values,dtype=float)
    return dict(minimum=float(values.min()),median=float(np.median(values)),maximum=float(values.max()))


def calibration_audit(entries,names,features,manifest,models,saved):
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)};data=r.matrices(entries,names,features)
    result=dict(arms={},coverage_score_shifts={},held_watch_groups=saved['watch_groups'],
        explanation='Blockers are calibration benign files that violate caps at the next lower calibration threshold increasing malware recall. Cohort score shifts are descriptive, not causal training influence. Held watch groups use only the original ensemble policy.')
    cal_scores={}
    for variant in t.VARIANTS:
        X,_=data[variant]
        for arm in t.ARMS:
            tag=variant+'/'+arm;folds=[]
            for fold in manifest['folds']:
                n=fold['fold'];shas=fold['calibration'];rows=[entries[k]['record'] for k in shas]
                scores=e.mean_probability([audit.training_order_scores(models[seed][(tag,n)],X[[index[k] for k in shas]]) for seed in s.SEEDS])
                policy=next(f['calibration'] for f in saved['arms'][tag]['folds'] if f['fold']==n)
                details=c.audit_policy(rows,scores,entries,'software',policy,detail_limit=len(rows))
                # Require exact threshold and the complete original policy, not only count agreement.
                actual=r.c.assess_policy(r.s.software_calibration(rows,scores,entries),fold['calibration_diversity'])
                if actual!=policy:raise ValueError('Ensemble calibration policy differs')
                if details['selected']['threshold']!=policy['threshold']:raise ValueError('Threshold grid differs')
                cal_scores[(tag,n)]=scores
                folds.append(dict(fold=n,**details))
            result['arms'][tag]=dict(folds=folds)
    for variant in t.VARIANTS:
        before=variant+'/prior_only';after=variant+'/targeted_fit_added';changes=[]
        for fold in manifest['folds']:
            n=fold['fold'];shas=fold['calibration'];rows=[entries[k]['record'] for k in shas]
            bp=cal_scores[(before,n)];ap=cal_scores[(after,n)]
            bd=next(f for f in result['arms'][before]['folds'] if f['fold']==n)
            ad=next(f for f in result['arms'][after]['folds'] if f['fold']==n)
            cohorts=[]
            for cohort,ids in c.constraints(rows,entries,'software'):
                cohorts.append(dict(cohort=cohort,count=len(ids),before=score_stats(bp[ids]),after=score_stats(ap[ids]),
                    paired_score_change=score_stats(ap[ids]-bp[ids]),
                    calibration_fp_before=int(r.g.gated(rows,bp,bd['saved_threshold'])[ids].sum()),
                    calibration_fp_after=int(r.g.gated(rows,ap,ad['saved_threshold'])[ids].sum())))
            blockers={k['sha256'] for detail in (bd,ad) for cohort in detail['limiting_sample_details'] for k in cohort['new_errors']}
            lookup={k:i for i,k in enumerate(shas)};profiles=[]
            for k in sorted(blockers):
                i=lookup[k];entry=entries[k]
                profiles.append(dict(sha256=k,source=rows[i]['source'],software=r.g.software_group(entry),
                    representation_group=manifest['groups'][k],score_before=float(bp[i]),score_after=float(ap[i]),
                    score_change=float(ap[i]-bp[i]),margin_before=float(bp[i]-bd['saved_threshold']),
                    margin_after=float(ap[i]-ad['saved_threshold']),
                    calibration_fp_before=bool(r.g.gated([rows[i]],bp[i:i+1],bd['saved_threshold'])[0]),
                    calibration_fp_after=bool(r.g.gated([rows[i]],ap[i:i+1],ad['saved_threshold'])[0]),
                    feature_vector=dict(zip(names,entry['feature_vector'])),rich_features=features[k],
                    libraries=r.g.libraries(entry),provenance=entry.get('provenance',{}),input_location=entry.get('input_location')))
            changes.append(dict(fold=n,threshold_before=bd['saved_threshold'],threshold_after=ad['saved_threshold'],
                constrained_benign_cohorts=cohorts,blocker_profiles=profiles))
        result['coverage_score_shifts'][variant]=changes
    return result


def run(args):
    source=(args.run or latest(args.root)).resolve();identity=cache.read(source/'inputs.json');saved=cache.read(source/'targeted-seed-ensemble-summary.json')
    if (saved.get('complete') is not True or identity['seeds']!=list(s.SEEDS) or identity['weights']!=[.2]*5
        or saved.get('training') is not False or saved.get('seed_selection') is not False):raise ValueError('Need completed equal-weight ensemble')
    cache.verify_hashes(identity['input_sha256']);hashes=dict(identity['input_sha256'])
    for module in (e,s,audit,t,r,cache):
        path=str(Path(module.__file__).resolve())
        if hashes.get(path)!=cache.digest(path):raise ValueError('Bound ensemble dependency changed: '+path)
    def bound(name):
        paths=[Path(p) for p in hashes if Path(p).name==name]
        if len(paths)!=1:raise ValueError('Need one bound '+name)
        return paths[0].parent
    entries,names,features,new,input_hashes=t.load_inputs(SimpleNamespace(root=args.root,prior_cache=bound('rich-feature-summary.json'),
        targeted_cache=bound('targeted-feature-summary.json'),structural_bundle=args.structural_bundle))
    hashes.update(input_hashes)
    stability=Path(identity['source_run']);stability_identity=cache.read(stability/'inputs.json');stability_report=cache.read(stability/'targeted-seed-stability-summary.json')
    manifest=cache.read(source/'split-manifest.json')
    if manifest!=cache.read(stability/'split-manifest.json') or cache.read(source/'excluded-sha256.json')!=sorted(entries):raise ValueError('Ensemble split/exclusions differ')
    if stability_report.get('complete') is not True or stability_report['completed_seeds']!=list(s.SEEDS):raise ValueError('Incomplete seed study')
    models={};maximum=0.
    for seed in s.SEEDS:
        folder=stability/f'seed-{seed}';marker=cache.read(folder/'completion.json')
        if marker.get('complete') is not True or marker['seed']!=seed:raise ValueError('Seed completion differs')
        cache.verify_hashes(marker['artifact_sha256'])
        location=Path(stability_identity['source_run']) if seed==s.SEEDS[0] else folder
        summary=cache.read(location/'targeted-coverage-summary.json')
        print(f'Replaying seed {seed} for calibration audit...',flush=True)
        records,models[seed],bindings,error=audit.replay(entries,names,features,new,location,summary,manifest)
        if any(hashes.get(p)!=digest for p,digest in bindings.items()):raise ValueError('Saved seed models/scores not bound to ensemble')
        actual=s.summarize_seed(seed,summary,records,entries,new,manifest['groups'],stability_identity['watch_groups'])
        if actual!=stability_report['per_seed'][s.SEEDS.index(seed)]:raise ValueError('Saved seed study differs')
        maximum=max(maximum,error)
    # Reproduce the entire saved ensemble and its held score artifacts before auditing.
    with tempfile.TemporaryDirectory() as tmp:
        rebuilt=e.ensemble(entries,names,features,new,manifest,models,stability_identity['watch_groups'],Path(tmp))
        rebuilt.update(complete=True,saved_seed_replay_max_abs_error=maximum,single_seed_reference=stability_report['aggregate'])
        if rebuilt!=saved:raise ValueError('Saved ensemble summary does not reproduce')
        for tag in saved['arms']:
            path=source/tag/'development-scores.json'
            if cache.read(path)!=cache.read(Path(tmp)/tag/'development-scores.json'):raise ValueError('Saved ensemble scores do not reproduce')
            hashes[str(path)]=cache.digest(path)
    for name in ('inputs.json','split-manifest.json','excluded-sha256.json','targeted-seed-ensemble-summary.json'):
        path=source/name;hashes[str(path)]=cache.digest(path)
    for module in (c,):hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__)
    result=calibration_audit(entries,names,features,manifest,models,saved)
    result.update(complete=True,role='five_seed_ensemble_calibration_audit',training=False,model_changes=False,
        threshold_tuning=False,held_threshold_search=False,independent_validation=False,seed_selection=False,
        saved_seed_replay_max_abs_error=maximum,source_run=str(source))
    cache.verify_hashes(hashes);r.g.f.fresh_output(args.output)
    cache.dump(args.output/'inputs.json',dict(source_run=str(source),input_sha256=hashes))
    cache.dump(args.output/'seed-ensemble-calibration-audit-summary.json',result)
    print(f'Complete: {args.output}\nSend seed-ensemble-calibration-audit-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default: newest completed equal-weight ensemble')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-seed-ensemble-calibration-audit-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.root=root;args.output=args.output.resolve();args.structural_bundle=args.structural_bundle.resolve()
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 seed ensemble calibration audit stopped: {error}\n')


if __name__=='__main__':main()
