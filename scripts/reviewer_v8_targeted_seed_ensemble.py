#!/usr/bin/env python3
"""Equal-probability five-seed ensemble on fixed development splits; no fitting."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import reviewer_v8_targeted_seed_stability as s

t,r,cache,audit=s.t,s.r,s.cache,s.audit


def mean_probability(values):
    values=np.asarray(values,dtype=float)
    if values.ndim!=2 or values.shape[0]!=len(s.SEEDS) or not np.isfinite(values).all() or np.any((values<0)|(values>1)):
        raise ValueError('Need five finite probability vectors in fixed seed order')
    return values.mean(axis=0)


def ensemble(entries,names,features,new,manifest,models,watch,output):
    if set(models)!=set(s.SEEDS):raise ValueError('All five seeds required')
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)};data=r.matrices(entries,names,features)
    result=dict(complete=False,training=False,ensemble=True,weights=[.2]*5,seeds=list(s.SEEDS),
        independent_validation=False,deployment_changed=False,final_refit=False,seed_selection=False,
        held_threshold_search=False,split_search=False,arms={},paired_coverage={},paired_imports={},watch_groups={},
        scope='Inspected development data, equal average of all five probabilities. Per-fold thresholds use original common calibration only; fixed threshold is diagnostic.')
    lookups={}
    for variant in t.VARIANTS:
        X,_=data[variant]
        for arm in t.ARMS:
            tag=variant+'/'+arm;records=[];details=[]
            for fold in manifest['folds']:
                n=fold['fold'];cal=fold['calibration'];held=fold['held']
                cr=[entries[k]['record'] for k in cal];hr=[entries[k]['record'] for k in held]
                def scores(shas):
                    return mean_probability([audit.training_order_scores(models[seed][(tag,n)],X[[index[k] for k in shas]]) for seed in s.SEEDS])
                cp=scores(cal)
                policy=r.c.assess_policy(r.s.software_calibration(cr,cp,entries),fold['calibration_diversity'])
                # Threshold is committed before held probabilities are computed.
                hp=scores(held);predictions={p:r.g.gated(hr,hp,policy['threshold'] if p=='software' else r.g.REFERENCE_THRESHOLD) for p in t.POLICIES}
                details.append(dict(fold=n,calibration=policy,calibration_count=len(cal),held_count=len(held)))
                records.extend(dict(sha256=k,label=hr[i]['label'],source=hr[i]['source'],fold=n,targeted=k in new,
                    reviewer_score=float(hp[i]),**{p+'_prediction':int(pred[i]) for p,pred in predictions.items()}) for i,k in enumerate(held))
            lookup={x['sha256']:x for x in records}
            if len(records)!=len(keys) or set(lookup)!=set(keys):raise ValueError('Ensemble held coverage differs')
            pooled={}
            for population,shas in (('prior',[k for k in keys if k not in new]),('targeted',sorted(new))):
                pooled[population]={p:r.d.group_metrics([entries[k]['record'] for k in shas],np.asarray([lookup[k][p+'_prediction'] for k in shas]),manifest['groups']) for p in t.POLICIES}
            result['arms'][tag]=dict(folds=details,pooled=pooled,
                all_software_policies_eligible=all(x['calibration']['eligible_development_policy'] for x in details),
                targeted_false_positive_sha256=[k for k in sorted(new) if lookup[k]['software_prediction']])
            for group,shas in watch.items():
                selected=[lookup[k] for k in shas];folds={x['fold'] for x in selected}
                if len(folds)!=1:raise ValueError('Watch group crossed folds')
                threshold=next(x['calibration']['threshold'] for x in details if x['fold']==next(iter(folds)))
                probabilities=[x['reviewer_score'] for x in selected]
                result['watch_groups'].setdefault(group,{})[tag]=dict(count=len(shas),held_fold=next(iter(folds)),
                    detected=sum(x['software_prediction'] for x in selected),score_min=min(probabilities),score_max=max(probabilities),
                    threshold=threshold,minimum_score_margin=min(probabilities)-threshold,maximum_score_margin=max(probabilities)-threshold)
            lookups[tag]=lookup;cache.dump(output/tag/'development-scores.json',records)
    def paired(before,after):
        return {population:{p:r.a.paired([entries[k]['record'] for k in shas],
                    [lookups[before][k][p+'_prediction'] for k in shas],
                    [lookups[after][k][p+'_prediction'] for k in shas])['overall'] for p in t.POLICIES}
                for population,shas in (('prior',[k for k in keys if k not in new]),('targeted',sorted(new)))}
    for variant in t.VARIANTS:result['paired_coverage'][variant]=paired(variant+'/prior_only',variant+'/targeted_fit_added')
    for arm in t.ARMS:result['paired_imports'][arm]=paired('structural_control/'+arm,'plus_imports/'+arm)
    return result


def latest(root):
    candidates=[p.parent for p in root.glob('reviewer-v8-targeted-seed-stability-*/targeted-seed-stability-summary.json') if cache.read(p).get('complete')]
    if not candidates:raise ValueError('No completed five-seed stability run')
    return max(candidates,key=lambda p:(p.stat().st_mtime,str(p)))


def run(args):
    source=(args.run or latest(args.root)).resolve();identity=cache.read(source/'inputs.json')
    report=cache.read(source/'targeted-seed-stability-summary.json');manifest=cache.read(source/'split-manifest.json')
    if (not report.get('complete') or report['completed_seeds']!=list(s.SEEDS) or identity['training_seeds']!=list(s.SEEDS)
        or report.get('seed_selection') is not False):raise ValueError('Need completed prespecified five-seed run')
    cache.verify_hashes(identity['input_sha256'])
    def bound(name):
        paths=[Path(p) for p in identity['input_sha256'] if Path(p).name==name]
        if len(paths)!=1:raise ValueError('Need one bound '+name)
        return paths[0].parent
    entries,names,features,new,hashes=t.load_inputs(SimpleNamespace(root=args.root,prior_cache=bound('rich-feature-summary.json'),
        targeted_cache=bound('targeted-feature-summary.json'),structural_bundle=args.structural_bundle))
    if cache.read(source/'excluded-sha256.json')!=sorted(entries):raise ValueError('Exclusion coverage differs')
    hashes.update(identity['input_sha256']);models={};maximum=0.
    for seed in s.SEEDS:
        folder=source/f'seed-{seed}';marker=folder/'completion.json';completed=cache.read(marker)
        if completed.get('complete') is not True or completed['seed']!=seed:raise ValueError('Invalid seed completion')
        cache.verify_hashes(completed['artifact_sha256']);hashes.update(completed['artifact_sha256'])
        destination=Path(identity['source_run']) if seed==s.SEEDS[0] else folder
        summary=cache.read(destination/'targeted-coverage-summary.json')
        if not summary.get('complete') or (seed!=s.SEEDS[0] and summary.get('training_seed')!=seed):raise ValueError('Seed summary identity differs')
        print(f'Replaying saved seed {seed}; no fits...',flush=True)
        records,models[seed],bindings,error=audit.replay(entries,names,features,new,destination,summary,manifest)
        actual=s.summarize_seed(seed,summary,records,entries,new,manifest['groups'],identity['watch_groups'])
        if actual!=report['per_seed'][s.SEEDS.index(seed)] or actual!=cache.read(folder/'seed-summary.json'):
            raise ValueError('Seed report differs from replay')
        hashes.update(bindings);maximum=max(maximum,error)
        for path in (marker,destination/'targeted-coverage-summary.json'):hashes[str(path)]=cache.digest(path)
    for path in (source/'inputs.json',source/'split-manifest.json',source/'excluded-sha256.json',source/'targeted-seed-stability-summary.json'):
        hashes[str(path)]=cache.digest(path)
    for module in (s,audit,t,r,cache):hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__)
    cache.verify_hashes(hashes);r.g.f.fresh_output(args.output)
    cache.dump(args.output/'inputs.json',dict(source_run=str(source),input_sha256=hashes,seeds=list(s.SEEDS),weights=[.2]*5))
    cache.dump(args.output/'split-manifest.json',manifest);cache.dump(args.output/'excluded-sha256.json',sorted(entries))
    result=ensemble(entries,names,features,new,manifest,models,identity['watch_groups'],args.output)
    result['saved_seed_replay_max_abs_error']=maximum
    result['single_seed_reference']=report['aggregate']
    cache.verify_hashes(hashes);result['complete']=True
    cache.dump(args.output/'targeted-seed-ensemble-summary.json',result)
    print(f'Complete: {args.output}\nSend targeted-seed-ensemble-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default: newest completed five-seed stability run')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-targeted-seed-ensemble-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.root=root;args.output=args.output.resolve();args.structural_bundle=args.structural_bundle.resolve()
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 targeted seed ensemble stopped: {error}\n')


if __name__=='__main__':main()
