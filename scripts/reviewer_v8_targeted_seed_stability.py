#!/usr/bin/env python3
"""Fixed-split, prespecified five-seed coverage stability experiment; no seed selection."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.metadata
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import reviewer_v8_targeted_coverage_audit as audit

t,r,cache=audit.t,audit.r,audit.cache
SEEDS=(8704,8705,8706,8707,8708)


@contextmanager
def training_seed(seed):
    original=r.g.SEED
    r.g.SEED=seed
    try:yield
    finally:r.g.SEED=original


def numeric_summary(values):
    values=np.asarray(values,dtype=float)
    return dict(mean=float(values.mean()),median=float(np.median(values)),minimum=float(values.min()),
                maximum=float(values.max()),standard_deviation=float(values.std(ddof=0)))


def plans_from_manifest(manifest,entries):
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)}
    roles=('prior_fit','expanded_fit','calibration','held','excluded_new_calibration','prior_held','targeted_held')
    return [{k:(np.asarray([index[s] for s in value],dtype=int) if k in roles else value)
             for k,value in fold.items()} for fold in manifest['folds']]


def summarize_seed(seed,summary,records,entries,new,groups,watch):
    result=dict(seed=seed,arms={},paired_coverage=summary['paired_coverage'],paired_imports=summary['paired_imports'],watch_groups={})
    for tag,arm in summary['arms'].items():
        result['arms'][tag]=dict(pooled=arm['pooled'],all_software_policies_eligible=arm['all_software_policies_eligible'],
            thresholds=[dict(fold=f['fold'],threshold=f['calibration']['threshold'],added_fit_count=f['added_fit_count']) for f in arm['folds']],
            export_max_abs_error=max(f['export_parity'] for f in arm['folds']),
            targeted_false_positive_sha256=[k for k in sorted(new) if records[tag][k]['software_prediction']==1])
        for group,shas in watch.items():
            selected=[records[tag][k] for k in shas]
            folds={x['fold'] for x in selected}
            if len(folds)!=1:raise ValueError('Watch group crossed held folds')
            fold=next(iter(folds));threshold=next(f['calibration']['threshold'] for f in arm['folds'] if f['fold']==fold)
            scores=[x['reviewer_score'] for x in selected]
            result['watch_groups'].setdefault(group,{})[tag]=dict(count=len(shas),held_fold=fold,
                detected=sum(x['software_prediction'] for x in selected),score_min=min(scores),score_max=max(scores),threshold=threshold,
                minimum_score_margin=min(scores)-threshold,maximum_score_margin=max(scores)-threshold)
    return result


def aggregate(results):
    out=dict(seed_count=len(results),seeds=[x['seed'] for x in results],arms={},coverage_effect={},watch_groups={},
             interpretation='Descriptive variation across fixed training seeds on one inspected development split. No best seed, independent validation, confidence interval or ensemble selected.')
    for tag in results[0]['arms']:
        out['arms'][tag]={}
        for population in ('prior','targeted'):
            metrics={}
            for field in ('fp','fn','fpr','tpr'):
                vals=[x['arms'][tag]['pooled'][population]['software']['sample_metrics'][field] for x in results]
                if all(v is not None for v in vals):metrics[field]=numeric_summary(vals)
            group_field='equal_weight_malware_group_recall' if population=='prior' else 'equal_weight_benign_group_fpr'
            metrics[group_field]=numeric_summary([x['arms'][tag]['pooled'][population]['software'][group_field] for x in results])
            out['arms'][tag][population]=metrics
    for variant in t.VARIANTS:
        deltas=[]
        for x in results:
            before=x['arms'][variant+'/prior_only']['pooled']['prior']['software']
            after=x['arms'][variant+'/targeted_fit_added']['pooled']['prior']['software']
            deltas.append(dict(seed=x['seed'],additional_malware_detected=before['sample_metrics']['fn']-after['sample_metrics']['fn'],
                additional_benign_false_positives=after['sample_metrics']['fp']-before['sample_metrics']['fp'],
                malware_group_recall_change=after['equal_weight_malware_group_recall']-before['equal_weight_malware_group_recall']))
        out['coverage_effect'][variant]=dict(per_seed=deltas,
            additional_malware_detected=numeric_summary([x['additional_malware_detected'] for x in deltas]),
            additional_benign_false_positives=numeric_summary([x['additional_benign_false_positives'] for x in deltas]),
            malware_group_recall_change=numeric_summary([x['malware_group_recall_change'] for x in deltas]),
            seeds_with_more_malware_detected=sum(x['additional_malware_detected']>0 for x in deltas),
            seeds_with_fewer_malware_detected=sum(x['additional_malware_detected']<0 for x in deltas))
    for group in results[0]['watch_groups']:
        out['watch_groups'][group]={tag:dict(detected=numeric_summary([x['watch_groups'][group][tag]['detected'] for x in results]),
            minimum_score_margin=numeric_summary([x['watch_groups'][group][tag]['minimum_score_margin'] for x in results]))
            for tag in results[0]['arms']}
    return out


def run(args):
    source=(args.run or audit.latest(args.root)).resolve();source_identity=cache.read(source/'inputs.json')
    cache.verify_hashes(source_identity['input_sha256'])
    if source_identity['input_sha256'].get(str(Path(t.__file__).resolve()))!=cache.digest(t.__file__):
        raise ValueError('Original experiment binding differs')
    def bound(name):
        paths=[Path(p) for p in source_identity['input_sha256'] if Path(p).name==name]
        if len(paths)!=1:raise ValueError('Need one bound '+name)
        return paths[0].parent
    entries,names,features,new,hashes=t.load_inputs(SimpleNamespace(root=args.root,prior_cache=bound('rich-feature-summary.json'),
        targeted_cache=bound('targeted-feature-summary.json'),structural_bundle=args.structural_bundle))
    original=cache.read(source/'targeted-coverage-summary.json');manifest=cache.read(source/'split-manifest.json')
    if not original.get('complete') or source_identity['seed']!=SEEDS[0]:raise ValueError('Need completed original seed-8704 experiment')
    print('Verifying the original saved models and fixed splits...',flush=True)
    baseline_records,_,model_hashes,maximum=audit.replay(entries,names,features,new,source,original,manifest)
    hashes.update(source_identity['input_sha256']);hashes.update(model_hashes)
    for name in ('inputs.json','split-manifest.json','targeted-coverage-summary.json'):
        path=source/name;hashes[str(path)]=cache.digest(path)
    for module in (audit,t,r,cache):hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__)
    groups=manifest['groups'];bins={}
    for k in sorted(entries):
        if entries[k]['record']['label']==1:bins.setdefault(groups[k],[]).append(k)
    watch=dict(sorted(bins.items(),key=lambda x:(-len(x[1]),x[0]))[:10])
    identity=dict(source_run=str(source),input_sha256=hashes,training_seeds=list(SEEDS),split_seed=source_identity['seed'],
        configuration=r.g.f.w.CONFIG,variants=t.VARIANTS,arms=t.ARMS,
        dependency_versions={k:importlib.metadata.version(k) for k in ('numpy','scipy','scikit-learn')},
        watch_groups=watch,seed_selection=False,split_search=False,ensemble=False,independent_validation=False)
    # JSON normalizes tuples to lists, so compare the serialized form on resume.
    import json
    identity=json.loads(json.dumps(identity))
    if args.resume:
        args.output=args.resume
        if cache.read(args.output/'inputs.json')!=identity:raise ValueError('Resume identity changed; use a new output')
        if cache.read(args.output/'split-manifest.json')!=manifest or cache.read(args.output/'excluded-sha256.json')!=sorted(entries):
            raise ValueError('Resume split/exclusion copy changed')
    else:
        r.g.f.fresh_output(args.output);cache.dump(args.output/'inputs.json',identity)
        cache.dump(args.output/'split-manifest.json',manifest);cache.dump(args.output/'excluded-sha256.json',sorted(entries))
    print(f'Output: {args.output}\nTraining seeds: {SEEDS}; splits remain fixed.',flush=True)
    plans=plans_from_manifest(manifest,entries);results=[]
    for seed in SEEDS:
        destination=args.output/f'seed-{seed}';completion=destination/'completion.json'
        if seed==SEEDS[0]:
            summary=original;records=baseline_records;artifact_hashes=model_hashes
            print('Seed 8704: reusing parity-checked original results.',flush=True)
        elif completion.is_file():
            completed=cache.read(completion)
            if completed.get('complete') is not True or completed['seed']!=seed:raise ValueError('Invalid completed seed marker')
            cache.verify_hashes(completed['artifact_sha256'])
            summary=cache.read(destination/'targeted-coverage-summary.json')
            if summary.get('complete') is not True or summary.get('training_seed')!=seed:raise ValueError('Completed seed summary/seed differs')
            records,_,artifact_hashes,_=audit.replay(entries,names,features,new,destination,summary,manifest)
            print(f'Seed {seed}: verified completed output; skipping fits.',flush=True)
        else:
            with training_seed(seed):summary=t.panel(entries,names,features,new,groups,plans,destination)
            cache.verify_hashes(hashes);summary['complete']=True;summary['training_seed']=seed
            cache.dump(destination/'targeted-coverage-summary.json',summary)
            records,_,artifact_hashes,_=audit.replay(entries,names,features,new,destination,summary,manifest)
        result=summarize_seed(seed,summary,records,entries,new,groups,watch)
        cache.dump(destination/'seed-summary.json',result)
        for path in (destination/'seed-summary.json',destination/'targeted-coverage-summary.json'):
            if path.is_file():artifact_hashes[str(path)]=cache.digest(path)
        cache.verify_hashes(hashes)
        cache.dump(completion,dict(complete=True,seed=seed,artifact_sha256=artifact_hashes))
        results.append(result)
        report=dict(complete=len(results)==len(SEEDS),role='fixed_split_training_seed_stability_development',
            training=True,independent_validation=False,deployment_changed=False,final_refit=False,seed_selection=False,
            split_search=False,ensemble=False,original_replay_max_abs_error=maximum,
            completed_seeds=[x['seed'] for x in results],planned_seeds=list(SEEDS),per_seed=results,aggregate=aggregate(results))
        cache.dump(args.output/'targeted-seed-stability-summary.json',report)
    cache.verify_hashes(hashes)
    print(f'Complete: {args.output}\nSend targeted-seed-stability-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default: newest completed original targeted coverage experiment')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path)
    ap.add_argument('--resume',type=Path)
    args=ap.parse_args();args.root=root
    if args.output and args.resume:ap.error('Use either --output or --resume')
    args.output=(args.output or root/('reviewer-v8-targeted-seed-stability-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))).resolve()
    args.structural_bundle=args.structural_bundle.resolve()
    if args.resume:args.resume=args.resume.resolve()
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 targeted seed stability stopped: {error}\n')


if __name__=='__main__':main()
