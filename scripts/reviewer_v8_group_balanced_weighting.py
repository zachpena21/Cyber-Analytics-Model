#!/usr/bin/env python3
"""Fixed-split five-seed group-balanced loss comparison; no seed or split search."""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import numpy as np
import reviewer_v8_seed_ensemble_calibration_audit as calibration_audit

e,s,t,r,cache,audit=(calibration_audit.e,calibration_audit.s,calibration_audit.t,
                    calibration_audit.r,calibration_audit.cache,calibration_audit.audit)
WEIGHT_DEFINITION='Routed fit rows only: N / (2 * G_label * n_label_group). Each class has mass N/2; each representation group within a class has equal mass. Group counts include fit rows only.'


def load_baseline(args):
    source=(args.run or calibration_audit.latest(args.root)).resolve();identity=cache.read(source/'inputs.json');saved=cache.read(source/'targeted-seed-ensemble-summary.json')
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
    versions={k:importlib.metadata.version(k) for k in ('numpy','scipy','scikit-learn')}
    if stability_identity['dependency_versions']!=versions or stability_identity['configuration']!=json.loads(json.dumps(r.g.f.w.CONFIG)):
        raise ValueError('Baseline training dependencies/configuration differ; restore the original environment')
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
    cache.verify_hashes(hashes)
    return entries,names,features,new,hashes,manifest,stability_identity['watch_groups'],saved,stability_report,source


def group_weights(rows,groups):
    ids=np.asarray([i for i,row in enumerate(rows) if row['adapter_probability']>=r.g.ROUTE],dtype=int)
    selected=[rows[i] for i in ids]
    if {row['label'] for row in selected}!={0,1}:raise ValueError('Both routed fit classes required')
    counts=Counter((row['label'],groups[row['sha256']]) for row in selected)
    number={label:sum(y==label for y,group in counts) for label in (0,1)}
    weights=np.asarray([len(ids)/(2*number[row['label']]*counts[(row['label'],groups[row['sha256']])]) for row in selected])
    if not np.isfinite(weights).all() or np.any(weights<=0):raise ValueError('Invalid group weights')
    for label in (0,1):
        if not np.isclose(weights[[row['label']==label for row in selected]].sum(),len(ids)/2,rtol=1e-12):raise ValueError('Class mass differs')
    return ids,weights


def weight_manifest(entries,groups,manifest):
    out=dict(definition=WEIGHT_DEFINITION,folds=[])
    for fold in manifest['folds']:
        arms={}
        for arm in t.ARMS:
            shas=fold['prior_fit' if arm=='prior_only' else 'expanded_fit'];rows=[entries[k]['record'] for k in shas]
            ids,weights=group_weights(rows,groups);selected=[rows[i] for i in ids]
            arms[arm]=dict(routed_fit_count=len(ids),
                class_mass={str(label):float(weights[[row['label']==label for row in selected]].sum()) for label in (0,1)},
                groups_per_class={str(label):len({groups[row['sha256']] for row in selected if row['label']==label}) for label in (0,1)},
                sample_weights={rows[i]['sha256']:float(w) for i,w in zip(ids,weights)})
        out['folds'].append(dict(fold=fold['fold'],arms=arms))
    return out


@contextmanager
def weighted_fitter(groups,seed):
    original=r.g.fit_model
    def fit(X,rows,selected=None,skimmer=False):
        if selected is not None or skimmer:raise ValueError('This experiment supports routed reviewer fitting only')
        ids,weights=group_weights(rows,groups);y=np.asarray([rows[i]['label'] for i in ids])
        clf=r.g.GradientBoostingClassifier(**r.g.f.w.CONFIG,random_state=seed)
        clf.fit(X[ids],y,sample_weight=weights)
        return clf
    r.g.fit_model=fit
    try:yield
    finally:r.g.fit_model=original


def paired_weighting(entries,new,before,after):
    keys=sorted(entries)
    return {tag:{population:{policy:r.a.paired([entries[k]['record'] for k in shas],
                [before[tag][k][policy+'_prediction'] for k in shas],
                [after[tag][k][policy+'_prediction'] for k in shas])['overall'] for policy in t.POLICIES}
            for population,shas in (('prior',[k for k in keys if k not in new]),('targeted',sorted(new)))} for tag in before}


def run(args):
    entries,names,features,new,hashes,manifest,watch,baseline,baseline_stability,source=load_baseline(args)
    for module in (calibration_audit,e,s,t,r,cache,audit):hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__)
    weights=weight_manifest(entries,manifest['groups'],manifest)
    identity=dict(source_run=str(source),input_sha256=hashes,
        seeds=list(s.SEEDS),weight_definition=WEIGHT_DEFINITION,configuration=r.g.f.w.CONFIG,
        dependency_versions={k:importlib.metadata.version(k) for k in ('numpy','scipy','scikit-learn')},
        ensemble_weights=[.2]*5,split_search=False,seed_selection=False,independent_validation=False)
    identity=json.loads(json.dumps(identity))
    if args.resume:
        args.output=args.resume
        if cache.read(args.output/'inputs.json')!=identity or cache.read(args.output/'fit-weight-manifest.json')!=weights:
            raise ValueError('Resume inputs/weight manifest changed; use a new output')
        if cache.read(args.output/'split-manifest.json')!=manifest or cache.read(args.output/'excluded-sha256.json')!=sorted(entries):
            raise ValueError('Resume split/exclusions differ')
    else:
        r.g.f.fresh_output(args.output);cache.dump(args.output/'inputs.json',identity)
        cache.dump(args.output/'fit-weight-manifest.json',weights);cache.dump(args.output/'split-manifest.json',manifest)
        cache.dump(args.output/'excluded-sha256.json',sorted(entries))
    print(f'Output: {args.output}\n100 group-balanced fits; fixed seeds/splits and calibration.',flush=True)
    plans=s.plans_from_manifest(manifest,entries);results=[];models={}
    for seed in s.SEEDS:
        destination=args.output/f'seed-{seed}';marker=destination/'completion.json'
        if marker.is_file():
            completed=cache.read(marker)
            if completed.get('complete') is not True or completed['seed']!=seed:raise ValueError('Invalid seed completion')
            cache.verify_hashes(completed['artifact_sha256']);summary=cache.read(destination/'targeted-coverage-summary.json')
            print(f'Seed {seed}: verifying completed models; skipping fits.',flush=True)
        else:
            print(f'Seed {seed}: group-balanced training...',flush=True)
            with weighted_fitter(manifest['groups'],seed):summary=t.panel(entries,names,features,new,manifest['groups'],plans,destination)
            cache.verify_hashes(hashes);summary.update(complete=True,training_seed=seed,training_weight=WEIGHT_DEFINITION)
            cache.dump(destination/'targeted-coverage-summary.json',summary)
        if (summary.get('complete') is not True or summary.get('training_seed')!=seed or summary.get('training_weight')!=WEIGHT_DEFINITION):
            raise ValueError('Group-balanced seed identity differs')
        records,models[seed],artifact_hashes,_=audit.replay(entries,names,features,new,destination,summary,manifest)
        result=s.summarize_seed(seed,summary,records,entries,new,manifest['groups'],watch)
        cache.dump(destination/'seed-summary.json',result)
        for name in ('targeted-coverage-summary.json','seed-summary.json'):
            path=destination/name;artifact_hashes[str(path)]=cache.digest(path)
        cache.verify_hashes(hashes);cache.dump(marker,dict(complete=True,seed=seed,artifact_sha256=artifact_hashes))
        results.append(result)
        cache.dump(args.output/'group-balanced-weighting-summary.json',dict(complete=False,training=True,
            completed_seeds=[x['seed'] for x in results],planned_seeds=list(s.SEEDS),per_seed=results))
    output=args.output/'group-balanced-ensemble'
    ensemble=e.ensemble(entries,names,features,new,manifest,models,watch,output)
    ensemble.update(complete=True,training_weight=WEIGHT_DEFINITION)
    cache.dump(output/'targeted-seed-ensemble-summary.json',ensemble)
    before={tag:{x['sha256']:x for x in cache.read(Path(identity['source_run'])/tag/'development-scores.json')} for tag in baseline['arms']}
    after={tag:{x['sha256']:x for x in cache.read(output/tag/'development-scores.json')} for tag in ensemble['arms']}
    report=dict(complete=True,role='fixed_split_group_balanced_weighting_development',training=True,
        final_refit=False,deployment_changed=False,independent_validation=False,seed_selection=False,split_search=False,
        held_threshold_search=False,weight_definition=WEIGHT_DEFINITION,completed_seeds=list(s.SEEDS),per_seed=results,
        aggregate=s.aggregate(results),class_balanced_seed_reference=baseline_stability['aggregate'],
        class_balanced_ensemble={k:baseline[k] for k in ('arms','paired_coverage','paired_imports','watch_groups')},
        group_balanced_ensemble=ensemble,paired_weighting=paired_weighting(entries,new,before,after),
        scope='Only routed fit weights change. Fixed representation groups, roles, configuration, five seeds, equal probability averaging, calibration constraints and historical fixed threshold. Inspected development data; no winner automatically selected.')
    cache.verify_hashes(hashes);cache.dump(args.output/'group-balanced-weighting-summary.json',report)
    print(f'Complete: {args.output}\nSend group-balanced-weighting-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default: newest completed class-balanced ensemble')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path);ap.add_argument('--resume',type=Path)
    args=ap.parse_args();args.root=root
    if args.output and args.resume:ap.error('Use either --output or --resume')
    args.output=(args.output or root/('reviewer-v8-group-balanced-weighting-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))).resolve()
    args.structural_bundle=args.structural_bundle.resolve()
    if args.resume:args.resume=args.resume.resolve()
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 group-balanced weighting stopped: {error}\n')


if __name__=='__main__':main()
