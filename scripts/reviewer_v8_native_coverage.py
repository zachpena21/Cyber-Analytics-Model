#!/usr/bin/env python3
"""Class-balanced native coverage comparison on preserved development roles."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import reviewer_v8_group_balanced_weighting as baseline_loader

e,s,t,r,cache,audit = (baseline_loader.e, baseline_loader.s, baseline_loader.t,
                     baseline_loader.r, baseline_loader.cache, baseline_loader.audit)
ARM_MEANING = dict(prior_only='previous coverage, including the earlier targeted files',
                   targeted_fit_added='previous coverage plus native files in fit roles only')


def latest_native(root, prior):
    candidates=[]
    for marker in root.glob('reviewer-v8-targeted-feature-cache-*/targeted-feature-summary.json'):
        doc=cache.read(marker)
        if (doc.get('complete') is True and Path(doc['prior_cache']).resolve()==prior.resolve()
                and Path(doc['inventory']).name.startswith('reviewer-v8-official-native-')):
            candidates.append(marker)
    if not candidates:raise ValueError('No completed official-native feature cache; pass --native-cache')
    return max(candidates,key=lambda p:(p.stat().st_mtime_ns,str(p))).parent


def extend_manifest(entries,names,features,new,old):
    """Preserve old partitions; stop on new links between different old roles."""
    oldkeys=set(old['groups'])
    if set(entries)!=oldkeys|new or oldkeys&new:raise ValueError('Combined SHA coverage differs')
    outer={k:f['fold'] for f in old['folds'] for k in f['held']}
    if set(outer)!=oldkeys or sum(len(f['held']) for f in old['folds'])!=len(oldkeys):
        raise ValueError('Old held coverage differs')
    groups=r.matched_groups(entries,names,features,'template');bins=defaultdict(list)
    for k in sorted(entries):bins[groups[k]].append(k)
    conflicts=[];assignments={};linked=[]
    for group,shas in sorted(bins.items()):
        existing=set(shas)&oldkeys;folds={outer[k] for k in existing}
        if len(folds)>1:conflicts.append(dict(group=group,old_outer_folds=sorted(folds),sha256=shas))
        assigned=next(iter(folds)) if len(folds)==1 else int(hashlib.sha256(
            ('native-coverage:8704:'+group).encode()).hexdigest(),16)%5
        assignments.update({k:assigned for k in shas})
        if set(shas)&new:linked.append(dict(group=group,old_count=len(existing),native_count=len(set(shas)&new),held_fold=assigned))
    for f in old['folds']:
        partitions=(set(f['expanded_fit']),set(f['calibration'])|set(f['excluded_new_calibration']),set(f['held']))
        if set.union(*partitions)!=oldkeys or sum(map(len,partitions))!=len(oldkeys):
            raise ValueError('Old role coverage differs')
        for group,shas in bins.items():
            roles=[i for i,part in enumerate(partitions) if set(shas)&part]
            if len(roles)>1:conflicts.append(dict(group=group,fold=f['fold'],old_roles=roles,sha256=shas))
    split_audit=dict(complete=True,training=False,old_roles_preserved=not conflicts,
        assignment='Linked groups inherit the old outer fold; novel joint groups use SHA256(native-coverage:8704:group) modulo five. No rebalance or split search.',
        conflicts=conflicts,native_groups=linked)
    if conflicts:return None,split_audit
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)};rows=[entries[k]['record'] for k in keys]
    fingerprints={k:r.s.stable_fingerprint(entries[k],names) for k in keys}
    manifest=dict(mode='template',role='preserved_native_coverage_development',groups=groups,folds=[])
    for f in old['folds']:
        held_fold=f['fold'];cal_folds={outer[k] for k in f['calibration']}
        if held_fold in cal_folds or len(cal_folds)!=2:raise ValueError('Expected old two-fold calibration')
        native_held={k for k in new if assignments[k]==held_fold}
        native_cal={k for k in new if assignments[k] in cal_folds}
        native_fit=new-native_held-native_cal
        fold=dict(fold=held_fold,prior_fit=sorted(f['expanded_fit']),
            expanded_fit=sorted(set(f['expanded_fit'])|native_fit),calibration=list(f['calibration']),
            held=sorted(set(f['held'])|native_held),prior_held=list(f['held']),targeted_held=sorted(native_held),
            excluded_new_calibration=sorted(native_cal),excluded_previous_calibration=list(f['excluded_new_calibration']))
        roles=(fold['expanded_fit'],fold['calibration']+fold['excluded_previous_calibration']+fold['excluded_new_calibration'],fold['held'])
        r.c.assert_split(rows,groups,[[index[k] for k in role] for role in roles])
        fold['calibration_diversity']=r.c.diversity([entries[k]['record'] for k in fold['calibration']],groups,fingerprints)
        for role in ('prior_fit','expanded_fit','calibration'):
            selected=[entries[k]['record'] for k in fold[role]]
            if not r.c.diversity(selected,groups,fingerprints)['diverse'] or not r.s.software_diversity(selected,entries)['diverse']:
                raise ValueError('Preserved '+role+' diversity blocked in fold '+str(held_fold))
        manifest['folds'].append(fold)
    return manifest,split_audit


def load_previous_models(source,hashes):
    identity=cache.read(source/'inputs.json');stability=Path(identity['source_run']);study=cache.read(stability/'inputs.json')
    models={};references={}
    for seed in s.SEEDS:
        folder=Path(study['source_run']) if seed==s.SEEDS[0] else stability/f'seed-{seed}'
        models[seed]={};references[seed]={}
        for variant in t.VARIANTS:
            tag=variant+'/targeted_fit_added'
            path=folder/tag/'development-scores.json'
            if hashes.get(str(path))!=cache.digest(path):raise ValueError('Unbound previous scores')
            references[seed][variant]={x['sha256']:x for x in cache.read(path)}
            for fold in range(5):
                path=folder/tag/f'fold-{fold:02d}-model.json'
                if hashes.get(str(path))!=cache.digest(path):raise ValueError('Unbound previous model')
                models[seed][(variant+'/prior_only',fold)]=cache.read(path)
    return models,references


def verify_previous(output,references):
    maximum=0.
    for variant,expected in references.items():
        actual={x['sha256']:x for x in cache.read(output/variant/'prior_only/development-scores.json')}
        for k,old in expected.items():
            current=actual[k];error=abs(current['reviewer_score']-old['reviewer_score']);maximum=max(maximum,error)
            if error>1e-9 or any(current[field]!=old[field] for field in ('fold','label','source','software_prediction','fixed_prediction')):
                raise ValueError('Previous coverage control does not reproduce: '+k)
    return maximum


def populations(output,entries,old_target,native,groups):
    result={};keys=set(entries)
    for variant in t.VARIANTS:
        for arm in t.ARMS:
            tag=variant+'/'+arm;lookup={x['sha256']:x for x in cache.read(output/tag/'development-scores.json')}
            result[tag]={name:{p:r.d.group_metrics([entries[k]['record'] for k in shas],
                np.asarray([lookup[k][p+'_prediction'] for k in shas]),groups) for p in t.POLICIES}
                for name,shas in (('original',sorted(keys-old_target-native)),('earlier_targeted',sorted(old_target)),('native',sorted(native)))}
    return result


def run(args):
    entries,names,features,old_target,hashes,old_manifest,watch,baseline,_,source=baseline_loader.load_baseline(args)
    prior_paths=[Path(p).parent for p in hashes if Path(p).name=='rich-feature-summary.json']
    if len(prior_paths)!=1:raise ValueError('Need one original rich cache')
    prior=prior_paths[0];args.native_cache=args.native_cache or latest_native(args.root,prior)
    extra,extra_names,extra_features,native,bindings=t.load_inputs(SimpleNamespace(root=args.root,prior_cache=prior,
        targeted_cache=args.native_cache,structural_bundle=args.structural_bundle))
    if names!=extra_names or native&set(entries):raise ValueError('Native schema/overlap differs')
    for k in set(extra)-native:
        if entries.get(k)!=extra[k] or features.get(k)!=extra_features[k]:raise ValueError('Original cache identity differs: '+k)
    entries=dict(entries);features=dict(features)
    entries.update({k:extra[k] for k in native});features.update({k:extra_features[k] for k in native})
    if not native or any(entries[k]['record']['label']!=0 for k in native):raise ValueError('Need new benign native files')
    for p,digest in bindings.items():
        if p in hashes and hashes[p]!=digest:raise ValueError('Conflicting input binding: '+p)
    hashes.update(bindings)
    models,references=load_previous_models(source,hashes)
    manifest,split_audit=extend_manifest(entries,names,features,native,old_manifest)
    for module in (baseline_loader,baseline_loader.calibration_audit,e,s,t,r,cache,audit):
        hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__)
    identity=json.loads(json.dumps(dict(source_run=str(source),native_cache=str(args.native_cache.resolve()),
        input_sha256=hashes,seeds=list(s.SEEDS),weights=[.2]*5,arm_meaning=ARM_MEANING,configuration=r.g.f.w.CONFIG,
        dependency_versions={k:importlib.metadata.version(k) for k in ('numpy','scipy','scikit-learn')},
        split_search=False,seed_selection=False,training_weight='class balanced, routed fit rows only')))
    if args.resume:
        args.output=args.resume
        if cache.read(args.output/'inputs.json')!=identity:raise ValueError('Resume inputs changed')
        if cache.read(args.output/'split-manifest.json')!=manifest:raise ValueError('Resume split changed')
        if cache.read(args.output/'excluded-sha256.json')!=sorted(entries):raise ValueError('Resume exclusions changed')
    else:
        r.g.f.fresh_output(args.output);cache.dump(args.output/'inputs.json',identity)
        cache.dump(args.output/'native-split-audit-summary.json',split_audit)
        cache.dump(args.output/'split-manifest.json',manifest);cache.dump(args.output/'excluded-sha256.json',sorted(entries))
    if manifest is None:raise ValueError('New links cross old roles; send native-split-audit-summary.json. No fitting performed.')
    print(f'Output: {args.output}\nPrevious samples: {len(entries)-len(native)}; native: {len(native)}; planned: 50 new class-balanced fits.',flush=True)
    if args.audit_only:
        cache.verify_hashes(hashes)
        print('Split audit complete; no fitting performed. Send native-split-audit-summary.json.',flush=True)
        return
    keys=sorted(entries);index={k:i for i,k in enumerate(keys)};data=r.matrices(entries,names,features);results=[]
    for seed in s.SEEDS:
        folder=args.output/f'seed-{seed}';marker=folder/'completion.json';parities={}
        done=cache.read(marker) if marker.is_file() else None
        if done:
            if done.get('complete') is not True or done['seed']!=seed:raise ValueError('Seed marker differs')
            cache.verify_hashes(done['artifact_sha256']);parities=done['export_parity']
        for variant in t.VARIANTS:
            X,schema=data[variant]
            for fold in manifest['folds']:
                n=fold['fold'];tag=variant+'/targeted_fit_added';path=folder/tag/f'fold-{n:02d}-model.json'
                if not done:
                    fit=[index[k] for k in fold['expanded_fit']];cal=[index[k] for k in fold['calibration']]
                    fr=[entries[k]['record'] for k in fold['expanded_fit']];cr=[entries[k]['record'] for k in fold['calibration']]
                    print(f'Seed {seed}, {variant}, fold {n+1}/5',flush=True)
                    with s.training_seed(seed):clf=r.g.fit_model(X[fit],fr)
                    cp=clf.predict_proba(X[cal])[:,1]
                    policy=r.c.assess_policy(r.s.software_calibration(cr,cp,entries),fold['calibration_diversity'])
                    parities[tag+f'/fold-{n}']=r.g.export_checked(clf,schema,policy['threshold'],X,path)
                    payload=cache.read(path)
                    error=float(np.max(np.abs(audit.training_order_scores(payload,X)-clf.predict_proba(X)[:,1])))
                    if error>1e-10:raise ValueError('Training-order export parity failed')
                else:payload=cache.read(path)
                if payload['feature_names']!=schema or payload.get('development_only') is not True:raise ValueError('Candidate schema differs')
                models[seed][(tag,n)]=payload
        # Repeating one seed five times yields its probability vector; no seed selection.
        result=e.ensemble(entries,names,features,native,manifest,{n:models[seed] for n in s.SEEDS},watch,folder)
        for variant in t.VARIANTS:
            tag=variant+'/targeted_fit_added'
            for fold in result['arms'][tag]['folds']:
                if abs(models[seed][(tag,fold['fold'])]['reviewer_threshold']-fold['calibration']['threshold'])>1e-9:
                    raise ValueError('Candidate calibration threshold replay differs')
        result.update(complete=True,seeds=[seed],weights=[1.],seed=seed,arm_meaning=ARM_MEANING,
            previous_control_max_abs=verify_previous(folder,references[seed]),
            populations=populations(folder,entries,old_target,native,manifest['groups']),export_parity=parities)
        cache.dump(folder/'native-seed-summary.json',result)
        artifacts={str(p):cache.digest(p) for p in folder.rglob('*') if p.is_file() and p!=marker}
        cache.verify_hashes(hashes);cache.dump(marker,dict(complete=True,seed=seed,artifact_sha256=artifacts,export_parity=parities))
        results.append(result)
        cache.dump(args.output/'native-coverage-summary.json',dict(complete=False,completed_seeds=[x['seed'] for x in results],per_seed=results))
    destination=args.output/'ensemble';ensemble=e.ensemble(entries,names,features,native,manifest,models,watch,destination)
    before={v:{x['sha256']:x for x in cache.read(source/v/'targeted_fit_added/development-scores.json')} for v in t.VARIANTS}
    ensemble.update(complete=True,arm_meaning=ARM_MEANING,previous_control_max_abs=verify_previous(destination,before),
        populations=populations(destination,entries,old_target,native,manifest['groups']))
    cache.dump(destination/'native-ensemble-summary.json',ensemble)
    report=dict(complete=True,role='preserved_class_balanced_native_coverage_development',completed_seeds=list(s.SEEDS),
        training=True,new_fit_count=50,sample_count=len(entries),earlier_targeted_count=len(old_target),native_count=len(native),
        arm_meaning=ARM_MEANING,per_seed=results,ensemble=ensemble,original_study_reference=baseline,
        independent_validation=False,deployment_changed=False,final_refit=False,seed_selection=False,split_search=False,
        held_threshold_search=False,scope='Inspected development data. Old fit/calibration/held partitions preserved; new calibration-role files excluded. Historical group metrics can change after safe within-role group merges; both current arms use identical joint groups. Go versions are one project, not independent software families.')
    cache.verify_hashes(hashes);cache.dump(args.output/'native-coverage-summary.json',report)
    print(f'Complete: {args.output}\nSend native-coverage-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Previous completed class-balanced five-seed ensemble')
    ap.add_argument('--native-cache',type=Path,help='Default: newest matching official-native feature cache')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path);ap.add_argument('--resume',type=Path);ap.add_argument('--audit-only',action='store_true')
    args=ap.parse_args();args.root=root
    if args.output and args.resume:ap.error('Use either --output or --resume')
    args.output=(args.output or root/('reviewer-v8-native-coverage-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))).resolve()
    for key in ('run','native_cache','structural_bundle','resume'):
        if getattr(args,key):setattr(args,key,getattr(args,key).resolve())
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 native coverage stopped: {error}\n')


if __name__=='__main__':main()
