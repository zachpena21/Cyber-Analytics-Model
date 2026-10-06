#!/usr/bin/env python3
"""Matched control/imports development fits with and without targeted benign fit coverage."""
import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import importlib.metadata
import itertools
from pathlib import Path

import numpy as np
import reviewer_v8_rich_ablation as r
import reviewer_v8_targeted_feature_cache as target

VARIANTS = ('structural_control', 'plus_imports')
ARMS = ('prior_only', 'targeted_fit_added')
POLICIES = ('software', 'fixed')


def latest_target(root, prior):
    matches = []
    for path in root.glob('reviewer-v8-targeted-feature-cache-*'):
        marker = path/'targeted-feature-summary.json'
        if marker.is_file():
            summary = r.cache.read(marker)
            if summary.get('complete') is True and Path(summary['prior_cache']).resolve() == prior.resolve():
                matches.append(path)
    if not matches:
        raise ValueError('No completed matching targeted cache; pass --targeted-cache')
    return max(matches, key=lambda p:(p.joinpath('targeted-feature-summary.json').stat().st_mtime_ns,str(p)))


def load_inputs(args):
    import reviewer_v8_structural_validation as v
    prior = r.cache.read(args.prior_cache/'development-input-cache.json')
    report = r.cache.read(args.prior_cache/'rich-feature-summary.json')
    features, hashes = r.validate_cache(args.prior_cache,prior['samples'],prior['feature_names'],report['converted_sha256'])
    args.targeted_cache = args.targeted_cache or latest_target(args.root,args.prior_cache)
    summary = r.cache.read(args.targeted_cache/'targeted-feature-summary.json')
    marker = r.cache.read(args.targeted_cache/'targeted-collection-inputs.json')
    r.cache.verify_hashes(marker['input_sha256'])
    if (summary.get('complete') is not True or summary.get('training') is not False
            or summary.get('threshold_tuning') is not False or summary.get('independent_validation') is not False
            or summary.get('role') != 'targeted_benign_development_feature_collection'
            or Path(summary['prior_cache']).resolve() != args.prior_cache.resolve()):
        raise ValueError('Targeted cache role/prior identity mismatch')
    if marker['input_sha256'].get(str(Path(target.__file__).resolve())) != r.cache.digest(target.__file__):
        raise ValueError('Targeted collector binding missing or changed')
    samples, inventory_hashes = target.inventory_samples(Path(summary['inventory']),args.prior_cache/'excluded-sha256.json')
    baseline = r.cache.read(args.targeted_cache/'targeted-development-input-cache.json')
    extra = r.cache.read(args.targeted_cache/'targeted-rich-feature-cache.json')
    partial = r.cache.read(args.targeted_cache/'partial-targeted-feature-cache.json')
    names = prior['feature_names']
    bundle = v.load_bundle(args.structural_bundle)
    if (baseline.get('complete') is not True or extra.get('complete') is not True
            or baseline['feature_names'] != names or names != list(bundle[3]['v7'][0].feature_names)
            or extra['feature_names'] != list(r.rich.FEATURE_NAMES)
            or extra['blocks'] != {k:list(n) for k,n in r.rich.BLOCKS.items()}
            or marker['baseline_feature_names'] != names or marker['feature_names'] != list(r.rich.FEATURE_NAMES)
            or marker['sample_sha256'] != sorted(samples)
            or any(set(doc['samples']) != set(samples) for doc in (baseline,extra,partial))
            or set(samples) & set(prior['samples']) or set(samples) & bundle[4]):
        raise ValueError('Targeted schema/SHA coverage/overlap mismatch')
    info = marker['service_model'];v.f.c.validate_service(info,bundle[3]['v7'][0])
    for sha, sample in samples.items():
        rebuilt = target.build_sample(sha,sample,partial['samples'][sha]['diagnostic_details'],info,names,v,bundle)
        if (rebuilt != partial['samples'][sha] or rebuilt['entry'] != baseline['samples'][sha]
                or rebuilt['rich'] != extra['samples'][sha]):
            raise ValueError('Targeted saved feature/score replay mismatch: '+sha)
    parity = [e['record']['v7_service_parity_error'] for e in baseline['samples'].values()]
    if (summary['sample_count'] != len(samples) or summary['docker_parity_checked'] != len(samples)
            or any(x is None for x in parity) or summary['docker_parity_max_abs'] != max(parity)
            or summary['by_pattern'] != dict(Counter(s['row']['pattern'] for s in samples.values()))
            or summary['parser_status'] != dict(Counter(f['status'] for f in extra['samples'].values()))
            or summary['combined_development_count'] != len(prior['samples'])+len(samples)
            or r.cache.read(args.targeted_cache/'excluded-sha256.json') != sorted(set(prior['samples'])|set(samples))):
        raise ValueError('Targeted summary/exclusions differ from cache')
    hashes.update(marker['input_sha256']);hashes.update(inventory_hashes)
    for filename in ('targeted-feature-summary.json','targeted-collection-inputs.json','targeted-development-input-cache.json',
                     'targeted-rich-feature-cache.json','partial-targeted-feature-cache.json','excluded-sha256.json'):
        path=args.targeted_cache/filename;hashes[str(path)]=r.cache.digest(path)
    entries = copy.deepcopy(prior['samples']);entries.update(copy.deepcopy(baseline['samples']))
    # Remove only the collector's acquisition prefix so installed-directory
    # cohorts agree with older path-derived directory cohorts. No fuzzy aliases.
    for entry in entries.values():
        nested = (entry.get('provenance') or {}).get('provenance') or {}
        package = nested.get('package')
        if isinstance(package,str) and package.startswith('installed:'):
            nested['package'] = package[len('installed:'):]
    features = dict(features);features.update(extra['samples'])
    return entries,names,features,set(samples),hashes


def make_plan(entries,names,features,new,output):
    """Joint grouping; count-only choice qualifying both arms before any fit."""
    keys=sorted(entries);rows=[entries[k]['record'] for k in keys]
    groups=r.matched_groups(entries,names,features,'template')
    fingerprints={k:r.s.stable_fingerprint(entries[k],names) for k in keys}
    folds=r.g.group_folds(rows,groups,5)
    is_new=np.asarray([k in new for k in keys])
    def profile(ids):
        selected=[rows[i] for i in ids]
        return dict(count=len(ids),labels=dict(Counter(str(x['label']) for x in selected)),
                    malware=r.c.diversity(selected,groups,fingerprints),software=r.s.software_diversity(selected,entries))
    audit=dict(complete=True,training=False,mode='template',candidates=[],blocked_held_folds=[])
    plans=[]
    for held in range(5):
        choices=[]
        for cal_folds in itertools.combinations([n for n in range(5) if n!=held],2):
            joint_cal=np.flatnonzero(np.isin(folds,cal_folds));joint_fit=np.flatnonzero((folds!=held)&~np.isin(folds,cal_folds))
            held_ids=np.flatnonzero(folds==held)
            old_fit=joint_fit[~is_new[joint_fit]];cal=joint_cal[~is_new[joint_cal]]
            profiles=dict(prior_fit=profile(old_fit),expanded_fit=profile(joint_fit),common_calibration=profile(cal))
            failures=[role+'_'+kind for role,p in profiles.items() for kind in ('malware','software') if not p[kind]['diverse']]
            audit['candidates'].append(dict(held_fold=held,calibration_folds=list(cal_folds),eligible=not failures,
                                           blocking_requirements=failures,**profiles))
            if failures:continue
            rank=(-min(len(profiles['prior_fit']['software']['eligible_software_counts']),
                       len(profiles['common_calibration']['software']['eligible_software_counts'])),
                  -len(profiles['common_calibration']['software']['eligible_software_counts']),
                  abs(len(cal)-(len(keys)-len(new))*.4),cal_folds)
            plan=dict(fold=held,prior_fit=old_fit,expanded_fit=joint_fit,calibration=cal,held=held_ids,
                      excluded_new_calibration=joint_cal[is_new[joint_cal]],
                      prior_held=held_ids[~is_new[held_ids]],targeted_held=held_ids[is_new[held_ids]],
                      calibration_diversity=profiles['common_calibration']['malware'],profiles=profiles)
            r.c.assert_split(rows,groups,[joint_fit,joint_cal,held_ids])
            choices.append((rank,plan))
        if choices:plans.append(min(choices,key=lambda x:x[0])[1])
        else:audit['blocked_held_folds'].append(held)
    audit['all_folds_qualify']=not audit['blocked_held_folds']
    r.cache.dump(output/'coverage-split-audit-summary.json',audit)
    manifest=dict(mode='template',role='targeted_coverage_development',groups=groups,folds=[])
    for plan in plans:
        manifest['folds'].append({k:([keys[i] for i in value] if isinstance(value,np.ndarray) else value) for k,value in plan.items()})
    r.cache.dump(output/'split-manifest.json',manifest)
    return groups,plans,audit


def panel(entries,names,features,new,groups,plans,output):
    keys=sorted(entries);rows=[entries[k]['record'] for k in keys];data=r.matrices(entries,names,features)
    summary=dict(complete=False,training=True,independent_validation=False,final_refit=False,deployment_changed=False,
                 arms={},paired_coverage={},paired_imports={},sample_count=len(keys),targeted_count=len(new),
                 scope='Joint template groups; identical prior calibration/held SHAs. Added benign files enter fit only; new calibration-role files excluded. Post-hoc development, no independent validation. Not directly comparable to earlier split results.')
    records_by_arm={}
    for variant in VARIANTS:
        X,schema=data[variant]
        for arm in ARMS:
            records=[];details=[];tag=variant+'/'+arm
            for plan in plans:
                fit=plan['prior_fit' if arm=='prior_only' else 'expanded_fit'];cal=plan['calibration'];held=plan['held']
                fr,cr,hr=([rows[i] for i in ids] for ids in (fit,cal,held))
                print(f'{tag} fold {plan["fold"]+1}/5: fit={len(fit)}, common calibration={len(cal)}, held={len(held)}',flush=True)
                clf=r.g.fit_model(X[fit],fr);cp=clf.predict_proba(X[cal])[:,1];hp=clf.predict_proba(X[held])[:,1]
                policy=r.c.assess_policy(r.s.software_calibration(cr,cp,entries),plan['calibration_diversity'])
                predictions=dict(software=r.g.gated(hr,hp,policy['threshold']),fixed=r.g.gated(hr,hp,r.g.REFERENCE_THRESHOLD))
                parity=r.g.export_checked(clf,schema,policy['threshold'],X,output/variant/arm/f'fold-{plan["fold"]:02d}-model.json')
                detail=dict(fold=plan['fold'],fit_count=len(fit),added_fit_count=sum(keys[i] in new for i in fit),
                    calibration=policy,export_parity=parity,held={})
                for population,ids in (('prior',np.flatnonzero([row['sha256'] not in new for row in hr])),
                                       ('targeted',np.flatnonzero([row['sha256'] in new for row in hr]))):
                    selected=[hr[i] for i in ids]
                    detail['held'][population]={p:r.d.group_metrics(selected,pred[ids],groups) if len(ids) else None
                                                 for p,pred in predictions.items()}
                details.append(detail)
                for i,row in enumerate(hr):
                    records.append(dict(sha256=row['sha256'],label=row['label'],source=row['source'],fold=plan['fold'],
                        targeted=row['sha256'] in new,reviewer_score=float(hp[i]),
                        **{p+'_prediction':int(pred[i]) for p,pred in predictions.items()}))
            lookup={rec['sha256']:rec for rec in records}
            if len(records)!=len(keys) or set(lookup)!=set(keys):raise ValueError('Held SHA coverage failed')
            pooled={}
            for population,selected in (('prior',[k for k in keys if k not in new]),('targeted',[k for k in keys if k in new])):
                selected_rows=[entries[k]['record'] for k in selected]
                pooled[population]={p:r.d.group_metrics(selected_rows,np.asarray([lookup[k][p+'_prediction'] for k in selected]),groups)
                                    for p in POLICIES}
            summary['arms'][tag]=dict(feature_count=len(schema),folds=details,pooled=pooled,
                all_software_policies_eligible=all(f['calibration']['eligible_development_policy'] for f in details))
            records_by_arm[tag]=lookup;r.cache.dump(output/variant/arm/'development-scores.json',records)
            r.cache.dump(output/'targeted-coverage-summary.json',summary)
    def paired(before,after):
        out={}
        for population,selected in (('prior',[k for k in keys if k not in new]),('targeted',[k for k in keys if k in new])):
            out[population]={p:r.a.paired([entries[k]['record'] for k in selected],
                [records_by_arm[before][k][p+'_prediction'] for k in selected],
                [records_by_arm[after][k][p+'_prediction'] for k in selected])['overall'] for p in POLICIES}
        return out
    for variant in VARIANTS:summary['paired_coverage'][variant]=paired(variant+'/prior_only',variant+'/targeted_fit_added')
    for arm in ARMS:summary['paired_imports'][arm]=paired('structural_control/'+arm,'plus_imports/'+arm)
    return summary


def run(args):
    entries,names,features,new,hashes=load_inputs(args)
    for module in (r,target,r.cache,r.rich):hashes[str(Path(module.__file__).resolve())]=r.cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=r.cache.digest(__file__)
    r.g.f.fresh_output(args.output)
    r.cache.dump(args.output/'inputs.json',dict(input_sha256=hashes,variants=VARIANTS,arms=ARMS,mode='template',
        seed=r.g.SEED,configuration=r.g.f.w.CONFIG,audit_only=args.audit_only,
        dependency_versions={k:importlib.metadata.version(k) for k in ('numpy','scipy','scikit-learn')},
        cohort_normalization='Remove acquisition-only installed: prefix; retain literal directory/package identities.',
        calibration='Identical original samples only; software-aware <=1% calibration caps. Fixed threshold diagnostic.'))
    r.cache.dump(args.output/'excluded-sha256.json',sorted(entries))
    groups,plans,audit=make_plan(entries,names,features,new,args.output)
    if args.audit_only:
        r.cache.verify_hashes(hashes)
        print(f'Complete split audit: {args.output}\nAll folds qualify: {audit["all_folds_qualify"]}\nSend coverage-split-audit-summary.json.',flush=True);return
    if not audit['all_folds_qualify']:raise ValueError('Split diversity blocked; send coverage-split-audit-summary.json. No fitting performed.')
    summary=panel(entries,names,features,new,groups,plans,args.output)
    r.cache.verify_hashes(hashes);summary['complete']=True
    r.cache.dump(args.output/'targeted-coverage-summary.json',summary)
    print(f'Complete: {args.output}\nSend targeted-coverage-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prior-cache',type=Path,required=True)
    ap.add_argument('--targeted-cache',type=Path,help='Default: newest completed cache matching --prior-cache')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-targeted-coverage-development-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    ap.add_argument('--audit-only',action='store_true')
    args=ap.parse_args();args.root=root
    for key in ('prior_cache','targeted_cache','structural_bundle','output'):
        value=getattr(args,key)
        if value:setattr(args,key,value.resolve())
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 targeted coverage experiment stopped: {error}\n')


if __name__=='__main__':main()
