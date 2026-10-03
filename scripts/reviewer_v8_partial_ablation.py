#!/usr/bin/env python3
"""Matched partial upstream feature ablations with two reproduced controls."""
import argparse
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import reviewer_v8_score_ablation as a

c, g, s = a.c, a.g, a.s
VARIANTS = ('full_72', 'structural_66', 'without_adapter_71', 'without_base_69')
REMOVE = {'full_72': (), 'structural_66': tuple(g.f.w.SCORE_FEATURES),
          'without_adapter_71': ('adapter_probability',),
          'without_base_69': ('benign_probability', 'base_trigger_raw', 'base_trigger_adjusted')}


def matrices(entries, names):
    X, schema = a.matrices(entries, names)['full_72']
    result = {}
    for variant in VARIANTS:
        keep = [i for i,n in enumerate(schema) if n not in REMOVE[variant]]
        result[variant] = X[:,keep].copy(), [schema[i] for i in keep]
    return result


def find_previous(root):
    candidates = []
    for path in root.glob('reviewer-v8-score-ablation-development*'):
        marker = path/'ablation-comparison-summary.json'
        if marker.is_file() and g.f.read(marker).get('complete'):
            candidates.append(path)
    if not candidates: raise ValueError('No completed score ablation found; pass --previous')
    return max(candidates, key=lambda p:(p.joinpath('ablation-comparison-summary.json').stat().st_mtime_ns,str(p)))


def prior_controls(entries, names, previous, software_previous, mode):
    manifest, _, _, plans = a.previous_panel(entries,names,software_previous,mode)
    old = g.f.read(previous/mode/'ablation-summary.json')
    if (not old.get('complete') or old['mode']!=mode or old['configuration']!=g.f.w.CONFIG or old['seed']!=g.SEED
            or g.f.read(previous/mode/'split-manifest.json')!=manifest):
        raise ValueError('Previous ablation summary/splits/configuration mismatch: '+mode)
    scores = {}
    expected_fold = {sha:f['fold'] for f in manifest['folds'] for sha in f['held']}
    for variant in ('full_72','structural_66'):
        records=g.f.read(previous/mode/variant/'development-scores.json')
        if not old['variants'][variant]['complete'] or len(records)!=len(entries) or {r['sha256'] for r in records}!=set(entries):
            raise ValueError('Prior control coverage incomplete: '+variant)
        for r in records:
            sha=r['sha256']
            if (r['fold']!=expected_fold[sha] or r['group']!=manifest['groups'][sha]
                    or any(r[k]!=entries[sha]['record'][k] for k in ('label','source'))):
                raise ValueError('Prior control held record mismatch')
        scores[variant]={r['sha256']:r for r in records}
    return manifest,old,scores,plans


def experiment_panel(entries,names,previous,software_previous,output,mode):
    manifest,old,old_scores,plans=prior_controls(entries,names,previous,software_previous,mode)
    keys=sorted(entries);rows=[entries[k]['record'] for k in keys];groups=manifest['groups'];data=matrices(entries,names)
    g.f.w.dump(output/'split-manifest.json',manifest)
    summary=dict(complete=False,role='matched_partial_ablation_development',mode=mode,sample_count=len(rows),
                 configuration=g.f.w.CONFIG,seed=g.SEED,variants={},paired_vs_full={},paired_vs_structural={},
                 control_max_score_error={},
                 limits='Post-hoc development with fixed legacy routing and historical overlap. Partial ablations retain signature indicators. Thresholds are selected separately on identical calibration rows; fixed numeric thresholds do not imply equal operating points.')
    records_by_variant={}
    for variant in VARIANTS:
        X,schema=data[variant];folds=[];records=[];max_error=0.
        for f in plans:
            n=f['fold'];print(f'{mode} {variant} fold {n+1}/5',flush=True)
            fr,cr,hr=([rows[i] for i in f[k]] for k in ('fit','calibration','held'))
            clf=g.fit_model(X[f['fit']],fr);cp=clf.predict_proba(X[f['calibration']])[:,1];hp=clf.predict_proba(X[f['held']])[:,1]
            policies=dict(ordinary=g.calibration(cr,cp,lambda t:g.gated(cr,cp,t)),software=s.software_calibration(cr,cp,entries))
            policies={k:c.assess_policy(v,f['calibration_diversity']) for k,v in policies.items()}
            pred={k:g.gated(hr,hp,v['threshold']) for k,v in policies.items()};pred['fixed']=g.gated(hr,hp,g.REFERENCE_THRESHOLD)
            if variant in old_scores:
                error=max(abs(float(hp[i])-old_scores[variant][r['sha256']]['reviewer_score']) for i,r in enumerate(hr))
                max_error=max(max_error,error)
                if error>1e-10:raise ValueError(f'{mode} {variant} reproduction failed fold {n}: max_abs={error}')
                for k,v in policies.items():
                    prior=old['variants'][variant]['folds'][n]['calibration'][k]
                    if abs(v['threshold']-prior['threshold'])>1e-10 or v['overall']!=prior['overall']:
                        raise ValueError('Control calibration reproduction failed')
                for k,v in pred.items():
                    if any(int(v[i])!=old_scores[variant][r['sha256']][k+'_prediction'] for i,r in enumerate(hr)):
                        raise ValueError('Control gate reproduction failed')
            parity=g.export_checked(clf,schema,policies['software']['threshold'],X,output/variant/f'fold-{n:02d}-model.json')
            folds.append(dict(fold=n,calibration=policies,export_parity=parity,held={k:g.rates(hr,v,groups) for k,v in pred.items()}))
            for i,r in enumerate(hr):
                records.append(dict(sha256=r['sha256'],label=r['label'],source=r['source'],group=groups[r['sha256']],fold=n,
                                    reviewer_score=float(hp[i]),**{k+'_prediction':int(v[i]) for k,v in pred.items()}))
            summary['variants'][variant]=dict(complete=False,feature_count=len(schema),features=schema,removed_features=list(REMOVE[variant]),folds=folds)
            g.f.w.dump(output/'partial-ablation-summary.json',summary);g.f.w.dump(output/variant/'development-scores.json',records)
        if len(records)!=len(entries) or {r['sha256'] for r in records}!=set(entries):raise ValueError('Held SHA coverage failed')
        summary['variants'][variant].update(complete=True,
            all_policies_eligible={k:all(f['calibration'][k]['eligible_development_policy'] for f in folds) for k in ('ordinary','software')},
            pooled={k:g.rates(records,np.array([r[k+'_prediction'] for r in records]),groups) for k in a.POLICIES})
        records_by_variant[variant]={r['sha256']:r for r in records}
        if variant in old_scores:summary['control_max_score_error'][variant]=max_error
    for baseline,target in [('full_72','paired_vs_full'),('structural_66','paired_vs_structural')]:
        for variant in VARIANTS:
            if variant==baseline:continue
            summary[target][variant]={k:a.paired(rows,
                np.array([records_by_variant[baseline][sha][k+'_prediction'] for sha in keys]),
                np.array([records_by_variant[variant][sha][k+'_prediction'] for sha in keys])) for k in a.POLICIES}
    summary['complete']=True;g.f.w.dump(output/'partial-ablation-summary.json',summary)
    return summary


def main():
    root=g.f.w.ROOT/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit',type=Path,action='append');ap.add_argument('--fresh-comparison',type=Path,action='append')
    ap.add_argument('--previous',type=Path,help='Completed score-ablation run; default is latest completed run')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-partial-ablation-development-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.fresh_audit=args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison=args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        args.previous=args.previous or find_previous(root);print(f'Using completed ablation: {args.previous}',flush=True)
        if not g.f.read(args.previous/'ablation-comparison-summary.json').get('complete'):raise ValueError('Previous ablation incomplete')
        if len(args.fresh_audit)!=len(args.fresh_comparison):raise ValueError('Pair fresh audits/evaluations')
        old_inputs=g.f.read(args.previous/'inputs.json');software_previous=Path(old_inputs['previous'])
        for path,digest in old_inputs['input_sha256'].items():
            if g.digest(Path(path))!=digest:raise ValueError('Previous input changed: '+path)
        for module in (a,s,c,g):
            old_digest=old_inputs['script_sha256'] if module is a else old_inputs['dependency_sha256'].get(str(Path(module.__file__)))
            if old_digest!=g.digest(Path(module.__file__)):raise ValueError('Previous ablation dependency changed: '+module.__name__)
        g.f.fresh_output(args.output);entries,names,hashes,converted=g.load_inputs(args)
        for path,digest in hashes.items():
            if old_inputs['input_sha256'].get(path)!=digest:raise ValueError('Cache/evaluation differs from previous ablation: '+path)
        for mode in c.MODES:
            prior_controls(entries,names,args.previous,software_previous,mode)
            for filename in ('split-manifest.json','ablation-summary.json','full_72/development-scores.json','structural_66/development-scores.json'):
                hashes[str(args.previous/mode/filename)]=g.digest(args.previous/mode/filename)
        hashes[str(args.previous/'inputs.json')]=g.digest(args.previous/'inputs.json')
        g.f.w.dump(args.output/'inputs.json',dict(role='development',previous=str(args.previous),software_previous=str(software_previous),
            input_sha256=hashes,script_sha256=g.digest(Path(__file__)),
            dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in (a,s,c,g)},former_evaluation_shas_now_development=converted))
        _,_,exclusions=g.f.load_bundle(args.bundle);g.f.w.dump(args.output/'excluded-sha256.json',sorted(exclusions|set(entries)))
        combined=dict(complete=False,role='matched_partial_ablation_development',modes={})
        for mode in c.MODES:
            result=experiment_panel(entries,names,args.previous,software_previous,args.output/mode,mode)
            combined['modes'][mode]=dict(control_max_score_error=result['control_max_score_error'],
                variants={k:dict(feature_count=v['feature_count'],removed_features=v['removed_features'],all_policies_eligible=v['all_policies_eligible'],
                    **{p:r['overall'] for p,r in v['pooled'].items()}) for k,v in result['variants'].items()},
                paired_vs_full={v:{p:r['overall'] for p,r in policies.items()} for v,policies in result['paired_vs_full'].items()},
                paired_vs_structural={v:{p:r['overall'] for p,r in policies.items()} for v,policies in result['paired_vs_structural'].items()})
            g.f.w.dump(args.output/'partial-ablation-comparison-summary.json',combined)
        combined['complete']=True;g.f.w.dump(args.output/'partial-ablation-comparison-summary.json',combined)
        print(f'Outputs: {args.output}',flush=True)
    except Exception as error:ap.exit(2,f'V8 partial ablation stopped: {error}\n')


if __name__=='__main__':main()
