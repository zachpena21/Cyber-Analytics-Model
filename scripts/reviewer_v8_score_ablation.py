#!/usr/bin/env python3
"""Matched upstream-score ablation on frozen development split manifests."""
import argparse
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import reviewer_v8_software_calibration as s

c, g = s.c, s.g
VARIANTS = ('full_72', 'structural_66')
POLICIES = ('ordinary', 'software', 'fixed')


def find_previous(root):
    candidates = []
    for path in root.glob('reviewer-v8-software-calibration-development*'):
        marker = path / 'calibration-comparison-summary.json'
        if marker.is_file() and g.f.read(marker).get('complete'):
            candidates.append(path)
    if not candidates:
        raise ValueError('No completed software-calibration experiment found; pass --previous')
    return max(candidates, key=lambda p: (p.joinpath('calibration-comparison-summary.json').stat().st_mtime_ns, str(p)))


def matrices(entries, names):
    keys = sorted(entries)
    if list(names[:6]) != list(g.f.w.SCORE_FEATURES) or len(names) != 66:
        raise ValueError('Expected six upstream score features followed by 60 structural features')
    schema = list(names) + list(g.f.t.e.IMPORT_FEATURES)
    X = np.array([entries[k]['feature_vector'] + list(g.f.t.e._import_values({'libraries': entries[k]['libraries']})) for k in keys])
    if X.shape[1] != 72:
        raise ValueError('Expected 72-feature control')
    return { 'full_72': (X, schema), 'structural_66': (X[:, 6:].copy(), schema[6:]) }


def previous_panel(entries, names, previous, mode):
    manifest = g.f.read(previous / mode / 'split-manifest.json')
    summary = g.f.read(previous / mode / 'control-summary.json')
    scores = g.f.read(previous / mode / 'development-scores.json')
    expected_groups = s.stable_groups(entries, names, mode)
    if (manifest.get('mode') != mode or manifest['groups'] != expected_groups or not summary.get('complete')
        or summary.get('mode') != mode or summary['configuration'] != g.f.w.CONFIG or summary['seed'] != g.SEED
        or len(scores) != len(entries) or {r['sha256'] for r in scores} != set(entries)):
        raise ValueError('Previous panel pool/groups/configuration/coverage mismatch: ' + mode)
    keys = sorted(entries); rows = [entries[k]['record'] for k in keys]; index = {k:i for i,k in enumerate(keys)}
    if len(manifest['folds']) != 5 or len(summary['folds']) != 5:
        raise ValueError('Five completed outer folds required')
    score_map = {r['sha256']:r for r in scores}; plans = []; held_all = []
    for fold_id, f in enumerate(manifest['folds']):
        if f['fold'] != fold_id or summary['folds'][fold_id]['fold'] != fold_id:
            raise ValueError('Previous fold order mismatch')
        plan = dict(f)
        for role in ('fit','calibration','held'):
            if len(f[role]) != len(set(f[role])) or not set(f[role]) <= set(entries):
                raise ValueError('Duplicate or unknown SHA in previous split')
            # Preserve exact training row order; it affects deterministic fitting.
            plan[role] = np.array([index[k] for k in f[role]], dtype=int)
        c.assert_split(rows, expected_groups, [plan[k] for k in ('fit','calibration','held')])
        fingerprints = {k:s.stable_fingerprint(entries[k], names) for k in keys}
        roles = [{fingerprints[rows[i]['sha256']] for i in plan[k]} for k in ('fit','calibration','held')]
        if roles[0]&roles[1] or roles[0]&roles[2] or roles[1]&roles[2]:
            raise ValueError('Entropy-invariant representation overlaps previous roles')
        for sha in f['held']:
            r = score_map[sha]
            if r['fold'] != fold_id or r['group'] != expected_groups[sha] or any(r[k] != entries[sha]['record'][k] for k in ('label','source')):
                raise ValueError('Previous held record mismatch')
        cd = c.diversity([rows[i] for i in plan['calibration']], expected_groups, fingerprints)
        if cd != f['calibration_diversity'] or not cd['diverse']:
            raise ValueError('Previous calibration diversity mismatch')
        held_all.extend(f['held']); plans.append(plan)
    if len(held_all) != len(entries) or set(held_all) != set(entries):
        raise ValueError('Previous held pool not exactly once per SHA')
    return manifest, summary, score_map, plans


def paired(rows, before, after):
    def counts(indices):
        result = {}
        for label, name in ((0,'benign'),(1,'malware')):
            ids = [i for i in indices if rows[i]['label'] == label]
            result[name] = dict(count=len(ids), rescued=sum(int(before[i] != label and after[i] == label) for i in ids),
                               regressed=sum(int(before[i] == label and after[i] != label) for i in ids))
        return result
    return dict(overall=counts(range(len(rows))), by_source={source:counts([i for i,r in enumerate(rows) if r['source']==source])
                for source in sorted({r['source'] for r in rows})})


def experiment_panel(entries, names, previous, output, mode):
    manifest, old, old_scores, plans = previous_panel(entries, names, previous, mode)
    keys=sorted(entries); rows=[entries[k]['record'] for k in keys]; groups=manifest['groups']; data=matrices(entries,names)
    g.f.w.dump(output/'split-manifest.json',manifest)
    summary=dict(complete=False, role='matched_development_ablation', mode=mode, sample_count=len(rows),
                 removed_features=list(names[:6]), configuration=g.f.w.CONFIG, seed=g.SEED, variants={}, paired={},
                 limits='Existing development splits and legacy gates; no independent validation. Each variant calibrates its own threshold on identical calibration SHAs. Fixed thresholds need not represent equal operating points.')
    all_scores={}; baseline_max=0.
    # Complete reproduction first, so candidate fitting never precedes baseline validation.
    for variant in VARIANTS:
        X,schema=data[variant]; folds=[]; records=[]
        for f in plans:
            n=f['fold']; print(f'{mode} {variant} fold {n+1}/5: fit={len(f["fit"])}, calibration={len(f["calibration"])}, held={len(f["held"])}',flush=True)
            fr,cr,hr=([rows[i] for i in f[k]] for k in ('fit','calibration','held'))
            clf=g.fit_model(X[f['fit']],fr); cp=clf.predict_proba(X[f['calibration']])[:,1]; hp=clf.predict_proba(X[f['held']])[:,1]
            policies=dict(ordinary=g.calibration(cr,cp,lambda t:g.gated(cr,cp,t)), software=s.software_calibration(cr,cp,entries))
            policies={k:c.assess_policy(v,f['calibration_diversity']) for k,v in policies.items()}
            predictions={k:g.gated(hr,hp,v['threshold']) for k,v in policies.items()}; predictions['fixed']=g.gated(hr,hp,g.REFERENCE_THRESHOLD)
            if variant=='full_72':
                err=max(abs(float(hp[i])-old_scores[r['sha256']]['reviewer_score']) for i,r in enumerate(hr))
                baseline_max=max(baseline_max,err)
                if err>1e-10: raise ValueError(f'{mode} baseline score reproduction failed fold {n}: max_abs={err}')
                for k,v in policies.items():
                    previous_policy=old['folds'][n]['calibration'][k]
                    if abs(v['threshold']-previous_policy['threshold'])>1e-10 or v['overall']!=previous_policy['overall']:
                        raise ValueError(f'{mode} baseline calibration reproduction failed: fold {n}, {k}')
                for k,v in predictions.items():
                    if any(int(v[i])!=old_scores[r['sha256']][k+'_prediction'] for i,r in enumerate(hr)):
                        raise ValueError('Baseline gate/prediction reproduction failed')
            parity=g.export_checked(clf,schema,policies['software']['threshold'],X,output/variant/f'fold-{n:02d}-model.json')
            folds.append(dict(fold=n,calibration=policies,export_parity=parity,held={k:g.rates(hr,v,groups) for k,v in predictions.items()}))
            for i,r in enumerate(hr):
                records.append(dict(sha256=r['sha256'],label=r['label'],source=r['source'],group=groups[r['sha256']],fold=n,
                                    reviewer_score=float(hp[i]),**{k+'_prediction':int(v[i]) for k,v in predictions.items()}))
            summary['variants'][variant]=dict(complete=False,feature_count=len(schema),features=schema,folds=folds)
            g.f.w.dump(output/'ablation-summary.json',summary); g.f.w.dump(output/variant/'development-scores.json',records)
        if len(records)!=len(entries) or {r['sha256'] for r in records}!=set(entries):raise ValueError('Ablation held coverage failed')
        summary['variants'][variant].update(complete=True,
            all_policies_eligible={k:all(f['calibration'][k]['eligible_development_policy'] for f in folds) for k in ('ordinary','software')},
            pooled={k:g.rates(records,np.array([r[k+'_prediction'] for r in records]),groups) for k in POLICIES})
        all_scores[variant]={r['sha256']:r for r in records}
    for policy in POLICIES:
        before=np.array([all_scores['full_72'][k][policy+'_prediction'] for k in keys])
        after=np.array([all_scores['structural_66'][k][policy+'_prediction'] for k in keys])
        summary['paired'][policy]=paired(rows,before,after)
    summary.update(complete=True,baseline_max_score_error=baseline_max)
    g.f.w.dump(output/'ablation-summary.json',summary)
    return summary


def main():
    root=g.f.w.ROOT/'validation-data'; ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit',type=Path,action='append');ap.add_argument('--fresh-comparison',type=Path,action='append')
    ap.add_argument('--previous',type=Path,help='Completed software-calibration run; default is most recently completed run')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-score-ablation-development-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.fresh_audit=args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison=args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        args.previous=args.previous or find_previous(root);print(f'Using completed splits from: {args.previous}',flush=True)
        marker=g.f.read(args.previous/'calibration-comparison-summary.json')
        if not marker.get('complete'):raise ValueError('Previous comparison is incomplete')
        if len(args.fresh_audit)!=len(args.fresh_comparison):raise ValueError('Pair fresh audits/evaluations')
        g.f.fresh_output(args.output);entries,names,hashes,converted=g.load_inputs(args)
        prior_inputs=g.f.read(args.previous/'inputs.json')
        for path,digest in prior_inputs['input_sha256'].items():
            if g.digest(Path(path))!=digest:raise ValueError('Previous run input file changed: '+path)
        for module in (s,c,g):
            old_digest=prior_inputs.get('script_sha256') if module is s else prior_inputs['dependency_sha256'].get(str(Path(module.__file__)))
            if old_digest!=g.digest(Path(module.__file__)):raise ValueError('Previous experiment dependency changed: '+module.__name__)
        for path,digest in hashes.items():
            if prior_inputs['input_sha256'].get(path)!=digest:raise ValueError('Current cache/evaluation differs from previous run: '+path)
        for mode in c.MODES:
            previous_panel(entries,names,args.previous,mode)
            for filename in ('split-manifest.json','control-summary.json','development-scores.json'):
                hashes[str(args.previous/mode/filename)]=g.digest(args.previous/mode/filename)
        g.f.w.dump(args.output/'inputs.json',dict(role='development',previous=str(args.previous),input_sha256=hashes,
            script_sha256=g.digest(Path(__file__)),dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in (s,c,g)},
            former_evaluation_shas_now_development=converted))
        _,_,exclusions=g.f.load_bundle(args.bundle);g.f.w.dump(args.output/'excluded-sha256.json',sorted(exclusions|set(entries)))
        combined=dict(complete=False,role='matched_development_ablation',modes={})
        for mode in c.MODES:
            result=experiment_panel(entries,names,args.previous,args.output/mode,mode)
            combined['modes'][mode]=dict(baseline_max_score_error=result['baseline_max_score_error'],
                variants={k:dict(feature_count=v['feature_count'],all_policies_eligible=v['all_policies_eligible'],
                    **{p:r['overall'] for p,r in v['pooled'].items()}) for k,v in result['variants'].items()},
                paired={p:v['overall'] for p,v in result['paired'].items()})
            g.f.w.dump(args.output/'ablation-comparison-summary.json',combined)
        combined['complete']=True;g.f.w.dump(args.output/'ablation-comparison-summary.json',combined)
        print(f'Outputs: {args.output}',flush=True)
    except Exception as error:ap.exit(2,f'V8 score ablation stopped: {error}\n')


if __name__=='__main__':main()
