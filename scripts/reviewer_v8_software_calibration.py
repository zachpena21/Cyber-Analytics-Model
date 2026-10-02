#!/usr/bin/env python3
"""Development-only entropy-invariant grouping and software-aware calibration."""
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
import reviewer_v8_grouping_controls as c

g = c.g
MIN_SOFTWARE_BENIGN = 20
MIN_SOFTWARE_GROUPS = 3


def stable_fingerprint(entry, names):
    # Conservative representation grouping, not proof of binary relatedness.
    vector = np.asarray(entry['feature_vector'], dtype=np.float32).tolist()
    value = [[v for i, v in enumerate(vector) if i >= 6 and names[i] != 'byte_entropy'], g.libraries(entry)]
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def stable_groups(entries, names, mode):
    old = c.mode_groups(entries, names, mode)
    parent = {s: s for s in entries}
    def find(s):
        while parent[s] != s:
            parent[s] = parent[parent[s]]; s = parent[s]
        return s
    seen = {}
    for s in sorted(entries):
        for tag in [('panel', old[s]), ('entropy_invariant', stable_fingerprint(entries[s], names))]:
            if tag in seen:
                a, b = find(s), find(seen[tag]); parent[max(a, b)] = min(a, b)
            seen[tag] = s
    return {s: find(s) for s in entries}


def software_ids(rows, entries):
    result = defaultdict(list)
    for i, r in enumerate(rows):
        cohort = g.software_group(entries[r['sha256']])
        if r['label'] == 0 and cohort and cohort.startswith('software:'):
            result[cohort].append(i)
    return {k: np.array(v, dtype=int) for k, v in result.items()}


def software_diversity(rows, entries):
    groups = software_ids(rows, entries)
    counts = {k: len(v) for k, v in groups.items()}
    eligible = {k: n for k, n in counts.items() if n >= MIN_SOFTWARE_BENIGN}
    return dict(identified_benign=sum(counts.values()), unidentified_benign=sum(r['label'] == 0 for r in rows)-sum(counts.values()),
                eligible_software_counts=eligible, diverse=len(eligible) >= MIN_SOFTWARE_GROUPS)


def split_plan(rows, groups, fingerprints, folds, entries):
    result = []; count = int(max(folds)) + 1
    for held in range(count):
        choices = []
        for calibration_folds in itertools.combinations([i for i in range(count) if i != held], 2):
            cal = np.flatnonzero(np.isin(folds, calibration_folds))
            fit = np.flatnonzero((folds != held) & ~np.isin(folds, calibration_folds))
            cr, fr = ([rows[i] for i in ids] for ids in (cal, fit))
            cd, fd = c.diversity(cr, groups, fingerprints), c.diversity(fr, groups, fingerprints)
            cs, fs = software_diversity(cr, entries), software_diversity(fr, entries)
            if not all(x['diverse'] for x in (cd, fd, cs, fs)):
                continue
            # Count/provenance-only choice. No score, prediction, or miss is used.
            rank = (-min(len(cs['eligible_software_counts']), len(fs['eligible_software_counts'])),
                    -len(cs['eligible_software_counts']), abs(len(cal)-len(rows)*.4), calibration_folds)
            choices.append((rank, fit, cal, cd, fd, cs, fs))
        if not choices:
            raise ValueError(f'No qualifying two-fold calibration plan for {held}; inspect diversity, do not split representation groups')
        _, fit, cal, cd, fd, cs, fs = min(choices, key=lambda x: x[0])
        result.append(dict(fold=held, fit=fit, calibration=cal, held=np.flatnonzero(folds == held),
                           calibration_diversity=cd, fit_diversity=fd, calibration_software=cs, fit_software=fs))
    return result


def software_calibration(rows, scores, entries, max_fpr=.01):
    sources = {s: np.array([i for i, r in enumerate(rows) if r['source'] == s and r['label'] == 0], dtype=int)
               for s in sorted({r['source'] for r in rows})}
    software = software_ids(rows, entries)
    constraints = [v for v in sources.values() if len(v) >= 100] + [v for v in software.values() if len(v) >= MIN_SOFTWARE_BENIGN]
    labels = np.array([r['label'] for r in rows]); best = None
    if set(labels) != {0, 1}:
        raise ValueError('Both classes required')
    unique = np.unique(scores)
    for threshold in np.unique(np.r_[unique, np.nextafter(unique, np.inf), 1.]):
        if not 0 < threshold <= 1:
            continue
        pred = g.gated(rows, scores, threshold)
        overall = g.f.w.metrics(rows, pred)
        worst = max((float(pred[v].mean()) for v in constraints), default=0.)
        if overall['fpr'] > max_fpr + 1e-15 or worst > max_fpr + 1e-15:
            continue
        rank = (overall['tpr'], -worst, -overall['fpr'], float(threshold))
        if best is None or rank > best[0]:
            best = rank, float(threshold)
    threshold = best[1] if best else 1.; pred = g.gated(rows, scores, threshold)
    result = dict(feasible=best is not None, threshold=threshold,
                  fallback=None if best else 'No feasible policy; threshold 1 is diagnostic only',
                  overall=g.f.w.metrics(rows, pred),
                  software_benign={k: dict(count=len(v), fp=int(pred[v].sum()), fpr=float(pred[v].mean()), constrained=len(v)>=MIN_SOFTWARE_BENIGN) for k,v in software.items()},
                  max_fpr=max_fpr, min_software_benign=MIN_SOFTWARE_BENIGN)
    return result


def descriptive_profile(shas, entries, names):
    if not shas:
        return dict(count=0, features={})
    X = np.asarray([entries[s]['feature_vector'] for s in shas])
    return dict(count=len(shas), features={name: dict(p10=float(np.quantile(X[:,i], .1)), median=float(np.median(X[:,i])),
                p90=float(np.quantile(X[:,i], .9))) for i,name in enumerate(names)})


def error_audit(entries, names, previous, output):
    all_rows = g.f.read(previous / 'development-scores.json')
    summary = g.f.read(previous / 'control-summary.json')
    if not summary.get('complete') or summary.get('mode') != 'provenance' or len(all_rows) != len(entries) or {r['sha256'] for r in all_rows} != set(entries):
        raise ValueError('Completed previous provenance score coverage required')
    scores = {r['sha256']: r for r in all_rows}
    for s, r in scores.items():
        if any(r[k] != entries[s]['record'][k] for k in ('label','source')):
            raise ValueError('Previous score label/source mismatch')
    result = dict(complete=True, role='descriptive_development_audit', software={},
        interpretation='Profiles and error-selected contrasts are descriptive, not causal feature importance or independent validation. No sample is removed or whitelisted.')
    routed = [s for s,e in entries.items() if e['record']['adapter_probability'] >= g.ROUTE]
    for package in ('software:git', 'software:scipy'):
        cohort = [s for s,e in entries.items() if e['record']['label'] == 0 and g.software_group(e) == package]
        misses = [s for s in cohort if scores[s]['fixed_prediction'] == 1]
        correct = [s for s in cohort if scores[s]['fixed_prediction'] == 0]
        templates = {g.structural_template(entries[s], names) for s in misses}
        same_template = [s for s in routed if entries[s]['record']['label']==1 and g.structural_template(entries[s], names) in templates]
        other_benign = [s for s in routed if entries[s]['record']['label']==0 and s not in cohort and scores[s]['fixed_prediction']==0]
        malware = [s for s in routed if entries[s]['record']['label']==1]
        buckets = dict(false_positives=misses, correct_same_software=correct,
                       correct_other_routed_benign=other_benign, malware_same_coarse_template=same_template, all_routed_malware=malware)
        profiles = {k: descriptive_profile(v, entries, names) for k,v in buckets.items()}
        contrasts = {}
        if misses:
            scale = np.std(np.asarray([entries[s]['feature_vector'] for s in routed]), axis=0)
            for key in ('correct_same_software','correct_other_routed_benign','malware_same_coarse_template','all_routed_malware'):
                if not buckets[key]:
                    contrasts[key] = []; continue
                ranked = []
                for i,name in enumerate(names):
                    if i < 6 or scale[i] == 0:
                        continue
                    a = profiles['false_positives']['features'][name]['median']; b=profiles[key]['features'][name]['median']
                    ranked.append(dict(feature=name, false_positive_median=a, comparator_median=b,
                                       absolute_standardized_median_difference=float(abs(a-b)/scale[i])))
                contrasts[key] = sorted(ranked,key=lambda r:-r['absolute_standardized_median_difference'])[:15]
        result['software'][package] = dict(benign_count=len(cohort), fixed_fp=len(misses),
            calibrated_fp=sum(scores[s]['calibrated_prediction'] for s in cohort),
            false_positive_shas=misses, profiles=profiles, descriptive_contrasts=contrasts)
    g.f.w.dump(output / 'software-error-audit.json', result)
    return result


def control(entries, names, output, mode):
    keys=sorted(entries); rows=[entries[s]['record'] for s in keys]
    groups=stable_groups(entries,names,mode); fp={s:stable_fingerprint(entries[s],names) for s in keys}
    folds=g.group_folds(rows,groups,5); plan=split_plan(rows,groups,fp,folds,entries)
    manifest=dict(mode=mode, groups=groups, folds=[])
    for f in plan:
        c.assert_split(rows,groups,[f[k] for k in ('fit','calibration','held')])
        role_sets=[{fp[rows[i]['sha256']] for i in f[k]} for k in ('fit','calibration','held')]
        if any(a & b for a,b in itertools.combinations(role_sets,2)):
            raise ValueError('Entropy-invariant representation crossed splits')
        manifest['folds'].append({k:([rows[i]['sha256'] for i in v] if k in ('fit','calibration','held') else v) for k,v in f.items()})
    g.f.w.dump(output/'split-manifest.json',manifest)
    g.f.w.dump(output/'group-overview.json',c.group_overview(entries,groups))
    schema=names+list(g.f.t.e.IMPORT_FEATURES)
    X=np.array([entries[s]['feature_vector']+list(g.f.t.e._import_values({'libraries':entries[s]['libraries']})) for s in keys])
    summary=dict(complete=False,role='development',mode=mode,configuration=g.f.w.CONFIG,seed=g.SEED,folds=[],
        limits='Post-hoc development; entropy-invariant representations are not verified binary relatives. Legacy base/adapter training overlap remains. Approximately 40% fitting, 40% calibration, 20% held; compare policies within this run, not directly with previous fits.')
    scores=[]
    for f in plan:
        print(f'{mode} software calibration fold {f["fold"]+1}/5: fit={len(f["fit"])}, calibration={len(f["calibration"])}, held={len(f["held"])}',flush=True)
        fr,cr,hr=([rows[i] for i in f[k]] for k in ('fit','calibration','held'))
        clf=g.fit_model(X[f['fit']],fr); cp=clf.predict_proba(X[f['calibration']])[:,1]; hp=clf.predict_proba(X[f['held']])[:,1]
        policies=dict(ordinary=g.calibration(cr,cp,lambda t:g.gated(cr,cp,t)), software=software_calibration(cr,cp,entries))
        policies={k:c.assess_policy(v,f['calibration_diversity']) for k,v in policies.items()}
        preds={k:g.gated(hr,hp,v['threshold']) for k,v in policies.items()}; preds['fixed']=g.gated(hr,hp,g.REFERENCE_THRESHOLD)
        parity=g.export_checked(clf,schema,policies['software']['threshold'],X,output/f'fold-{f["fold"]:02d}-control-model.json')
        result=dict(fold=f['fold'],calibration=policies,calibration_software=f['calibration_software'],
                    calibration_diversity=f['calibration_diversity'],export_parity=parity,
                    held={k:g.rates(hr,p,groups) for k,p in preds.items()})
        summary['folds'].append(result)
        for i,r in enumerate(hr):
            scores.append(dict(sha256=r['sha256'],label=r['label'],source=r['source'],group=groups[r['sha256']],fold=f['fold'],
                              reviewer_score=float(hp[i]),**{k+'_prediction':int(v[i]) for k,v in preds.items()}))
        g.f.w.dump(output/'control-summary.json',summary); g.f.w.dump(output/'development-scores.json',scores)
    if len(scores)!=len(entries) or {r['sha256'] for r in scores}!=set(entries):
        raise ValueError('Held coverage failed')
    summary.update(complete=True,sample_count=len(entries),group_count=len(set(groups.values())),
        pooled={k:g.rates(scores,np.array([r[k+'_prediction'] for r in scores]),groups) for k in ('ordinary','software','fixed')},
        all_policies_eligible={k:all(f['calibration'][k]['eligible_development_policy'] for f in summary['folds']) for k in ('ordinary','software')})
    g.f.w.dump(output/'control-summary.json',summary)
    return summary


def main():
    root=g.f.w.ROOT/'validation-data'; ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit',type=Path,action='append'); ap.add_argument('--fresh-comparison',type=Path,action='append')
    ap.add_argument('--previous',type=Path,default=root/'reviewer-v8-grouping-controls-development/provenance')
    ap.add_argument('--output',type=Path,default=root/'reviewer-v8-software-calibration-development')
    ap.add_argument('--audit-only',action='store_true'); args=ap.parse_args()
    args.fresh_audit=args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison=args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        if len(args.fresh_audit)!=len(args.fresh_comparison): raise ValueError('Pair every fresh audit with its evaluation')
        g.f.fresh_output(args.output); entries,names,hashes,converted=g.load_inputs(args)
        for filename in ('control-summary.json','development-scores.json'):
            hashes[str(args.previous/filename)]=g.digest(args.previous/filename)
        g.f.w.dump(args.output/'inputs.json',dict(input_sha256=hashes,script_sha256=g.digest(Path(__file__)),
            dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in (c,g)},former_evaluation_shas_now_development=converted,
            settings=dict(min_software_benign=MIN_SOFTWARE_BENIGN,min_software_groups=MIN_SOFTWARE_GROUPS,calibration_folds=2)))
        _,_,exclusions=g.f.load_bundle(args.bundle); g.f.w.dump(args.output/'excluded-sha256.json',sorted(exclusions|set(entries)))
        error_audit(entries,names,args.previous,args.output)
        overview={mode:c.group_overview(entries,stable_groups(entries,names,mode)) for mode in c.MODES}
        g.f.w.dump(args.output/'grouping-summary.json',{mode:dict(group_count=len(v),largest_groups=[dict(group=k,**r) for k,r in sorted(v.items(),key=lambda x:-x[1]['count'])[:10]]) for mode,v in overview.items()})
        if not args.audit_only:
            combined=dict(complete=False,role='development',modes={})
            for mode in c.MODES:
                summary=control(entries,names,args.output/mode,mode)
                combined['modes'][mode]=dict(all_policies_eligible=summary['all_policies_eligible'],**{k:v['overall'] for k,v in summary['pooled'].items()})
                g.f.w.dump(args.output/'calibration-comparison-summary.json',combined)
            combined['complete']=True; g.f.w.dump(args.output/'calibration-comparison-summary.json',combined)
        print(f'Outputs: {args.output}',flush=True)
    except Exception as error:
        ap.exit(2,f'V8 software calibration stopped: {error}\n')


if __name__=='__main__': main()
