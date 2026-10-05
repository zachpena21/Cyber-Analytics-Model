#!/usr/bin/env python3
"""Audit paired sample changes, feature profiles and threshold margins; no fitting."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import reviewer_v8_group_diagnostics as d

p, a, c, g, s = d.p, d.a, d.c, d.g, d.s
CHALLENGERS = ('structural_66', 'without_adapter_71')


def find_previous(root):
    paths = []
    for path in root.glob('reviewer-v8-group-diagnostics-*'):
        marker = path / 'group-diagnostic-comparison-summary.json'
        if marker.is_file() and g.f.read(marker).get('complete'):
            paths.append(path)
    if not paths:
        raise ValueError('No completed group diagnostics found; pass --previous')
    return max(paths, key=lambda x: (x.joinpath('group-diagnostic-comparison-summary.json').stat().st_mtime_ns, str(x)))


def threshold(summary, variant, fold, policy):
    return (g.REFERENCE_THRESHOLD if policy == 'fixed' else
            summary['variants'][variant]['folds'][fold]['calibration'][policy]['threshold'])


def outcome(label, before, after):
    if before != label and after == label:
        return 'rescued'
    if before == label and after != label:
        return 'regressed'
    return 'unchanged_correct' if after == label else 'unchanged_wrong'


def sample_change(row, before, after, bt, at, policy):
    bs, score = before['reviewer_score'], after['reviewer_score']
    bp, ap = before[policy + '_prediction'], after[policy + '_prediction']
    routed = row['adapter_probability'] >= g.ROUTE
    if bp != ap and not routed:
        raise ValueError('A non-routed sample changed despite identical adapter gate')
    # Two counterfactual comparisons, preserving the actual adapter gate. These
    # describe decision boundaries; neither is a tested deployment policy.
    score_only = int(g.gated([row], [score], bt)[0])
    threshold_only = int(g.gated([row], [bs], at)[0])
    direction = 1 if row['label'] else -1
    return dict(outcome=outcome(row['label'], bp, ap), routed=routed,
                before_score=bs, after_score=score, before_threshold=bt, after_threshold=at,
                before_prediction=bp, after_prediction=ap,
                before_margin=bs-bt if routed else None,
                after_margin=score-at if routed else None,
                score_delta=score-bs, threshold_delta=at-bt,
                margin_delta=(score-bs)-(at-bt) if routed else None,
                correctness_score_contribution=direction*(score-bs) if routed else None,
                correctness_threshold_contribution=-direction*(at-bt) if routed else None,
                after_score_with_before_threshold_prediction=score_only,
                before_score_with_after_threshold_prediction=threshold_only,
                score_change_alone_reproduces_flip=score_only == ap if bp != ap else None,
                threshold_change_alone_reproduces_flip=threshold_only == ap if bp != ap else None)


def feature_profiles(X, schema, ids, reference):
    profiles = {}; shifts = []
    for j, name in enumerate(schema):
        values = X[ids, j]; base = X[reference, j]
        profiles[name] = dict(cohort=d.distribution(values), unchanged_correct_reference=d.distribution(base))
        if len(values) and len(base):
            scale = float(np.quantile(base, .75)-np.quantile(base, .25))
            delta = float(np.median(values)-np.median(base))
            profiles[name]['median_delta'] = delta
            profiles[name]['reference_iqr'] = scale
            profiles[name]['median_delta_over_reference_iqr'] = delta/scale if scale > 0 else None
            if scale > 0:
                shifts.append(dict(feature=name, median_delta=delta, reference_iqr=scale,
                                   median_delta_over_reference_iqr=delta/scale))
    return dict(features=profiles, largest_standardized_median_shifts=sorted(
        shifts, key=lambda r: (-abs(r['median_delta_over_reference_iqr']), r['feature']))[:12])


def analyze_panel(entries, names, summary, groups, records, output):
    keys = sorted(entries); X, schema = p.matrices(entries, names)['full_72']
    result = dict(complete=True, mode=summary['mode'], variants={}, overlap={},
                  role='descriptive_development_sample_diagnostics',
                  interpretation='Profiles and counterfactuals are descriptive, not causal feature attribution or deployable policies. Fold thresholds differ. Groups are not verified malware families. All reused samples remain development data.')
    outcomes = {}
    for policy in a.POLICIES:
        outcomes[policy] = {}
        for variant in CHALLENGERS:
            changed = []; per_sha = {}; cohorts = {}
            for keys_index, sha in enumerate(keys):
                row = entries[sha]['record']; before = records['full_72'][sha]; after = records[variant][sha]
                fold = before['fold']
                if after['fold'] != fold:
                    raise ValueError('Challengers use different held folds')
                info = sample_change(row, before, after, threshold(summary, 'full_72', fold, policy),
                                     threshold(summary, variant, fold, policy), policy)
                per_sha[sha] = info
                if info['outcome'] in ('rescued', 'regressed'):
                    changed.append(dict(sha256=sha, label=row['label'], source=row['source'],
                                        group=groups[sha], fold=fold, **info,
                                        features={name:float(X[keys_index, j]) for j,name in enumerate(schema)}))
            outcomes[policy][variant] = per_sha
            for label, label_name in ((0, 'benign'), (1, 'malware')):
                reference = [i for i,k in enumerate(keys) if entries[k]['record']['label'] == label and per_sha[k]['outcome'] == 'unchanged_correct']
                cohorts[label_name] = {}
                for kind in ('rescued', 'regressed', 'unchanged_wrong', 'unchanged_correct'):
                    ids = [i for i,k in enumerate(keys) if entries[k]['record']['label'] == label and per_sha[k]['outcome'] == kind]
                    chosen = [keys[i] for i in ids]
                    report = dict(count=len(ids), groups=len({groups[k] for k in chosen}),
                                  by_source=dict(Counter(entries[k]['record']['source'] for k in chosen)),
                                  by_fold=dict(Counter(str(records[variant][k]['fold']) for k in chosen)))
                    if kind in ('rescued', 'regressed'):
                        report['feature_profiles'] = feature_profiles(X, schema, ids, reference)
                        report['reference_count'] = len(reference)
                        report['margins'] = {field:d.distribution([per_sha[k][field] for k in chosen]) for field in
                            ('before_margin','after_margin','score_delta','threshold_delta','margin_delta',
                             'correctness_score_contribution','correctness_threshold_contribution')}
                        report['flip_counterfactuals'] = dict(
                            score_alone=sum(per_sha[k]['score_change_alone_reproduces_flip'] for k in chosen),
                            threshold_alone=sum(per_sha[k]['threshold_change_alone_reproduces_flip'] for k in chosen),
                            both_alone=sum(per_sha[k]['score_change_alone_reproduces_flip'] and per_sha[k]['threshold_change_alone_reproduces_flip'] for k in chosen),
                            neither_alone=sum(not per_sha[k]['score_change_alone_reproduces_flip'] and not per_sha[k]['threshold_change_alone_reproduces_flip'] for k in chosen))
                    cohorts[label_name][kind] = report
                expected = summary['paired_vs_full'][variant][policy]['overall'][label_name]
                if any(cohorts[label_name][kind]['count'] != expected[kind] for kind in ('rescued', 'regressed')):
                    raise ValueError('Sample cohorts disagree with original paired counts')
            g.f.w.dump(output / f'{variant}-{policy}-changed-samples.json', dict(samples=changed, feature_schema=schema))
            result['variants'].setdefault(variant, {})[policy] = dict(cohorts=cohorts, changed_samples=len(changed))
        overlap = {}
        for label, label_name in ((0,'benign'),(1,'malware')):
            cross = Counter()
            for sha in keys:
                if entries[sha]['record']['label'] == label:
                    cross[(outcomes[policy][CHALLENGERS[0]][sha]['outcome'], outcomes[policy][CHALLENGERS[1]][sha]['outcome'])] += 1
            overlap[label_name] = [dict(structural_outcome=x, no_adapter_outcome=y, count=n) for (x,y),n in sorted(cross.items())]
        result['overlap'][policy] = overlap
    g.f.w.dump(output / 'sample-diagnostic-summary.json', result)
    return result


def main():
    root = g.f.w.ROOT / 'validation-data'; ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--previous', type=Path, help='Completed group-diagnostic run; default latest completed')
    ap.add_argument('--bundle', type=Path, default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache', type=Path, default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit', type=Path, action='append')
    ap.add_argument('--fresh-comparison', type=Path, action='append')
    ap.add_argument('--output', type=Path, default=root/('reviewer-v8-sample-diagnostics-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args = ap.parse_args()
    args.fresh_audit = args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison = args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        args.previous = args.previous or find_previous(root)
        print(f'Auditing completed group diagnostics: {args.previous}', flush=True)
        old = g.f.read(args.previous/'inputs.json')
        if not g.f.read(args.previous/'group-diagnostic-comparison-summary.json').get('complete'):
            raise ValueError('Previous diagnostics incomplete')
        for path, digest in old['input_sha256'].items():
            if g.digest(Path(path)) != digest:
                raise ValueError('Previous input changed: '+path)
        for module in (d,p,a,s,c,g):
            expected = old['script_sha256'] if module is d else old['dependency_sha256'].get(str(Path(module.__file__)))
            if expected != g.digest(Path(module.__file__)):
                raise ValueError('Previous dependency changed: '+module.__name__)
        if len(args.fresh_audit) != len(args.fresh_comparison):
            raise ValueError('Pair fresh audits and evaluations')
        g.f.fresh_output(args.output); entries,names,hashes,converted = g.load_inputs(args)
        for path,digest in hashes.items():
            if old['input_sha256'].get(path) != digest:
                raise ValueError('Current cache differs from previous diagnostics')
        partial = Path(old['previous']); combined = dict(complete=False,role='descriptive_development_sample_diagnostics',modes={})
        for mode in c.MODES:
            print(f'Checking exported held scores and analyzing samples: {mode}', flush=True)
            summary,groups,records,parity = d.checked_panel(entries,names,partial,mode,hashes)
            panel = analyze_panel(entries,names,summary,groups,records,args.output/mode)
            combined['modes'][mode] = dict(export_score_max_error=parity,overlap=panel['overlap'],
                variants={v:{pol:{label:{kind:{key:value for key,value in report.items() if key!='feature_profiles'}
                    for kind,report in reports.items()} for label,reports in detail['cohorts'].items()}
                    for pol,detail in policies.items()} for v,policies in panel['variants'].items()})
            g.f.w.dump(args.output/'sample-diagnostic-comparison-summary.json',combined)
        hashes[str(args.previous/'inputs.json')] = g.digest(args.previous/'inputs.json')
        g.f.w.dump(args.output/'inputs.json',dict(previous=str(args.previous),input_sha256=hashes,
            script_sha256=g.digest(Path(__file__)),dependency_sha256={str(Path(m.__file__)):g.digest(Path(m.__file__)) for m in (d,p,a,s,c,g)},
            former_evaluation_shas_now_development=converted))
        _,_,excluded = g.f.load_bundle(args.bundle)
        g.f.w.dump(args.output/'excluded-sha256.json',sorted(excluded | set(entries)))
        combined['complete'] = True; g.f.w.dump(args.output/'sample-diagnostic-comparison-summary.json',combined)
        print(f'Outputs: {args.output}',flush=True)
    except Exception as error:
        ap.exit(2,f'V8 sample diagnostics stopped: {error}\n')


if __name__ == '__main__':
    main()
