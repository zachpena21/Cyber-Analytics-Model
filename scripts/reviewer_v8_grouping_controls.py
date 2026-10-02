#!/usr/bin/env python3
"""Audit grouping bridges/feature aliases, then refit reviewer-only controls offline."""
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
import reviewer_v8_grouped_experiment as g

MIN_MALWARE = 20
MIN_MALWARE_GROUPS = 3
MAX_GROUP_SHARE = .7
MODES = ('provenance', 'template')


def fingerprint(entry):
    """Exact runtime structural representation, excluding six upstream scores."""
    vector = np.asarray(entry['feature_vector'][6:], dtype=np.float32).tolist()
    value = [vector, g.libraries(entry)]
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def mode_groups(entries, names, mode):
    if mode not in MODES:
        raise ValueError('Unknown grouping mode')
    keys = sorted(entries); parents = {sha: sha for sha in keys}

    def find(sha):
        while parents[sha] != sha:
            parents[sha] = parents[parents[sha]]; sha = parents[sha]
        return sha

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parents[max(a, b)] = min(a, b)

    seen = {}
    for sha in keys:
        entry = entries[sha]
        tags = [('representation', fingerprint(entry))]
        if mode == 'provenance':
            cohort = g.software_group(entry)
            if cohort:
                tags.append(('provenance', cohort))
        else:
            tags.append(('template', g.structural_template(entry, names)))
        for tag in tags:
            if tag in seen:
                union(sha, seen[tag])
            seen[tag] = sha
    return {sha: find(sha) for sha in keys}


def group_overview(entries, groups):
    buckets = defaultdict(list)
    for sha in sorted(entries):
        buckets[groups[sha]].append(sha)
    return {group: dict(count=len(shas), benign=sum(entries[s]['record']['label'] == 0 for s in shas),
        malicious=sum(entries[s]['record']['label'] == 1 for s in shas),
        sources=dict(Counter(entries[s]['record']['source'] for s in shas))) for group, shas in buckets.items()}


def feature_profile(shas, entries, names):
    X = np.asarray([entries[s]['feature_vector'] for s in shas], dtype=float)
    X32 = X.astype(np.float32)
    constants = {names[i]: float(X[0, i]) for i in range(6, len(names)) if np.all(X[:, i] == X[0, i])}
    variable = {names[i]: dict(min=float(X[:, i].min()), max=float(X[:, i].max()),
                              unique=int(len(np.unique(X[:, i])))) for i in range(6, len(names)) if names[i] not in constants}
    aliases = Counter(fingerprint(entries[s]) for s in shas)
    members = defaultdict(list)
    for sha in shas:
        members[fingerprint(entries[sha])].append(sha)
    a = [g.attributes(entries[s], names) for s in shas]
    return dict(count=len(shas), structural_float64_unique=int(len(np.unique(X[:, 6:], axis=0))),
        structural_float32_unique=int(len(np.unique(X32[:, 6:], axis=0))),
        full_float32_unique=int(len(np.unique(X32, axis=0))),
        structural_plus_import_representation_unique=len(aliases),
        constant_structural_features=constants, variable_structural_features=variable,
        zero_section_count=sum(r['numberof_sections'] == 0 for r in a),
        zero_virtual_size_count=sum(r['virtual_size'] == 0 for r in a),
        zero_import_count=sum(r['imports'] == 0 for r in a),
        largest_alias_sets=[dict(count=count, sha256=members[key]) for key, count in aliases.most_common(5)],
        interpretation='Equal representations or model scores do not establish byte-identical samples, malware families, or extraction failure. Zero-field counts are diagnostics only.')


def grouping_audit(entries, names, prior, output):
    manifest = g.f.read(prior / 'group-manifest.json')
    summary = g.f.read(prior / 'experiment-summary.json')
    scores = g.f.read(prior / 'development-scores.json')
    old_groups = manifest['groups']
    if (not summary.get('complete') or set(old_groups) != set(entries)
            or len(scores) != len(entries) or {r['sha256'] for r in scores} != set(entries)
            or old_groups != g.make_groups(entries, names)):
        raise ValueError('Previous grouped experiment does not match current cache pool/groups')
    for row in scores:
        expected = entries[row['sha256']]['record']
        if row['label'] != expected['label'] or row['source'] != expected['source'] or row['group'] != old_groups[row['sha256']]:
            raise ValueError('Previous development-score labels/sources/groups changed')
    old_overview = group_overview(entries, old_groups)
    largest = max(old_overview, key=lambda k: old_overview[k]['count'])
    malware_only = [k for k, v in old_overview.items() if v['malicious'] and not v['benign']]
    targets = [largest] + sorted(malware_only, key=lambda k: -old_overview[k]['count'])[:1]
    result = dict(complete=False, role='development_audit', sample_count=len(entries), components=[], modes={})
    for target in dict.fromkeys(targets):
        shas = [sha for sha in entries if old_groups[sha] == target]
        profile = feature_profile(shas, entries, names)
        template_buckets = defaultdict(list)
        for sha in shas:
            template_buckets[g.structural_template(entries[sha], names)].append(sha)
        bridges = []
        for template, members in template_buckets.items():
            cohorts = defaultdict(list)
            for sha in members:
                e = entries[sha]
                cohort = g.software_group(e) or 'unresolved-report:' + e['record']['source']
                cohorts[cohort].append(sha)
            if len(cohorts) <= 1:
                continue
            bridges.append(dict(template=list(template[:-1]) + [list(template[-1])], count=len(members),
                label_counts=dict(Counter(str(entries[s]['record']['label']) for s in members)),
                representation_count=len({fingerprint(entries[s]) for s in members}),
                cohorts={key: dict(count=len(ss), examples=ss[:3]) for key, ss in sorted(cohorts.items())}))
        selected_scores = [r for r in scores if r['group'] == target]
        score_unique = {key: len({r[key + '_score'] for r in selected_scores}) for key in ('refit_72', 'enhanced', 'skimmer')}
        result['components'].append(dict(group=target, **old_overview[target], feature_profile=profile,
            model_score_unique_counts=score_unique, template_bridge_count=len(bridges)))
        g.f.w.dump(output / ('component-' + target[:12] + '-details.json'), dict(group=target, sha256=shas,
            feature_profile=profile, template_bridges=sorted(bridges, key=lambda b: (-b['count'], str(b['template'])))))
    for mode in MODES:
        groups = mode_groups(entries, names, mode); overview = group_overview(entries, groups)
        result['modes'][mode] = dict(group_count=len(overview),
            largest_groups=[dict(group=k, **v) for k, v in sorted(overview.items(), key=lambda kv: -kv[1]['count'])[:10]])
    result.update(complete=True, interpretation='Split rules were revised after prior development results. This remains development analysis, not independent validation. Detailed bridges include unresolved historical reports, not verified software/family identities.')
    g.f.w.dump(output / 'grouping-audit-summary.json', result)
    return result


def diversity(rows, groups, fingerprints):
    malware = [r for r in rows if r['label'] == 1 and r['adapter_probability'] >= g.ROUTE]
    counts = Counter(groups[r['sha256']] for r in malware)
    representation_count = len({fingerprints[r['sha256']] for r in malware})
    share = max(counts.values(), default=0) / len(malware) if malware else 1.
    return dict(routed_malware=len(malware), malware_groups=len(counts),
        malware_representations=representation_count, largest_malware_group_share=share,
        diverse=len(malware) >= MIN_MALWARE and len(counts) >= MIN_MALWARE_GROUPS
                and representation_count >= MIN_MALWARE_GROUPS and share <= MAX_GROUP_SHARE)


def split_plan(rows, groups, fingerprints, fold_ids):
    count = int(max(fold_ids)) + 1; result = []
    for held_fold in range(count):
        held_ids = np.flatnonzero(fold_ids == held_fold)
        alternatives = []
        others = [i for i in range(count) if i != held_fold]
        # Prefer one diverse calibration fold. Combine two only if needed.
        for n in (1, 2):
            for cal_folds in itertools.combinations(others, n):
                cal_ids = np.flatnonzero(np.isin(fold_ids, cal_folds))
                fit_ids = np.flatnonzero((fold_ids != held_fold) & ~np.isin(fold_ids, cal_folds))
                cal_rows, fit_rows = ([rows[i] for i in ids] for ids in (cal_ids, fit_ids))
                cd, fd = diversity(cal_rows, groups, fingerprints), diversity(fit_rows, groups, fingerprints)
                if not cd['diverse'] or not fd['diverse']:
                    continue
                if {r['label'] for r in cal_rows} != {0, 1} or {r['label'] for r in fit_rows} != {0, 1}:
                    continue
                # Assignment consults counts/groups only, never predictions.
                rank = (n, abs(len(cal_ids) - len(rows) / count), cal_folds)
                alternatives.append((rank, fit_ids, cal_ids, cd, fd))
            if alternatives:
                break
        if not alternatives:
            raise ValueError(f'No diverse fit/calibration split for held fold {held_fold}; inspect group audit rather than splitting aliases')
        _, fit_ids, cal_ids, cd, fd = min(alternatives, key=lambda x: x[0])
        result.append(dict(fold=held_fold, fit=fit_ids, calibration=cal_ids, held=held_ids,
                           calibration_diversity=cd, fit_diversity=fd))
    return result


def assert_split(rows, groups, roles):
    sha_sets = [{rows[i]['sha256'] for i in ids} for ids in roles]
    if set.union(*sha_sets) != {r['sha256'] for r in rows}:
        raise ValueError('Split SHA coverage incomplete')
    for a, b in itertools.combinations(sha_sets, 2):
        if a & b or {groups[s] for s in a} & {groups[s] for s in b}:
            raise ValueError('Group/SHA overlap between split roles')


def assess_policy(policy, calibration_diversity):
    result = dict(policy)
    result['zero_recall'] = result['overall']['tpr'] == 0.
    result['eligible_development_policy'] = (result['feasible'] and not result['zero_recall']
                                             and calibration_diversity['diverse'])
    return result


def overlap_report(rows, groups, roles, entries, names):
    tags = {}
    for label, ids in roles.items():
        tags[label] = dict(provenance={g.software_group(entries[rows[i]['sha256']]) for i in ids} - {None},
                           template={g.structural_template(entries[rows[i]['sha256']], names) for i in ids},
                           representation={fingerprint(entries[rows[i]['sha256']]) for i in ids})
    return {a + '_vs_' + b: {key: len(tags[a][key] & tags[b][key]) for key in tags[a]}
            for a, b in itertools.combinations(tags, 2)}


def control_mode(entries, names, output, mode, outer_count=5):
    keys = sorted(entries); rows = [entries[k]['record'] for k in keys]
    groups = mode_groups(entries, names, mode)
    fingerprints = {k: fingerprint(entries[k]) for k in keys}
    overview = group_overview(entries, groups)
    g.f.w.dump(output / 'group-overview.json', overview)
    folds = g.group_folds(rows, groups, outer_count)
    plan = split_plan(rows, groups, fingerprints, folds)
    manifest = dict(role='development', mode=mode, groups=groups, folds=[])
    for fold in plan:
        roles = [fold[k] for k in ('fit', 'calibration', 'held')]
        assert_split(rows, groups, roles)
        manifest['folds'].append(dict(fold=fold['fold'], **{k: [rows[i]['sha256'] for i in fold[k]] for k in ('fit', 'calibration', 'held')},
            calibration_diversity=fold['calibration_diversity'], fit_diversity=fold['fit_diversity'],
            other_panel_overlap=overlap_report(rows, groups, {k: fold[k] for k in ('fit', 'calibration', 'held')}, entries, names)))
    g.f.w.dump(output / 'split-manifest.json', manifest)
    schema = names + list(g.f.t.e.IMPORT_FEATURES)
    X = np.array([entries[k]['feature_vector'] + list(g.f.t.e._import_values({'libraries': entries[k]['libraries']})) for k in keys])
    summary = dict(complete=False, role='development', mode=mode, sample_count=len(rows), group_count=len(overview),
        configuration=g.f.w.CONFIG, seed=g.SEED, folds=[],
        limits='Same fixed legacy base/adapter; their historical training overlap is not removed. Post-hoc grouping revision, no independent final validation. Other-panel overlap is reported, not hidden.',
        diversity_requirements=dict(min_routed_malware=MIN_MALWARE, min_malware_groups=MIN_MALWARE_GROUPS,
            min_malware_representations=MIN_MALWARE_GROUPS, max_single_group_share=MAX_GROUP_SHARE))
    scores = []
    for fold in plan:
        fit_ids, cal_ids, held_ids = (fold[k] for k in ('fit', 'calibration', 'held'))
        fit_rows, cal_rows, held_rows = ([rows[i] for i in ids] for ids in (fit_ids, cal_ids, held_ids))
        print(f'{mode} control fold {fold["fold"] + 1}/{outer_count}: fit={len(fit_ids)}, cal={len(cal_ids)}, held={len(held_ids)}; cal malware groups={fold["calibration_diversity"]["malware_groups"]}', flush=True)
        clf = g.fit_model(X[fit_ids], fit_rows)
        cp = clf.predict_proba(X[cal_ids])[:, 1]
        policy = g.calibration(cal_rows, cp, lambda t: g.gated(cal_rows, cp, t))
        policy = assess_policy(policy, fold['calibration_diversity'])
        hp = clf.predict_proba(X[held_ids])[:, 1]
        calibrated = g.gated(held_rows, hp, policy['threshold'])
        fixed = g.gated(held_rows, hp, g.REFERENCE_THRESHOLD)
        parity = g.export_checked(clf, schema, policy['threshold'], X,
                                  output / f'fold-{fold["fold"]:02d}-control-model.json')
        result = dict(fold=fold['fold'], calibration=policy, calibration_diversity=fold['calibration_diversity'],
            export_parity=parity, held_calibrated=g.rates(held_rows, calibrated, groups),
            held_fixed=g.rates(held_rows, fixed, groups))
        summary['folds'].append(result)
        for i, r in enumerate(held_rows):
            scores.append(dict(sha256=r['sha256'], label=r['label'], source=r['source'], group=groups[r['sha256']],
                fold=fold['fold'], reviewer_score=float(hp[i]), calibrated_prediction=int(calibrated[i]),
                fixed_prediction=int(fixed[i]), calibrated_threshold=policy['threshold'],
                policy_eligible=policy['eligible_development_policy']))
        g.f.w.dump(output / 'control-summary.json', summary)
        g.f.w.dump(output / 'development-scores.json', scores)
        print('  Held-out calibrated: ' + json.dumps(result['held_calibrated']['overall']), flush=True)
    if len(scores) != len(entries) or {r['sha256'] for r in scores} != set(entries):
        raise ValueError('Control held-out coverage incomplete/duplicated')
    summary['pooled'] = {name: g.rates(scores, np.array([r[name + '_prediction'] for r in scores]), groups)
                         for name in ('calibrated', 'fixed')}
    summary['all_calibrated_policies_eligible'] = all(r['calibration']['eligible_development_policy'] for r in summary['folds'])
    summary['complete'] = True
    g.f.w.dump(output / 'control-summary.json', summary)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__); root = g.f.w.ROOT / 'validation-data'
    ap.add_argument('--bundle', type=Path, default=root / 'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache', type=Path, default=root / 'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit', type=Path, action='append')
    ap.add_argument('--fresh-comparison', type=Path, action='append')
    ap.add_argument('--previous', type=Path, default=root / 'reviewer-v8-grouped-experiment-development')
    ap.add_argument('--output', type=Path, default=root / 'reviewer-v8-grouping-controls-development')
    ap.add_argument('--audit-only', action='store_true')
    args = ap.parse_args()
    args.fresh_audit = args.fresh_audit or [root / 'reviewer-v8-fresh-error-audit', root / 'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison = args.fresh_comparison or [root / 'reviewer-v8-fresh-evaluation', root / 'reviewer-v8-fresh-git-evaluation']
    try:
        g.f.fresh_output(args.output)
        if len(args.fresh_audit) != len(args.fresh_comparison):
            raise ValueError('Each fresh audit requires its completed evaluation')
        entries, names, hashes, converted = g.load_inputs(args)
        for filename in ('group-manifest.json', 'experiment-summary.json', 'development-scores.json'):
            hashes[str(args.previous / filename)] = g.digest(args.previous / filename)
        g.f.w.dump(args.output / 'inputs.json', dict(role='development', input_sha256=hashes,
            script_sha256=g.digest(Path(__file__)), dependency_script_sha256=g.digest(Path(g.__file__)),
            former_evaluation_shas_now_development=converted))
        _, _, exclusions = g.f.load_bundle(args.bundle)
        g.f.w.dump(args.output / 'excluded-sha256.json', sorted(exclusions | set(entries)))
        audit = grouping_audit(entries, names, args.previous, args.output)
        print('Grouping audit complete: ' + json.dumps({k: v['group_count'] for k, v in audit['modes'].items()}), flush=True)
        if not args.audit_only:
            combined = dict(complete=False, role='development', models='72-feature reviewer only; no skimmer or enhanced reviewer fitted', modes={})
            for mode in MODES:
                result = control_mode(entries, names, args.output / mode, mode)
                combined['modes'][mode] = dict(all_calibrated_policies_eligible=result['all_calibrated_policies_eligible'],
                    calibrated=result['pooled']['calibrated']['overall'], fixed=result['pooled']['fixed']['overall'])
                g.f.w.dump(args.output / 'control-comparison-summary.json', combined)
            combined['complete'] = True
            g.f.w.dump(args.output / 'control-comparison-summary.json', combined)
        print(f'Send grouping-audit-summary.json from {args.output}', flush=True)
        if not args.audit_only:
            print('Also send control-comparison-summary.json, provenance/control-summary.json and template/control-summary.json.', flush=True)
    except Exception as error:
        ap.exit(2, f'V8 grouping controls stopped: {error}\n')


if __name__ == '__main__':
    main()
