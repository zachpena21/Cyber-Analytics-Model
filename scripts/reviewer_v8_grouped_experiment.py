#!/usr/bin/env python3
"""Offline grouped development comparison: refit reviewer, build/import reviewer, skimmer.

Uses complete Docker audit caches. Does not run samples or change deployed models.
Previously evaluated acquisitions become development data in this experiment.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import re

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

import reviewer_v8_fresh_validation as f

SEED = 8704
ROUTE = .15
REFERENCE_THRESHOLD = .639722991937624
BASE_THRESHOLD = .510001
ADAPTER_THRESHOLD = .7
EXTRA_NAMES = (
    'build_linker2', 'build_linker2_symbols', 'build_linker2_no_debug',
    'build_linker2_tls', 'build_symbols_no_debug_tls',
    'imports_managed_runtime', 'imports_cygwin_runtime', 'imports_msvcrt',
    'imports_ucrt_api_count', 'imports_cpp_runtime', 'imports_crypto_runtime',
    'imports_network_runtime', 'imports_library_count', 'imports_sparse_le3',
)
ZONE_NAMES = ('oof_reviewer_score', 'zone_base_malware', 'zone_adapter_malware',
              'zone_reviewer_malware', 'zone_disagreement', 'zone_reviewer_middle')
SKIMMER_CONFIG = dict(n_estimators=64, learning_rate=.05, max_depth=2,
                      min_samples_leaf=16, max_features=None, subsample=1.)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def attributes(entry, names):
    return dict(zip(names, entry['feature_vector']))


def libraries(entry):
    return sorted(set(x.replace('\\', '/').rsplit('/', 1)[-1].casefold()
                      for x in entry['libraries'].split()))


def extra_values(entry, names):
    a = attributes(entry, names)
    libs = libraries(entry)
    linker2 = a['major_linker_version'] == 2
    symbols = a['symbols'] > 0
    debug = a['has_debug'] > 0
    tls = a['has_tls'] > 0
    return list(map(float, (
        linker2, linker2 and symbols, linker2 and not debug, linker2 and tls,
        symbols and not debug and tls,
        'mscoree.dll' in libs, any('cygwin' in x or x == 'msys-2.0.dll' for x in libs),
        'msvcrt.dll' in libs, sum(x.startswith('api-ms-win-crt-') for x in libs),
        any(x.startswith(('libstdc++', 'libgcc', 'msvcp', 'vcruntime')) for x in libs),
        any(x in ('crypt32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'ncrypt.dll') for x in libs),
        any(x in ('ws2_32.dll', 'wininet.dll', 'winhttp.dll') or x.startswith('libcurl') for x in libs),
        len(libs), a['imports'] <= 3,
    )))


def checked_entry(sha, entry, names, candidates):
    row = entry['record']
    vector = entry['feature_vector']
    if (row['sha256'] != sha or row['label'] not in (0, 1)
            or len(sha) != 64 or re.fullmatch('[0-9a-f]{64}', sha) is None):
        raise ValueError('Invalid cache SHA/label')
    if len(vector) != len(names) or not np.isfinite(vector).all():
        raise ValueError('Cache feature schema/nonfinite value mismatch')
    if vector[:6] != [row[k] for k in f.w.SCORE_FEATURES]:
        raise ValueError('Cache component/vector mismatch')
    if row['adapter_threshold'] != ADAPTER_THRESHOLD or not isinstance(entry['libraries'], str):
        raise ValueError('Cache adapter threshold/imports mismatch')
    flags = list(f.t.e._import_values({'libraries': entry['libraries']}))
    for name in ('v7', 'v8_import_midpoint'):
        model = candidates[name][0]
        score = f.c.reviewer_score(model, vector + (flags if name != 'v7' else []))
        routed, pred = f.c.verdict(score, model, row, ADAPTER_THRESHOLD)
        if (abs(score - row[name + '_score']) > 1e-9
                or routed != row[name + '_routed'] or pred != row[name + '_prediction']):
            raise ValueError(f'Cache does not reproduce frozen scores/gates: {sha}')


def load_inputs(args):
    bundle, candidates, excluded = f.load_bundle(args.bundle)
    names = list(candidates['v7'][0].feature_names)
    if len(names) != 66:
        raise ValueError('Expected frozen 66-feature Docker schema')
    if digest(args.training_cache) != bundle['inputs']['docker_cache_sha256']:
        raise ValueError('Original Docker cache differs from frozen bundle')
    old = f.read(args.training_cache)
    if not old.get('complete') or len(old['samples']) != bundle['exclusions']['development_samples']:
        raise ValueError('Original Docker cache is incomplete/count mismatch')
    entries = dict(old['samples'])
    if not set(entries) <= excluded:
        raise ValueError('Original Docker samples absent from frozen exclusions')
    hashes = {str(args.bundle / 'freeze-manifest.json'): digest(args.bundle / 'freeze-manifest.json'),
              str(args.training_cache): digest(args.training_cache)}
    converted = []
    for audit, comparison in zip(args.fresh_audit, args.fresh_comparison):
        summary = f.read(audit / 'audit-summary.json')
        cache = f.read(audit / 'docker-feature-cache.json')
        bound = f.read(audit / 'inputs.json')
        evaluation = f.read(comparison / 'evaluation-manifest.json')
        previous = {r['sha256']: r for r in f.read(comparison / 'comparison-scores.json')}
        if (not evaluation.get('complete') or evaluation.get('role') != 'evaluation'
                or digest(comparison / 'evaluation-manifest.json') != bound['evaluation_manifest_sha256']
                or digest(comparison / 'comparison-scores.json') != bound['evaluation_scores_sha256']):
            raise ValueError('Fresh audit does not match its completed evaluation')
        if (not summary.get('complete') or not cache.get('complete')
                or summary['sample_count'] != len(cache['samples'])
                or bound['freeze_manifest_sha256'] != digest(args.bundle / 'freeze-manifest.json')):
            raise ValueError('Fresh audit incomplete or frozen provenance mismatch')
        if set(cache['samples']) & (set(entries) | excluded):
            raise ValueError('Fresh audit duplicates another pool or frozen development SHA')
        wanted = {r['sha256']: r for r in evaluation['samples']}
        if set(cache['samples']) != set(wanted) or set(previous) != set(wanted):
            raise ValueError('Fresh audit SHA coverage differs from completed evaluation')
        for sha, entry in cache['samples'].items():
            row = entry['record']
            if row['label'] != wanted[sha]['label'] or row['source'] != wanted[sha]['source_id']:
                raise ValueError('Fresh cache label/source differs from completed evaluation')
            for key in (*f.w.SCORE_FEATURES, 'adapter_threshold',
                        *(n + suffix for n in f.c.NAMES for suffix in ('_score', '_prediction', '_routed'))):
                if row[key] != previous[sha][key]:
                    raise ValueError('Fresh cache scores/components differ from completed evaluation')
        entries.update(cache['samples'])
        converted.extend(cache['samples'])
        for filename in ('audit-summary.json', 'docker-feature-cache.json', 'inputs.json'):
            hashes[str(audit / filename)] = digest(audit / filename)
        for filename in ('evaluation-manifest.json', 'comparison-scores.json'):
            hashes[str(comparison / filename)] = digest(comparison / filename)
    for i, (sha, entry) in enumerate(sorted(entries.items()), 1):
        if i % 1000 == 0:
            print(f'Checking Docker cache parity {i}/{len(entries)}', flush=True)
        checked_entry(sha, entry, names, candidates)
    return entries, names, hashes, sorted(converted)


def software_group(entry):
    """Provenance is used for splitting only, never as a model input."""
    row = entry['record']
    source = row['source'].casefold()
    provenance = entry.get('provenance') or {}
    if not isinstance(provenance, dict):
        provenance = {}
    nested = provenance.get('provenance') or {}
    if isinstance(nested, dict) and nested.get('package'):
        return 'software:' + nested['package'].casefold().replace('_', '-')
    if source.startswith('portablegit-'):
        return 'software:git'
    path = str(entry.get('original_path') or provenance.get('original_path') or '').replace('\\', '/').casefold()
    match = re.search(r'/program files(?: \(x86\))?/([^/]+)', path)
    if row['label'] == 0 and match:
        return 'software:' + match.group(1)
    if row['label'] == 1:
        batch = provenance.get('batch_url')
        # Hourly batches are acquisition groups; template links also span hours.
        if batch:
            return 'malware-acquisition:' + str(batch)
        if source.startswith('coverage-malware:'):
            return 'malware-acquisition:' + source.removeprefix('coverage-malware:')
        # Historical report names can mix acquisitions. Group their templates,
        # rather than claiming that the report itself is one malware family.
        return None
    return None


def structural_template(entry, names):
    a = attributes(entry, names)
    keys = ('major_linker_version', 'minor_linker_version', 'symbols', 'has_debug',
            'has_tls', 'imports', 'exports', 'numberof_sections')
    # Deliberately omit label, source, filename and scores.
    return tuple(a[k] for k in keys) + (tuple(libraries(entry)),)


def make_groups(entries, names):
    keys = sorted(entries)
    parent = {k: k for k in keys}

    def find(k):
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)

    templates, software = {}, {}
    for sha in keys:
        template = structural_template(entries[sha], names)
        if template in templates:
            union(sha, templates[template])
        templates[template] = sha
        group = software_group(entries[sha])
        if group:
            if group in software:
                union(sha, software[group])
            software[group] = sha
    groups = {sha: find(sha) for sha in keys}
    return groups


def group_folds(rows, groups, count, seed=SEED):
    """Deterministic label-count balancing; never consult scores or errors."""
    members = defaultdict(list)
    for i, row in enumerate(rows):
        members[groups[row['sha256']]].append(i)
    if len(members) < count:
        raise ValueError('Too few independent groups for requested folds')
    totals = np.bincount([r['label'] for r in rows], minlength=2).astype(float)
    if np.any(totals == 0):
        raise ValueError('Both labels required')
    sizes = {g: np.bincount([rows[i]['label'] for i in ids], minlength=2) for g, ids in members.items()}
    order = sorted(members, key=lambda g: (-max(sizes[g] / totals), -len(members[g]),
                    hashlib.sha256(f'{seed}:{g}'.encode()).hexdigest()))
    counts = np.zeros((count, 2)); assignment = {}
    for g in order:
        options = []
        for fold in range(count):
            trial = counts.copy(); trial[fold] += sizes[g]
            imbalance = float(np.sum((trial / totals - 1 / count) ** 2))
            options.append((imbalance, float(counts[fold].sum()), fold))
        fold = min(options)[2]; assignment[g] = fold; counts[fold] += sizes[g]
    result = np.array([assignment[groups[r['sha256']]] for r in rows])
    for fold in range(count):
        selected = [rows[i] for i in np.flatnonzero(result == fold)]
        if {r['label'] for r in selected} != {0, 1}:
            raise ValueError('Group imbalance leaves a single-class fold; inspect groups, do not split templates')
    return result


def fit_model(X, rows, selected=None, skimmer=False):
    ids = np.array(selected if selected is not None else [i for i, r in enumerate(rows)
                                                         if r['adapter_probability'] >= ROUTE], dtype=int)
    y = np.array([rows[i]['label'] for i in ids])
    if set(y) != {0, 1}:
        raise ValueError('Both classes required in routed fitting data')
    clf = GradientBoostingClassifier(**(SKIMMER_CONFIG if skimmer else f.w.CONFIG), random_state=SEED)
    clf.fit(X[ids], y, sample_weight=compute_sample_weight('balanced', y))
    return clf


def oof_scores(X, rows, groups, count=3, fitter=fit_model):
    folds = group_folds(rows, groups, count, SEED + 1)
    scores = np.full(len(rows), np.nan); manifests = []
    for fold in range(count):
        fit_ids = np.flatnonzero(folds != fold); held_ids = np.flatnonzero(folds == fold)
        fit_rows = [rows[i] for i in fit_ids]
        held_groups = {groups[rows[i]['sha256']] for i in held_ids}
        if held_groups & {groups[r['sha256']] for r in fit_rows}:
            raise ValueError('OOF group leaked into fit')
        clf = fitter(X[fit_ids], fit_rows)
        scores[held_ids] = clf.predict_proba(X[held_ids])[:, 1]
        manifests.append(dict(fold=fold, fit=[r['sha256'] for r in fit_rows],
                              held=[rows[i]['sha256'] for i in held_ids]))
        print(f'  Skimmer input OOF fold {fold + 1}/{count} completed', flush=True)
    if not np.isfinite(scores).all():
        raise ValueError('Incomplete OOF coverage')
    return scores, manifests


def zone_values(row, score):
    base = row['benign_probability'] < BASE_THRESHOLD
    adapter = row['adapter_probability'] >= ADAPTER_THRESHOLD
    reviewer = score >= REFERENCE_THRESHOLD
    return [float(score), float(base), float(adapter), float(reviewer),
            float(base != adapter or adapter != reviewer), float(.3181019231722836 <= score <= .85)]


def skimmer_region(row, score, extra):
    # Predeclared error-derived hypothesis, not a tuned or benign-bypass rule.
    return row['adapter_probability'] >= ROUTE and bool(
        zone_values(row, score)[4] or extra[0] or extra[5] or extra[-1])


def gated(rows, scores, threshold):
    return np.array([int(s >= threshold) if r['adapter_probability'] >= ROUTE else
                     int(r['adapter_probability'] >= ADAPTER_THRESHOLD) for r, s in zip(rows, scores)])


def skim_predictions(rows, scores, threshold, first_scores, first_threshold, region):
    pred = gated(rows, first_scores, first_threshold)
    pred[np.asarray(region, dtype=bool)] = np.asarray(scores)[region] >= threshold
    return pred


def calibration(rows, scores, predict, max_fpr=.01):
    """Same FPR caps/objective as previous workflow, with arbitrary fixed gates."""
    labels = np.array([r['label'] for r in rows]); n0 = int(sum(labels == 0)); n1 = int(sum(labels == 1))
    if not n0 or not n1:
        raise ValueError('Both classes required for calibration')
    by_source = {s: np.array([i for i, r in enumerate(rows) if r['source'] == s])
                 for s in sorted({r['source'] for r in rows})}
    constraints = [ids[labels[ids] == 0] for ids in by_source.values() if sum(labels[ids] == 0) >= 100]
    unique = np.unique(scores)
    thresholds = np.unique(np.r_[unique, np.nextafter(unique, np.inf), 1.])
    best = None
    for threshold in thresholds:
        if not 0 < threshold <= 1:
            continue
        pred = predict(float(threshold)).astype(bool)
        fp = int(sum(pred & (labels == 0))); fn = int(sum(~pred & (labels == 1)))
        worst = max((float(pred[ids].mean()) for ids in constraints), default=0.)
        if fp / n0 > max_fpr + 1e-15 or worst > max_fpr + 1e-15:
            continue
        rank = (1 - fn / n1, -worst, -fp / n0, float(threshold))
        if best is None or rank > best[0]:
            best = (rank, float(threshold))
    threshold = best[1] if best else 1.
    pred = predict(threshold)
    return dict(feasible=best is not None, threshold=threshold,
                fallback='reject all scores below 1; not an eligible policy' if best is None else None,
                overall=f.w.metrics(rows, pred),
                by_source={s: f.w.metrics([rows[i] for i in ids], pred[ids]) for s, ids in by_source.items()})


def tree_payload(clf, names, threshold):
    spec = dict(route_min=ROUTE, feature_names=list(names), categories={}, derived_features=[])
    payload = f.w.export(clf, spec, threshold)
    payload.update(format_version='grouped_development_v1', development_only=True,
                   runtime_supported=False)
    return payload


def exported_scores(payload, X):
    X = np.asarray(X, dtype=np.float32).tolist(); result = []
    for vector in X:
        leaves = []
        for tree in payload['estimators']:
            node = 0
            while tree['children_left'][node] >= 0:
                left = vector[tree['feature'][node]] <= tree['threshold'][node]
                node = tree['children_left' if left else 'children_right'][node]
            leaves.append(tree['raw_value'][node])
        raw = payload['initial_raw_score'] + payload['learning_rate'] * sum(leaves)
        value = 1 / (1 + math.exp(-raw)) if raw >= 0 else math.exp(raw) / (1 + math.exp(raw))
        result.append(value)
    return np.array(result)


def export_checked(clf, names, threshold, X, path):
    payload = tree_payload(clf, names, threshold)
    error = float(np.max(np.abs(exported_scores(payload, X) - clf.predict_proba(X)[:, 1])))
    if error > 1e-10:
        raise ValueError(f'Float32 tree export parity failed: {error}')
    f.w.dump(path, payload)
    return error


def rates(rows, pred, groups):
    result = dict(overall=f.w.metrics(rows, pred), by_source={}, by_group={})
    for field, values in (('source', {r['source'] for r in rows}), ('group', {groups[r['sha256']] for r in rows})):
        for value in sorted(values):
            ids = [i for i, r in enumerate(rows) if (r['source'] if field == 'source' else groups[r['sha256']]) == value]
            result['by_' + field][value] = f.w.metrics([rows[i] for i in ids], pred[ids])
    return result


def experiment(entries, names, output, outer_count=5, inner_count=3):
    keys = sorted(entries); rows = [entries[k]['record'] for k in keys]
    groups = make_groups(entries, names)
    members = defaultdict(list)
    for r in rows:
        members[groups[r['sha256']]].append(r)
    f.w.dump(output / 'group-overview.json', dict(group_count=len(members),
        groups={g: dict(count=len(rs), benign=sum(r['label'] == 0 for r in rs),
                        malicious=sum(r['label'] == 1 for r in rs), sources=dict(Counter(r['source'] for r in rs)))
                for g, rs in members.items()}))
    print(f'Connected split groups: {len(members)}; largest={max(map(len, members.values()))}', flush=True)
    folds = group_folds(rows, groups, outer_count)
    base_names = names + list(f.t.e.IMPORT_FEATURES)
    enhanced_names = base_names + list(EXTRA_NAMES)
    base_X = np.array([entries[k]['feature_vector'] + list(f.t.e._import_values({'libraries': entries[k]['libraries']})) for k in keys])
    extra_X = np.array([extra_values(entries[k], names) for k in keys])
    X = np.c_[base_X, extra_X]
    summary = dict(complete=False, role='development', experiment='v8_grouped_reviewer_and_skimmer',
        sample_count=len(rows), group_count=len(set(groups.values())), folds=[],
        baseline_configuration=f.w.CONFIG, enhanced_configuration=f.w.CONFIG,
        skimmer_configuration=SKIMMER_CONFIG, seed=SEED, outer_folds=outer_count,
        inner_folds=inner_count, added_features=list(EXTRA_NAMES),
        route_min=ROUTE, calibration_fpr_cap=.01,
        group_rule='Connected components of software/acquisition groups and label-free structural/import templates. Transitive links stay intact.',
        score_scope='Reviewer scores for skimmer fitting are group-OOF. Base/adapter are fixed legacy models; their own historical training overlap is not removed. Not a fully OOF whole-stack evaluation.',
        interpretation='All batches are development data. Features/gates were informed by prior errors. No promotion or independent final validation.',
        skimmer_region='Routed AND (base/adapter/reviewer disagreement OR linker2 OR managed-runtime import OR <=3 imports). Reviewer zone uses fixed .639722991937624, not a held-out-tuned gate.',
        skimmer_features=enhanced_names + list(ZONE_NAMES))
    manifest = dict(role='development', groups=groups, outer_fold={k: int(folds[i]) for i, k in enumerate(keys)}, folds=[])
    f.w.dump(output / 'group-manifest.json', manifest)
    all_scores = []
    for fold in range(outer_count):
        cal_fold = (fold + 1) % outer_count
        fit_ids = np.flatnonzero((folds != fold) & (folds != cal_fold))
        cal_ids = np.flatnonzero(folds == cal_fold); test_ids = np.flatnonzero(folds == fold)
        fit_rows, cal_rows, test_rows = ([rows[i] for i in ids] for ids in (fit_ids, cal_ids, test_ids))
        print(f'Outer fold {fold + 1}/{outer_count}: fit={len(fit_ids)}, calibration={len(cal_ids)}, held={len(test_ids)}', flush=True)
        fold_dir = output / f'fold-{fold:02d}'
        split = dict(fold=fold, fit=[r['sha256'] for r in fit_rows], calibration=[r['sha256'] for r in cal_rows],
                     held=[r['sha256'] for r in test_rows])
        full_models = {}
        record = dict(fold=fold, models={})
        held_predictions = {}; held_probabilities = {}
        for label, features, schema in (('refit_72', base_X, base_names), ('enhanced', X, enhanced_names)):
            clf = fit_model(features[fit_ids], fit_rows)
            cp = clf.predict_proba(features[cal_ids])[:, 1]
            policy = calibration(cal_rows, cp, lambda t: gated(cal_rows, cp, t))
            hp = clf.predict_proba(features[test_ids])[:, 1]
            pred = gated(test_rows, hp, policy['threshold'])
            parity = export_checked(clf, schema, policy['threshold'], features[np.r_[fit_ids, cal_ids, test_ids]],
                                    fold_dir / (label + '-model.json'))
            record['models'][label] = dict(calibration=policy, held=rates(test_rows, pred, groups),
                                          export_parity=parity,
                                          held_at_fixed_threshold=rates(test_rows, gated(test_rows, hp, REFERENCE_THRESHOLD), groups))
            full_models[label] = (clf, cp, hp, policy)
            held_predictions[label] = pred; held_probabilities[label] = hp
        first, first_cp, first_hp, first_policy = full_models['enhanced']
        oof, inner_manifest = oof_scores(X[fit_ids], fit_rows, groups, inner_count)
        split['skimmer_oof'] = inner_manifest
        fit_meta = np.c_[X[fit_ids], np.array([zone_values(r, s) for r, s in zip(fit_rows, oof)])]
        fit_region = np.array([skimmer_region(r, s, extra_X[i]) for r, s, i in zip(fit_rows, oof, fit_ids)])
        skim = fit_model(fit_meta, fit_rows, selected=np.flatnonzero(fit_region), skimmer=True)
        cal_meta = np.c_[X[cal_ids], np.array([zone_values(r, s) for r, s in zip(cal_rows, first_cp)])]
        test_meta = np.c_[X[test_ids], np.array([zone_values(r, s) for r, s in zip(test_rows, first_hp)])]
        cal_region = np.array([skimmer_region(r, s, extra_X[i]) for r, s, i in zip(cal_rows, first_cp, cal_ids)])
        test_region = np.array([skimmer_region(r, s, extra_X[i]) for r, s, i in zip(test_rows, first_hp, test_ids)])
        cp = skim.predict_proba(cal_meta)[:, 1]; hp = skim.predict_proba(test_meta)[:, 1]
        policy = calibration(cal_rows, cp, lambda t: skim_predictions(cal_rows, cp, t, first_cp, first_policy['threshold'], cal_region))
        pred = skim_predictions(test_rows, hp, policy['threshold'], first_hp, first_policy['threshold'], test_region)
        parity = export_checked(skim, enhanced_names + list(ZONE_NAMES), policy['threshold'],
                                np.r_[fit_meta, cal_meta, test_meta], fold_dir / 'skimmer-model.json')
        f.w.dump(fold_dir / 'policy.json', dict(role='development', first_stage='enhanced-model.json',
            skimmer='skimmer-model.json', first_threshold=first_policy['threshold'], skimmer_threshold=policy['threshold'],
            zone_reference_threshold=REFERENCE_THRESHOLD, route_min=ROUTE, region=summary['skimmer_region'],
            runtime_supported=False))
        record['models']['skimmer'] = dict(calibration=policy, held=rates(test_rows, pred, groups), export_parity=parity,
            fitting_region_count=int(fit_region.sum()), calibration_region_count=int(cal_region.sum()),
            held_region_count=int(test_region.sum()), first_stage_calibration_feasible=first_policy['feasible'])
        held_predictions['skimmer'] = pred; held_probabilities['skimmer'] = hp
        for i, row in enumerate(test_rows):
            score_row = dict(sha256=row['sha256'], source=row['source'], label=row['label'], group=groups[row['sha256']], fold=fold,
                             skimmer_routed=bool(test_region[i]))
            for label in held_predictions:
                score_row[label + '_score'] = float(held_probabilities[label][i])
                score_row[label + '_prediction'] = int(held_predictions[label][i])
            all_scores.append(score_row)
        f.w.dump(fold_dir / 'skimmer-oof-scores.json', [dict(sha256=r['sha256'], score=float(s),
                                                         region=bool(region)) for r, s, region in zip(fit_rows, oof, fit_region)])
        manifest['folds'].append(split); summary['folds'].append(record)
        f.w.dump(output / 'group-manifest.json', manifest)
        f.w.dump(output / 'development-scores.json', all_scores)
        f.w.dump(output / 'experiment-summary.json', summary)
        print('  Held-out development: ' + json.dumps({k: v['held']['overall'] for k, v in record['models'].items()}), flush=True)
    if {r['sha256'] for r in all_scores} != set(entries) or len(all_scores) != len(entries):
        raise ValueError('Outer held-out coverage is incomplete/duplicated')
    summary['pooled_group_heldout'] = {}
    for label in ('refit_72', 'enhanced', 'skimmer'):
        pred = np.array([r[label + '_prediction'] for r in all_scores])
        eligible = all(x['models'][label]['calibration']['feasible'] for x in summary['folds'])
        if label == 'skimmer':
            eligible &= all(x['models'][label]['first_stage_calibration_feasible'] for x in summary['folds'])
        summary['pooled_group_heldout'][label] = dict(eligible_policy=bool(eligible), **rates(all_scores, pred, groups))
    summary['paired_changes_vs_refit'] = {}
    for label in ('enhanced', 'skimmer'):
        paired = {}
        for cls in (0, 1):
            selected = [r for r in all_scores if r['label'] == cls]
            paired[str(cls)] = dict(rescued=sum(r['refit_72_prediction'] != cls and r[label + '_prediction'] == cls for r in selected),
                                   regressed=sum(r['refit_72_prediction'] == cls and r[label + '_prediction'] != cls for r in selected))
        summary['paired_changes_vs_refit'][label] = paired
    summary['complete'] = True
    f.w.dump(output / 'experiment-summary.json', summary)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    root = f.w.ROOT / 'validation-data'
    ap.add_argument('--bundle', type=Path, default=root / 'reviewer-v8-frozen-validation')
    ap.add_argument('--training-cache', type=Path, default=root / 'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit', type=Path, action='append', help='Repeat to override the two default fresh audit directories')
    ap.add_argument('--fresh-comparison', type=Path, action='append', help='Completed evaluation directory paired with each --fresh-audit')
    ap.add_argument('--output', type=Path, default=root / 'reviewer-v8-grouped-experiment-development')
    args = ap.parse_args()
    args.fresh_audit = args.fresh_audit or [root / 'reviewer-v8-fresh-error-audit', root / 'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison = args.fresh_comparison or [root / 'reviewer-v8-fresh-evaluation', root / 'reviewer-v8-fresh-git-evaluation']
    try:
        f.fresh_output(args.output)
        if len(args.fresh_audit) != len(args.fresh_comparison):
            raise ValueError('Each fresh audit needs a matching fresh comparison directory')
        entries, names, hashes, converted = load_inputs(args)
        f.w.dump(args.output / 'inputs.json', dict(role='development', input_sha256=hashes, script_sha256=digest(Path(__file__)),
            dependency_versions={k: importlib.metadata.version(k) for k in ('numpy', 'scikit-learn')},
            former_evaluation_shas_now_development=converted))
        # Future validation must exclude old reports and every newly reused SHA.
        _, _, excluded = f.load_bundle(args.bundle)
        f.w.dump(args.output / 'excluded-sha256.json', sorted(excluded | set(entries)))
        result = experiment(entries, names, args.output)
        print(json.dumps({k: v['overall'] for k, v in result['pooled_group_heldout'].items()}, indent=2))
        print(f'Send experiment-summary.json and group-manifest.json from {args.output}', flush=True)
    except Exception as error:
        ap.exit(2, f'V8 grouped experiment stopped: {error}\n')


if __name__ == '__main__':
    main()
