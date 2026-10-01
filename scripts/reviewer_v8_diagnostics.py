#!/usr/bin/env python3
"""Explain v8 import-experiment holdout errors and calibration sensitivity.

Diagnostic only: writes no model and makes no production threshold selection.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

import numpy as np

import reviewer_v8_workflow as w
import reviewer_v8_import_experiment as e


def weighted_threshold(rows, probabilities, weights):
    """The workflow calibration objective, with bootstrap multiplicities.

    Counts use scores >= threshold. Ties and nextafter candidates match calibrate.
    Weights affect empirical rates, not the already-fitted model.
    """
    p = np.asarray(probabilities, dtype=float)
    weights = np.asarray(weights, dtype=float)
    if len(rows) != len(p) or len(p) != len(weights) or np.any(weights < 0):
        raise ValueError('Invalid bootstrap weights')
    unique = np.unique(p[weights > 0])
    thresholds = np.unique(np.concatenate((unique, np.nextafter(unique, np.inf), [1.])))
    thresholds = thresholds[(thresholds > 0) & (thresholds <= 1)]
    y = np.array([r['label'] for r in rows])
    order = np.argsort(p, kind='stable')
    positions = np.searchsorted(p[order], thresholds, side='left')
    def above(mask):
        values = weights[order] * mask[order]
        return values.sum() - np.concatenate(([0.], np.cumsum(values)))[positions]
    n0, n1 = weights[y == 0].sum(), weights[y == 1].sum()
    if not n0 or not n1:
        raise ValueError('Both classes required for threshold diagnostics')
    fp, tp = above(y == 0) / n0, above(y == 1) / n1
    worst = np.zeros(len(thresholds))
    for source in sorted({r['source'] for r in rows}):
        mask = np.array([r['source'] == source and r['label'] == 0 for r in rows])
        denominator = weights[mask].sum()
        if denominator >= 100:
            worst = np.maximum(worst, above(mask) / denominator)
    valid = np.flatnonzero((fp <= .01 + 1e-15) & (worst <= .01 + 1e-15))
    if not len(valid):
        raise ValueError('No valid bootstrap threshold')
    best = max(valid, key=lambda i: (tp[i], -worst[i], -fp[i], thresholds[i]))
    return float(thresholds[best])


def threshold_stability(cal_rows, cal_scores, heldout, heldout_scores, expected, repeats, seed):
    if weighted_threshold(cal_rows, cal_scores, np.ones(len(cal_rows))) != expected:
        raise ValueError('Fast threshold implementation differs from workflow calibration')
    rng = np.random.RandomState(seed)
    strata = defaultdict(list)
    for i, r in enumerate(cal_rows):
        strata[(r['source'], r['label'])].append(i)
    thresholds, infeasible = [], 0
    for _ in range(repeats):
        weights = np.zeros(len(cal_rows), dtype=int)
        for indices in strata.values():
            draw = rng.choice(indices, size=len(indices), replace=True)
            weights += np.bincount(draw, minlength=len(cal_rows))
        try:
            thresholds.append(weighted_threshold(cal_rows, cal_scores, weights))
        except ValueError as error:
            if str(error) != 'No valid bootstrap threshold':
                raise
            infeasible += 1
    if not thresholds:
        raise ValueError('No feasible calibration thresholds in bootstrap resamples')
    values = np.asarray(thresholds)
    quantiles = dict(zip(('min', 'p05', 'median', 'p95', 'max'),
                        map(float, np.quantile(values, [0, .05, .5, .95, 1]))))
    result = dict(repeats=repeats, feasible_repeats=len(thresholds), infeasible_repeats=infeasible,
                  seed=seed, calibrated_threshold=expected,
                  threshold_quantiles=quantiles,
                  threshold_standard_deviation=float(values.std()),
                  bootstrap_unit='Sample within source/class; model fixed, only calibration resampled',
                  limitation='Does not measure retraining, family duplication, or unseen-source uncertainty')
    if heldout:
        scores = np.asarray(heldout_scores)
        preds = scores[:, None] >= values[None, :]
        label = np.array([r['label'] for r in heldout])
        fps, fns = preds[label == 0].sum(axis=0), (~preds[label == 1]).sum(axis=0)
        result.update(heldout_fp_range=[int(fps.min()), int(fps.max())],
                      heldout_fn_range=[int(fns.min()), int(fns.max())],
                      threshold_sensitive_samples=[dict(sha256=r['sha256'], label=r['label'],
                          probability=float(scores[i]), malware_vote_fraction=float(preds[i].mean()))
                          for i, r in enumerate(heldout) if preds[i].any() and not preds[i].all()])
    return result


def error_neighbors(heldout, baseline_scores, import_scores, baseline_t, import_t,
                    cached, training_rows, names, count=5, route=.15):
    # Scale is fit only on the fold's training rows. Scores and the six added
    # import flags do not enter distance: structural similarity is separate.
    S = np.log1p(np.maximum(np.array([cached[r['sha256']]['structural_vector']
                                     for r in training_rows]), 0))
    med = np.median(S, axis=0)
    scale = np.quantile(S, .75, axis=0) - np.quantile(S, .25, axis=0)
    fallback = S.std(axis=0)
    scale = np.where(scale > 1e-9, scale, np.where(fallback > 1e-9, fallback, 1.))
    raw = np.array([cached[r['sha256']]['structural_vector'] for r in heldout])
    Z = (np.log1p(np.maximum(raw, 0)) - med) / scale
    base_pred = np.asarray(baseline_scores) >= baseline_t
    pred = np.asarray(import_scores) >= import_t
    labels = np.array([r['label'] for r in heldout])
    result = []
    for i, r in enumerate(heldout):
        if pred[i] == labels[i]:
            continue
        distances = np.mean(np.minimum(np.abs(Z - Z[i]), 10.), axis=1)
        neighbors = {}
        for label, key in ((labels[i], 'same_class_correct'), (1 - labels[i], 'opposite_class_correct')):
            eligible = [j for j in range(len(heldout)) if labels[j] == label and pred[j] == labels[j]]
            chosen = sorted(eligible, key=lambda j: (distances[j], heldout[j]['sha256']))[:count]
            neighbors[key] = [dict(sha256=heldout[j]['sha256'], distance=float(distances[j]),
                probability=float(import_scores[j]), label=heldout[j]['label'],
                import_features=dict(zip(e.IMPORT_FEATURES, e._import_values(cached[heldout[j]['sha256']]['attributes']))))
                for j in chosen]
            if key == 'same_class_correct' and chosen:
                differences = np.abs(Z[i] - np.median(Z[chosen], axis=0))
                neighbor_median = np.median(raw[chosen], axis=0)
                neighbors['largest_structural_differences'] = [dict(feature=names[k], value=float(raw[i,k]),
                    correct_neighbor_median=float(neighbor_median[k]), scaled_difference=float(differences[k]))
                    for k in np.argsort(-differences, kind='stable')[:10]]
        sample = cached[r['sha256']]
        result.append(dict(sha256=r['sha256'], source=r['source'], label=r['label'],
            reviewer_routed=bool(r['adapter_probability'] >= route),
            error_type='false_negative' if r['label'] else 'false_positive',
            newly_misclassified=bool(base_pred[i] == labels[i]),
            baseline_probability=float(baseline_scores[i]), import_probability=float(import_scores[i]),
            baseline_threshold=baseline_t, import_threshold=import_t,
            import_margin=float(import_scores[i] - import_t),
            upstream_scores={k:r[k] for k in w.SCORE_FEATURES}, pe_attributes=sample['attributes'],
            import_features=dict(zip(e.IMPORT_FEATURES, e._import_values(sample['attributes']))),
            comparisons=neighbors))
    return result


def diagnose(rows, cached, frozen, baseline, candidate, output, repeats=100):
    train, cal = w.preserved_split(rows)
    base_clf, base_t, _ = e.verify_baseline(rows, cached, frozen, baseline, train, cal)
    metadata = json.loads((candidate / 'metadata.json').read_text())
    payload = json.loads((candidate / 'model.json').read_text())
    manifest = json.loads((candidate / 'split_manifest.json').read_text())
    if (metadata.get('experiment') != 'boundary_reviewer_v8_fixed_import_features'
            or metadata.get('configuration') != w.CONFIG
            or manifest.get('training') != [r['sha256'] for r in train]
            or manifest.get('calibration') != [r['sha256'] for r in cal]):
        raise ValueError('Candidate experiment specification or split differs')
    augmented = e.augment_cache(cached)
    route = frozen['route_min']
    clf = w.fit(train, augmented, route)
    cp = w.predict(clf, cal, augmented, route)
    ct, cm, _ = w.calibrate(cal, cp)
    if e.export_imports(clf, frozen, ct) != payload or cm != metadata['calibration']:
        raise ValueError('Completed import candidate cannot be reproduced exactly')
    results = dict(development_only=True,
        warning='Descriptive neighbor comparisons and calibration sensitivity only. No production threshold selection; no new model is saved. Prior holdouts informed development, so fresh data remains necessary.',
        neighbor_method='Clipped L1 over log1p baseline structural features, scaled only on fold training rows. Correct peers come from the same held-out source, scored by the same refit. Labels select comparison groups, not distances. Similarity is not causal explanation or malware family attribution.',
        score_convention='Below route_min, probability zero is a policy placeholder; reviewer is not evaluated.',
        calibration_stability={
            'baseline':threshold_stability(cal, w.predict(base_clf, cal, cached, route), [], [], base_t, repeats, 2704),
            'import_candidate':threshold_stability(cal, cp, [], [], ct, repeats, 2704)},
        source_holdouts=[])
    all_errors = []
    for fold_index, source in enumerate(e.SOURCES):
        heldout = [r for r in rows if r['source'] == source]
        fit_rows, cal_rows = w.preserved_split([r for r in rows if r['source'] != source])
        reference = next(f for f in metadata['leave_one_source_out'] if f['source'] == source)
        fold = dict(source=source, models={})
        scores, thresholds = {}, {}
        for name, features in (('baseline', cached), ('import_candidate', augmented)):
            fc = w.fit(fit_rows, features, route)
            pc = w.predict(fc, cal_rows, features, route)
            ft, fm, _ = w.calibrate(cal_rows, pc)
            hp = w.predict(fc, heldout, features, route)
            ref = reference['models'][name]
            if ft != ref['threshold'] or fm != ref['calibration'] or w.metrics(heldout, hp >= ft) != ref['heldout']:
                raise ValueError(f'{source} {name} holdout no longer reproduces experiment')
            scores[name], thresholds[name] = hp, ft
            fold['models'][name] = threshold_stability(cal_rows, pc, heldout, hp, ft, repeats, 3704 + fold_index)
        errors = error_neighbors(heldout, scores['baseline'], scores['import_candidate'],
            thresholds['baseline'], thresholds['import_candidate'], cached, fit_rows,
            frozen['feature_names'][len(w.SCORE_FEATURES):], route=route)
        fold['import_errors'] = dict(count=len(errors), new_errors=sum(r['newly_misclassified'] for r in errors),
            feature_difference_frequency=dict(Counter(d['feature'] for r in errors
                for d in r['comparisons'].get('largest_structural_differences', []))))
        results['source_holdouts'].append(fold)
        all_errors.extend(errors)
        print(f'Diagnosed {source}: {len(errors)} candidate errors; calibration bootstraps complete', flush=True)
        w.dump(output / 'diagnostics.json', results)
        w.dump(output / 'neighbor-audit.json', dict(method=results['neighbor_method'], errors=all_errors))
    return results, all_errors


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reports-dir', type=Path, default=w.ROOT / 'validation-data')
    ap.add_argument('--baseline-output', type=Path, default=w.ROOT / 'validation-data/reviewer-v8-development')
    ap.add_argument('--candidate-output', type=Path, default=w.ROOT / 'validation-data/reviewer-v8-import-features-development')
    ap.add_argument('--v7-model', type=Path, default=w.ROOT / 'defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json')
    ap.add_argument('--output', type=Path, default=w.ROOT / 'validation-data/reviewer-v8-diagnostics')
    ap.add_argument('--bootstrap-repeats', type=int, default=100)
    args = ap.parse_args()
    try:
        if not 10 <= args.bootstrap_repeats <= 1000:
            raise ValueError('bootstrap-repeats must be between 10 and 1000')
        if args.output.resolve() in (args.baseline_output.resolve(), args.candidate_output.resolve()):
            raise ValueError('Diagnostic output must differ from model experiment directories')
        frozen = json.loads(args.v7_model.read_text())
        w.BoundaryReviewer(args.v7_model)
        sha = hashlib.sha256(args.v7_model.read_bytes()).hexdigest()
        for directory in (args.baseline_output, args.candidate_output):
            if json.loads((directory / 'inputs.json').read_text()).get('frozen_model_sha256') != sha:
                raise ValueError('Frozen v7 provenance differs from completed experiment')
        audit_rows, paths = w.load_audit(args.reports_dir)
        rows, old_paths = w.merge_training(args.reports_dir, audit_rows)
        paths.update(old_paths)
        cache = json.loads((args.baseline_output / 'feature-cache.json').read_text())
        cached = cache['samples']
        if cache['provenance']['feature_names'] != frozen['feature_names']:
            raise ValueError('Cached feature schema differs')
        if any(r['sha256'] not in cached for r in rows):
            raise ValueError('Feature cache incomplete; rerun import experiment first')
        args.output.mkdir(parents=True, exist_ok=True)
        w.dump(args.output / 'inputs.json', dict(frozen_model_sha256=sha,
            report_sha256={s:hashlib.sha256(Path(p).read_bytes()).hexdigest() for s,p in paths.items()},
            baseline_model_sha256=hashlib.sha256((args.baseline_output / 'model.json').read_bytes()).hexdigest(),
            candidate_model_sha256=hashlib.sha256((args.candidate_output / 'model.json').read_bytes()).hexdigest()))
        diagnose(rows, cached, frozen, args.baseline_output, args.candidate_output, args.output, args.bootstrap_repeats)
        print(f'Send diagnostics.json and neighbor-audit.json from {args.output}', flush=True)
    except (ValueError, OSError, ImportError, RuntimeError, KeyError) as error:
        ap.exit(2, f'V8 diagnostics stopped: {error}\n')


if __name__ == '__main__':
    main()
