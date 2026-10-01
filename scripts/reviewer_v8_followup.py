#!/usr/bin/env python3
"""Controlled threshold-interval and build-category v8 experiments.

Development only. No source-holdout scores select thresholds. No sample is run.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

import numpy as np

import reviewer_v8_workflow as w
import reviewer_v8_import_experiment as e
import reviewer_v8_diagnostics as d
from defender.models.boundary_reviewer import BUILD_FEATURES, _build_values


def midpoint_threshold(probabilities, upper, weights=None):
    scores = np.asarray(probabilities, dtype=float)
    if weights is not None:
        scores = scores[np.asarray(weights) > 0]
    below = scores[scores < upper]
    lower = float(below.max()) if len(below) else 0.
    threshold = max(float(np.nextafter(lower, np.inf)), lower + (upper - lower) / 2.)
    threshold = min(upper, threshold)
    if np.any((scores >= threshold) != (scores >= upper)):
        raise ValueError('Midpoint changed calibration predictions')
    return dict(threshold=float(threshold), lower_exclusive=lower, upper_inclusive=float(upper),
                width=float(upper - lower))


def policies(rows, probabilities):
    upper, metric, by_source = w.calibrate(rows, probabilities)
    band = midpoint_threshold(probabilities, upper)
    return dict(upper_endpoint=dict(threshold=upper, calibration=metric, calibration_by_source=by_source),
                interval_midpoint=dict(**band, calibration=metric, calibration_by_source=by_source))


def bootstrap_policies(cal, scores, heldout, hp, repeats, seed):
    rng = np.random.RandomState(seed)
    strata = defaultdict(list)
    for i, row in enumerate(cal):
        strata[(row['source'], row['label'])].append(i)
    upper, _, _ = w.calibrate(cal, scores)
    if d.weighted_threshold(cal, scores, np.ones(len(cal))) != upper:
        raise ValueError('Weighted objective differs from original calibration')
    values = {'upper_endpoint': [], 'interval_midpoint': []}
    failed = 0
    for _ in range(repeats):
        weights = np.zeros(len(cal), dtype=int)
        for group in strata.values():
            weights += np.bincount(rng.choice(group, len(group), replace=True), minlength=len(cal))
        try:
            t = d.weighted_threshold(cal, scores, weights)
        except ValueError as error:
            if str(error) != 'No valid bootstrap threshold':
                raise
            failed += 1
            continue
        values['upper_endpoint'].append(t)
        values['interval_midpoint'].append(midpoint_threshold(scores, t, weights)['threshold'])
    if not values['upper_endpoint']:
        raise ValueError('No feasible bootstrap calibration resamples')
    result = dict(repeats=repeats, feasible_repeats=repeats-failed, infeasible_repeats=failed, seed=seed,
        scope='Sample bootstrap within calibration source/class, fitted model fixed. Post-hoc heldout sensitivity; no threshold selection from heldout.')
    labels = np.array([r['label'] for r in heldout])
    for name, thresholds in values.items():
        result[name] = dict(threshold_quantiles=dict(zip(('min','p05','median','p95','max'),
            map(float, np.quantile(thresholds, [0,.05,.5,.95,1])))),
            standard_deviation=float(np.std(thresholds)))
        if heldout:
            pred = np.asarray(hp)[:,None] >= np.asarray(thresholds)[None,:]
            fp = pred[labels == 0].sum(axis=0); fn = (~pred[labels == 1]).sum(axis=0)
            result[name].update(heldout_fp_range=[int(fp.min()),int(fp.max())],
                               heldout_fn_range=[int(fn.min()),int(fn.max())])
    return result


def augment_build(import_cache):
    return {sha:dict(sample, structural_vector=sample['structural_vector'] + list(_build_values(sample['attributes'])))
            for sha,sample in import_cache.items()}


def category_coverage(rows, cached):
    groups = defaultdict(list)
    for row in rows:
        attrs = cached[row['sha256']]['attributes']
        build = _build_values(attrs)
        for name, included in (('kernel_driver_import', e._import_values(attrs)[-1] > 0),
                               ('linker2_with_symbols', build[3] > 0),
                               ('linker2_symbols_no_debug_tls', build[4] > 0)):
            if included:
                groups[name].append(row)
    return {name:dict(count=len(group), benign=sum(r['label']==0 for r in group),
                     malicious=sum(r['label']==1 for r in group),
                     source_label_counts=dict(Counter(f"{r['source']}:label_{r['label']}" for r in group)))
            for name, group in groups.items()}


def export_build(clf, frozen, threshold):
    spec = dict(frozen, feature_names=list(frozen['feature_names']) + list(e.IMPORT_FEATURES) + list(BUILD_FEATURES))
    payload = w.export(clf, spec, threshold)
    payload.update(format_version=9, build_features=list(BUILD_FEATURES), import_features=list(e.IMPORT_FEATURES))
    runtime = w.BoundaryReviewer.__new__(w.BoundaryReviewer)
    runtime._load(payload)
    return payload


def tree_trace(clf, features, names):
    x = np.asarray(features, dtype=np.float32)
    stages = []
    for i, estimator in enumerate(clf.estimators_[:,0]):
        t, node, path = estimator.tree_, 0, []
        while t.children_left[node] >= 0:
            index = int(t.feature[node]); value = float(x[index]); cut = float(t.threshold[node])
            left = value <= cut
            path.append(dict(feature=names[index], value=value, threshold=cut, branch='left' if left else 'right'))
            node = int(t.children_left[node] if left else t.children_right[node])
        contribution = float(clf.learning_rate * t.value[node,0,0])
        stages.append(dict(stage=i, raw_score_contribution=contribution, path=path))
    initial = float(clf._raw_predict_init(np.asarray([features]))[0,0])
    raw = initial + sum(s['raw_score_contribution'] for s in stages)
    probability = float(np.exp(-np.logaddexp(0.,-raw)))
    if abs(probability - float(clf.predict_proba(np.asarray([features]))[0,1])) > 1e-10:
        raise ValueError('Tree trace does not reproduce sklearn probability')
    return dict(initial_raw_score=initial, total_raw_score=raw, probability=probability,
        positive_stage_count=sum(s['raw_score_contribution'] > 0 for s in stages),
        largest_malware_contributions=sorted([s for s in stages if s['raw_score_contribution'] > 0],
            key=lambda s:-s['raw_score_contribution'])[:8],
        largest_benign_contributions=sorted([s for s in stages if s['raw_score_contribution'] < 0],
            key=lambda s:s['raw_score_contribution'])[:8])


def evaluate(rows, cached, frozen, baseline, candidate, output, repeats=100):
    train, cal = w.preserved_split(rows)
    base_clf, _, _ = e.verify_baseline(rows, cached, frozen, baseline, train, cal)
    original = json.loads((candidate/'metadata.json').read_text())
    original_payload = json.loads((candidate/'model.json').read_text())
    manifest = json.loads((candidate/'split_manifest.json').read_text())
    if (original.get('experiment') != 'boundary_reviewer_v8_fixed_import_features'
            or original.get('configuration') != w.CONFIG
            or manifest.get('training') != [r['sha256'] for r in train]
            or manifest.get('calibration') != [r['sha256'] for r in cal]):
        raise ValueError('Import experiment specification or split differs')
    import_cache = e.augment_cache(cached); build_cache = augment_build(import_cache)
    route, original_t = frozen['route_min'], frozen['reviewer_threshold']
    import_clf = w.fit(train, import_cache, route)
    ip = w.predict(import_clf, cal, import_cache, route)
    it, im, _ = w.calibrate(cal, ip)
    if e.export_imports(import_clf, frozen, it) != original_payload or im != original['calibration']:
        raise ValueError('Completed import candidate no longer reproduces exactly')
    build_clf = w.fit(train, build_cache, route)
    caches = dict(baseline=cached, imports=import_cache, build_categories=build_cache)
    clfs = dict(baseline=base_clf, imports=import_clf, build_categories=build_clf)
    exporters = dict(baseline=w.export, imports=e.export_imports, build_categories=export_build)
    summary = dict(experiment='v8_threshold_intervals_and_build_categories', development_only=True, completed=False,
        warning='Hypotheses informed by prior errors/holdouts. All comparisons are development diagnostics; fresh data required. Build indicators are not a benign bypass or proven compiler-family labels.',
        configuration=w.CONFIG, seed=704, added_build_features=list(BUILD_FEATURES),
        feature_names={name:list(frozen['feature_names']) + (list(e.IMPORT_FEATURES) if name!='baseline' else [])
                       + (list(BUILD_FEATURES) if name=='build_categories' else []) for name in caches},
        training_category_coverage=category_coverage(train,cached),
        calibration_category_coverage=category_coverage(cal,cached),
        source_counts=dict(Counter(r['source'] for r in rows)),
        route_min=route, original_threshold=original_t,
        threshold_rule='Preserve selected calibration predictions/FPR caps; choose midpoint of (largest excluded score, original upper endpoint]. Objective unchanged; only location inside identical-prediction interval changes.',
        calibration={}, leave_one_source_out=[])
    for name in caches:
        cp = w.predict(clfs[name], cal, caches[name], route)
        ps = policies(cal,cp)
        summary['calibration'][name] = dict(policies=ps,
            at_original_threshold=w.metrics(cal,cp >= original_t),
            bootstrap=bootstrap_policies(cal,cp,[],[],repeats,4704))
        X = np.array([w.vector(r,caches[name][r['sha256']]) for r in rows])
        for rule, info in ps.items():
            if name != 'build_categories' and rule == 'upper_endpoint':
                continue  # These models already exist in their original folders.
            payload = exporters[name](clfs[name],frozen,info['threshold'])
            error = float(np.max(np.abs(clfs[name].predict_proba(X)[:,1]-w.model_probabilities(payload,X))))
            if error > 1e-10:
                raise ValueError(f'{name} export parity failed: {error}')
            summary['calibration'][name].setdefault('export_parity',{})[rule] = error
            w.dump(output/(name+'-'+rule+'-model.json'),payload)
    traces, score_records = [], []
    for index, source in enumerate(e.SOURCES):
        heldout = [r for r in rows if r['source'] == source]
        fit_rows, cal_rows = w.preserved_split([r for r in rows if r['source'] != source])
        reference = next(f for f in original['leave_one_source_out'] if f['source'] == source)
        fold = dict(source=source, models={}, training_category_coverage=category_coverage(fit_rows,cached),
                    calibration_category_coverage=category_coverage(cal_rows,cached)); fold_clfs={}; scores={}; settings={}
        trace_names = dict(imports=list(frozen['feature_names']) + list(e.IMPORT_FEATURES),
                           build_categories=list(frozen['feature_names']) + list(e.IMPORT_FEATURES) + list(BUILD_FEATURES))
        for name, features in caches.items():
            fc = w.fit(fit_rows,features,route)
            cp = w.predict(fc,cal_rows,features,route); hp=w.predict(fc,heldout,features,route)
            ps = policies(cal_rows,cp)
            if name != 'build_categories':
                ref=reference['models']['baseline' if name=='baseline' else 'import_candidate']
                info=ps['upper_endpoint']
                if (info['threshold'] != ref['threshold'] or info['calibration'] != ref['calibration']
                        or w.metrics(heldout,hp >= info['threshold']) != ref['heldout']):
                    raise ValueError(f'{source} {name} refit no longer matches previous experiment')
            for info in ps.values():
                info['heldout']=w.metrics(heldout,hp >= info['threshold'])
            fold['models'][name]=dict(policies=ps,
                at_original_threshold=w.metrics(heldout,hp >= original_t),
                bootstrap=bootstrap_policies(cal_rows,cp,heldout,hp,repeats,5704+index))
            fold_clfs[name],scores[name],settings[name]=fc,hp,ps
        # Trace errors from the reference import model, comparing the same
        # sample and its nearest correct same-class peer in both fitted models.
        errors=d.error_neighbors(heldout,scores['baseline'],scores['imports'],
            settings['baseline']['upper_endpoint']['threshold'],settings['imports']['upper_endpoint']['threshold'],
            cached,fit_rows,frozen['feature_names'][len(w.SCORE_FEATURES):],route=route)
        heldout_by_sha={r['sha256']:r for r in heldout}
        for error in errors:
            peers=error['comparisons']['same_class_correct']
            samples=[('error',heldout_by_sha[error['sha256']])]
            if peers:
                samples.append(('nearest_correct_same_class',heldout_by_sha[peers[0]['sha256']]))
            entry=dict(source=source,sha256=error['sha256'],label=error['label'],
                       newly_misclassified=error['newly_misclassified'],samples=[])
            for role,row in samples:
                sample=dict(role=role,sha256=row['sha256'],label=row['label'],models={})
                for name in trace_names:
                    sample['models'][name]=tree_trace(fold_clfs[name],w.vector(row,caches[name][row['sha256']]),trace_names[name])
                    sample['models'][name]['reviewer_routed']=row['adapter_probability'] >= route
                entry['samples'].append(sample)
            traces.append(entry)
        for i,row in enumerate(heldout):
            record=dict(sha256=row['sha256'],source=source,label=row['label'],
                        reviewer_routed=row['adapter_probability'] >= route)
            for name in caches:
                record[name+'_probability']=float(scores[name][i]) if record['reviewer_routed'] else None
                for rule, info in settings[name].items():
                    record[name+'_'+rule+'_prediction']=int(scores[name][i]>=info['threshold'])
                    record[name+'_'+rule+'_threshold']=info['threshold']
            score_records.append(record)
        summary['leave_one_source_out'].append(fold)
        print(f'Completed {source}: '+json.dumps({name:{rule:info["heldout"] for rule,info in f['policies'].items()}
                                               for name,f in fold['models'].items()}),flush=True)
        w.dump(output/'metadata.json',summary)
        w.dump(output/'tree-path-audit.json',dict(warning='Stage contributions are additive raw-score terms, not causal feature attributions. Paths use float32 inputs; top eight positive and negative stages shown. Below-route traces are hypothetical and not policy scores.',errors=traces))
    w.dump(output/'split_manifest.json',dict(training=[r['sha256'] for r in train],
        calibration=[r['sha256'] for r in cal],baseline_split_preserved=True))
    import csv
    with (output/'source-heldout-scores.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(score_records[0]));writer.writeheader();writer.writerows(score_records)
    summary['completed']=True
    w.dump(output/'metadata.json',summary)
    return summary


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reports-dir',type=Path,default=w.ROOT/'validation-data')
    ap.add_argument('--baseline-output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-development')
    ap.add_argument('--candidate-output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-import-features-development')
    ap.add_argument('--v7-model',type=Path,default=w.ROOT/'defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json')
    ap.add_argument('--output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-followup-development')
    ap.add_argument('--bootstrap-repeats',type=int,default=100)
    args=ap.parse_args()
    try:
        if not 10<=args.bootstrap_repeats<=1000:
            raise ValueError('bootstrap-repeats must be between 10 and 1000')
        if args.output.resolve() in (args.baseline_output.resolve(),args.candidate_output.resolve()):
            raise ValueError('Output must differ from previous experiment directories')
        frozen=json.loads(args.v7_model.read_text());reviewer=w.BoundaryReviewer(args.v7_model)
        if reviewer.format_version!=6 or abs(reviewer.route_min-.15)>1e-12:
            raise ValueError('Expected original frozen v7 format 6 with route_min .15')
        sha=hashlib.sha256(args.v7_model.read_bytes()).hexdigest()
        for directory in (args.baseline_output,args.candidate_output):
            if json.loads((directory/'inputs.json').read_text()).get('frozen_model_sha256')!=sha:
                raise ValueError('Frozen v7 provenance differs')
        audit_rows,paths=w.load_audit(args.reports_dir)
        rows,old_paths=w.merge_training(args.reports_dir,audit_rows);paths.update(old_paths)
        cache=json.loads((args.baseline_output/'feature-cache.json').read_text());cached=cache['samples']
        if cache['provenance']['feature_names']!=frozen['feature_names'] or any(r['sha256'] not in cached for r in rows):
            raise ValueError('Feature cache incomplete or schema differs')
        args.output.mkdir(parents=True,exist_ok=True)
        w.dump(args.output/'inputs.json',dict(frozen_model_sha256=sha,
            report_sha256={s:hashlib.sha256(Path(p).read_bytes()).hexdigest() for s,p in paths.items()},
            baseline_model_sha256=hashlib.sha256((args.baseline_output/'model.json').read_bytes()).hexdigest(),
            import_model_sha256=hashlib.sha256((args.candidate_output/'model.json').read_bytes()).hexdigest()))
        evaluate(rows,cached,frozen,args.baseline_output,args.candidate_output,args.output,args.bootstrap_repeats)
        print(f'Send metadata.json and tree-path-audit.json from {args.output}',flush=True)
    except (ValueError,OSError,ImportError,RuntimeError,KeyError) as error:
        ap.exit(2,f'V8 follow-up stopped: {error}\n')


if __name__=='__main__':
    main()
