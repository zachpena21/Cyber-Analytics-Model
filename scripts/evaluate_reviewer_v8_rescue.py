#!/usr/bin/env python3
"""Evaluate one fixed agreement rescue rule; no fitting, sweeps or deployment."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

from prepare_reviewer_v8_whitebox import candidate_from_bytes, metrics
from score_reviewer_v8_whitebox import model_score

POLICY = dict(name='v8-t060-agreement-rescue-research', reviewer_threshold=.60,
              route_min=.15, adapter_min=.99, base_benign_max=.20,
              reviewer_min=.30, require_adjusted_base_trigger=True,
              exclude_verified_signatures=True)
CACHE_SHA = 'a264e6da9633346eddda084814242608d513ea343bd294c64cb67b5b12f57471'
IMPORTS = ('ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'wdfldr.sys', 'ks.sys')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def number(value):
    if value in (None, '', False, 'False', 'false'):
        return 0.
    if value in (True, 'True', 'true'):
        return 1.
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('Non-finite numeric input')
    return value


def gates(row):
    adapter, benign = number(row['adapter_probability']), number(row['benign_probability'])
    if not 0 <= adapter <= 1 or not 0 <= benign <= 1:
        raise ValueError('Upstream probability out of range')
    return (adapter >= POLICY['adapter_min'] and benign <= POLICY['base_benign_max']
            and number(row['base_trigger_adjusted']) == 1
            and number(row['signature_verified']) == 0)


def predict(row, score):
    score = number(score)
    if not 0 <= score <= 1:
        raise ValueError('Reviewer score out of range')
    routed = number(row['adapter_probability']) >= POLICY['route_min']
    baseline = int(score >= POLICY['reviewer_threshold']) if routed else int(number(row['adapter_probability']) >= .7)
    rescued = bool(baseline == 0 and routed and score >= POLICY['reviewer_min'] and gates(row))
    return baseline, int(baseline == 1 or rescued), rescued


def summarize(rows):
    if not rows or len({r['sha256'] for r in rows}) != len(rows):
        raise ValueError('Empty or duplicated full-score cohort')
    before, after, changes = [], [], []
    for row in rows:
        if row['label'] not in (0, 1):
            raise ValueError('Unexpected class label')
        b, a, rescue = predict(row, row['score'])
        if row.get('expected_baseline', b) != b:
            raise ValueError('Saved baseline does not match frozen t060 cascade')
        before.append(b); after.append(a)
        if rescue:
            changes.append(dict(sha256=row['sha256'], label=row['label'], source=row.get('source'),
                                reviewer_probability=row['score'],
                                adapter_probability=number(row['adapter_probability']),
                                benign_probability=number(row['benign_probability'])))
    new_fp = sum(r['label'] == 0 for r in changes)
    return dict(sample_count=len(rows), baseline=metrics(rows, before), candidate=metrics(rows, after),
                rescued_malware=sum(r['label'] == 1 for r in changes), new_false_positives=new_fp,
                malware_regressions=0, no_new_false_positives=new_fp == 0, changes=changes)


def load_ta(path, model):
    report = json.loads(path.read_text())
    if not report.get('complete') or report.get('errors') != 0 or report.get('successful') != 100:
        raise ValueError('TA runtime report is incomplete')
    info = report['service_model']
    expected_sha = hashlib.sha256((json.dumps(model, indent=2)+'\n').encode()).hexdigest()
    if report.get('model_sha256') != expected_sha:
        raise ValueError('TA report model hash differs from the frozen t060 artifact')
    if info['reviewer_threshold'] != .6 or info['reviewer_route_min'] != .15:
        raise ValueError('TA report is not the tested t060 candidate')
    rows = []
    for r in report['rows']:
        if (not isinstance(r['is_malware'], bool) or r['reviewer_feature_names'] != model['feature_names']
                or len(r['reviewer_feature_vector']) != len(model['feature_names'])
                or r['sample_sha256'] != r['sha256']):
            raise ValueError('TA identity/schema mismatch')
        score = model_score(model, r['reviewer_feature_vector'])
        if r['reviewer_routed'] and abs(score-r['reviewer_probability']) > 1e-9:
            raise ValueError('TA tree-score parity differs')
        rows.append(dict(r, label=int(r['is_malware']), score=score,
                         source=r.get('family') or r.get('source_name'), expected_baseline=r['result']))
    if len(rows) != 100 or sum(r['label'] for r in rows) != 50:
        raise ValueError('TA class counts differ')
    return rows


def load_cache(path, model):
    if path.is_dir():
        path = path/'development-input-cache.json'
    if digest(path) != CACHE_SHA:
        raise ValueError('Cache hash differs from the cache bound to final v8 export')
    cache = json.loads(path.read_text())
    if cache.get('complete') is not True or cache['feature_names'] != model['feature_names'][:-6]:
        raise ValueError('Development cache schema/completion mismatch')
    rows = []
    for sha, entry in sorted(cache['samples'].items()):
        record = entry['record']
        if record['sha256'] != sha:
            raise ValueError('Cache sample identity differs')
        libraries = {t.replace('\\', '/').rsplit('/', 1)[-1].casefold() for t in entry['libraries'].split()}
        flags = [float(name in libraries) for name in IMPORTS]
        vector = entry['feature_vector'] + flags + [sum(flags)]
        if len(vector) != len(model['feature_names']) or any(not math.isfinite(float(v)) for v in vector):
            raise ValueError('Cache feature vector invalid')
        for name, value in zip(model['feature_names'][:6], vector[:6]):
            if abs(number(record[name])-number(value)) > 1e-9:
                raise ValueError('Cache upstream record/vector differs: '+name)
        rows.append(dict(record, score=model_score(model, vector)))
        if len(rows) % 1000 == 0:
            print('Scored cached vectors:', len(rows), flush=True)
    if len(rows) != 13245 or sum(r['label'] == 0 for r in rows) != 12764:
        raise ValueError('Expected final export pool: 12,764 benign and 481 malware')
    return path, rows


def csv_reports(paths):
    # Keep every observation when a SHA was scored in more than one runtime.
    # A benign observation entering the upstream gate blocks the safety claim,
    # even if a later observation for that SHA does not enter it.
    observations, unique, conflicts, possible = 0, {}, [], []
    proofs, matched = [], []
    for path in paths:
        with path.open(encoding='utf-8-sig', newline='') as stream:
            source = list(csv.DictReader(stream))
        required = {'sha256', 'label', 'adapter_probability', 'benign_probability',
                    'base_trigger_adjusted', 'signature_verified'}
        if not source or not required <= set(source[0]):
            raise ValueError('CSV lacks required upstream fields: '+str(path))
        for r in source:
            label = int(r['label'])
            if label not in (0, 1):
                raise ValueError('Unexpected CSV label')
            if r['sha256'] in unique and unique[r['sha256']] != label:
                conflicts.append(r['sha256'])
            unique[r['sha256']] = label; observations += 1
            if label == 0 and gates(r):
                possible.append(dict(sha256=r['sha256'], source=r.get('source'), report=path.name))
        proofs.append(dict(name=path.name, sha256=digest(path), rows=len(source)))
        if 'structural_primary_score' in source[0]:
            matched.append(dict(report=path.name, sha256=digest(path), **summarize([
                dict(r, label=int(r['label']), score=float(r['structural_primary_score'])) for r in source])))
    if conflicts:
        raise ValueError('Conflicting historical labels')
    return dict(unique_samples=len(unique), unique_benign=sum(y == 0 for y in unique.values()),
                unique_malware=sum(y == 1 for y in unique.values()), observations=observations,
                possible_new_benign_flags=possible, no_benign_enters_upstream_gate=not possible,
                reports=proofs, matched_final_model_cohorts=matched,
                scope='Conservative upstream-gate screen; only explicitly matched structural-primary cohorts have accuracy metrics.')


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ta-report', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--csv', type=Path, action='append', default=[])
    parser.add_argument('--local-preview', action='store_true', help='Explicitly allow missing full cache; never qualifies a candidate')
    parser.add_argument('--output', type=Path, default=root/'validation-data/phorpiex-rescue-experiment.json')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output exists; choose a new --output path to preserve prior evidence')
    model_path = root/'defender/defender/models/boundary_reviewer_v8_final/model.json'
    _, model = candidate_from_bytes(model_path.read_bytes())
    result = dict(complete=False, training=False, deployment_changed=False, policy=POLICY,
                  scope='Manually specified rule informed by disclosed TA miss. Development evidence only; no global FPR guarantee.',
                  ta_tuning_set=None, full_development_pool=None, historical_upstream_screen=None,
                  no_new_false_positives_on_full_pool=None, ready_for_runtime_test=False)
    if args.ta_report:
        result['ta_report_sha256'] = digest(args.ta_report)
        result['ta_tuning_set'] = summarize(load_ta(args.ta_report, model))
    if args.csv:
        result['historical_upstream_screen'] = csv_reports(args.csv)
    cache = args.cache
    if cache is None:
        matches = sorted((root/'validation-data').glob('reviewer-v8-rich-feature-cache-*/development-input-cache.json'))
        cache = next((p for p in matches if digest(p) == CACHE_SHA), None)
    if cache is not None:
        path, rows = load_cache(cache, model)
        result['cache_sha256'] = digest(path)
        result['full_development_pool'] = summarize(rows)
        result['no_new_false_positives_on_full_pool'] = result['full_development_pool']['no_new_false_positives']
        result['ready_for_runtime_test'] = result['no_new_false_positives_on_full_pool']
    elif not args.local_preview:
        parser.error('Final v8 development cache unavailable. Pass --cache with its directory; no rule has been deployed.')
    result['complete'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False)+'\n')
    for name in ('ta_tuning_set', 'full_development_pool', 'historical_upstream_screen'):
        if result[name]:
            summary = {k:v for k,v in result[name].items() if k not in ('changes', 'reports')}
            print(name, json.dumps(summary), flush=True)
    print('Report:', args.output)
    if result['full_development_pool'] and not result['no_new_false_positives_on_full_pool']:
        raise SystemExit('REJECTED: rescue rule introduces benign regressions. Passing t060 remains unchanged.')


if __name__ == '__main__':
    main()
