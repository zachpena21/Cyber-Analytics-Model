#!/usr/bin/env python3
"""Prepare the fixed 0.60 whitebox candidate and replay saved scores. No fits."""
import argparse
import copy
import csv
import hashlib
import json
import math
from pathlib import Path

from score_reviewer_v8_whitebox import model_score

BASELINE_SHA = '6dbe19e2f0962b4797ee5f58e17a37511b16dae94385253394e8f1add1df78be'
THRESHOLD = 0.60
BASELINE_THRESHOLD = 0.6882517225516912


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def candidate_from_bytes(raw):
    raw = raw.replace(b'\r\n', b'\n')
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA:
        raise ValueError('Source is not the frozen submitted v8 model')
    baseline = json.loads(raw)
    if baseline['route_min'] != .15 or baseline['reviewer_threshold'] != BASELINE_THRESHOLD:
        raise ValueError('Frozen policy differs')
    candidate = copy.deepcopy(baseline)
    candidate['reviewer_threshold'] = THRESHOLD
    return baseline, candidate


def metrics(rows, predictions):
    benign = sum(r['label'] == 0 for r in rows)
    malware = sum(r['label'] == 1 for r in rows)
    fp = sum(r['label'] == 0 and p == 1 for r, p in zip(rows, predictions))
    tp = sum(r['label'] == 1 and p == 1 for r, p in zip(rows, predictions))
    return dict(samples=len(rows), benign=benign, malware=malware, false_positives=fp,
                true_positives=tp, false_negatives=malware-tp,
                false_positive_rate=fp/benign if benign else None,
                detection_rate=tp/malware if malware else None,
                accuracy=(tp+benign-fp)/len(rows))


def decision(row, threshold):
    if not math.isfinite(row['score']) or not 0 <= row['score'] <= 1:
        raise ValueError('Invalid saved reviewer score')
    if not math.isfinite(row['adapter']) or not 0 <= row['adapter'] <= 1:
        raise ValueError('Invalid saved adapter score')
    return int(row['score'] >= threshold) if row['adapter'] >= .15 else int(row['adapter'] >= .7)


def compare(rows):
    if not rows or len({r['sha256'] for r in rows}) != len(rows):
        raise ValueError('Empty or duplicated cohort')
    before = [decision(r, BASELINE_THRESHOLD) for r in rows]
    after = [decision(r, THRESHOLD) for r in rows]
    if any(r['baseline_result'] != p for r, p in zip(rows, before)):
        raise ValueError('Recorded baseline decisions do not reproduce the frozen policy')
    changed = [dict(sha256=r['sha256'], label=r['label'], source=r.get('source'),
                    reviewer_probability=r['score'], before=b, after=a)
               for r, b, a in zip(rows, before, after) if a != b]
    return dict(baseline=metrics(rows, before), candidate=metrics(rows, after),
                changed=changed, score_or_weight_changes=0)


def ta_rows(report, baseline):
    if (report.get('complete') is not True or report.get('errors') != 0
            or report.get('successful') != 100 or report.get('sample_count') != 100
            or report.get('model_sha256') != BASELINE_SHA):
        raise ValueError('Expected a complete 100-row frozen-v8 baseline report')
    rows = []
    for r in report['rows']:
        if 'error' in r or not isinstance(r['is_malware'], bool):
            raise ValueError('Invalid TA row')
        if r['sample_sha256'] != r['sha256'] or r['reviewer_feature_names'] != baseline['feature_names']:
            raise ValueError('TA hash/schema mismatch')
        if len(r['reviewer_feature_vector']) != len(baseline['feature_names']):
            raise ValueError('TA vector length mismatch')
        score = model_score(baseline, r['reviewer_feature_vector'])
        routed = r['adapter_probability'] >= .15
        if routed != r['reviewer_routed']:
            raise ValueError('TA route mismatch')
        if routed and abs(score-r['reviewer_probability']) > 1e-9:
            raise ValueError('Saved TA score does not match submitted weights')
        rows.append(dict(sha256=r['sha256'], label=int(r['is_malware']),
                         adapter=r['adapter_probability'], score=score,
                         source=r.get('family') or r.get('source_name'), baseline_result=r['result']))
    if len(rows) != 100 or sum(r['label'] for r in rows) != 50:
        raise ValueError('Expected 50 benign and 50 malware rows')
    return rows


def regression_rows(path):
    # These are scores of the same fixed structural primary, not OOF scores
    # or the expanded/ensemble reviewers from older experiments.
    with path.open(newline='', encoding='utf-8-sig') as stream:
        source = list(csv.DictReader(stream))
    rows = []
    for r in source:
        label = int(r['label'])
        if label not in (0, 1) or float(r['adapter_threshold']) != .7:
            raise ValueError('Unexpected historical label/adapter policy')
        rows.append(dict(sha256=r['sha256'], label=label, source=r['source'],
                         adapter=float(r['adapter_probability']), score=float(r['structural_primary_score']),
                         baseline_result=int(r['structural_primary_prediction'])))
    return rows


def run(args):
    baseline, candidate = candidate_from_bytes(args.model.read_bytes())
    output = args.output
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output is not empty; choose a new directory')
    ta = ta_rows(json.loads(args.baseline_report.read_text()), baseline)
    result = dict(complete=True, role='whitebox_threshold_candidate', training=False,
                  threshold_tuning=True, threshold=THRESHOLD, route_min=.15,
                  source_model_sha256=BASELINE_SHA, runtime_verified=False,
                  scope='TA set informed threshold selection; all replay metrics are development/tuning evidence.',
                  input_sha256={'baseline_report': digest(args.baseline_report)},
                  ta_tuning_set=compare(ta), historical_cohorts=[])
    for path in args.regression_csv:
        rows = regression_rows(path)
        overlap = len({r['sha256'] for r in rows} & {r['sha256'] for r in ta})
        result['historical_cohorts'].append(dict(file=path.name, sha256=digest(path),
                                               ta_overlap=overlap, **compare(rows)))
    output.mkdir(parents=True, exist_ok=True)
    def save(name, value):
        (output/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    save('model.json', candidate)
    result['candidate_model_sha256'] = digest(output/'model.json')
    save('metadata.json', dict(name='v8 whitebox threshold 0.60 candidate',
         source_model_sha256=BASELINE_SHA, runtime_model_sha256=result['candidate_model_sha256'],
         reviewer_threshold=THRESHOLD, route_min=.15, refit=False, threshold_tuning=True,
         changed_model_fields=['reviewer_threshold'], deployment_changed=False,
         note='Research candidate; preserve submitted v8 and its ZIP. Run Docker verification before packaging.'))
    save('whitebox-candidate-comparison.json', result)
    print(json.dumps(result, indent=2))


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, default=root/'defender/defender/models/boundary_reviewer_v8_final/model.json')
    parser.add_argument('--baseline-report', type=Path, required=True)
    parser.add_argument('--regression-csv', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())


if __name__ == '__main__':
    main()
