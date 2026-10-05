#!/usr/bin/env python3
"""Collect runtime PE features for a completed structural evaluation; no fitting."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unique_records(records):
    if not records:
        raise ValueError('Empty score/sample records')
    result = {}
    for row in records:
        sha = row['sha256']
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
            raise ValueError('Invalid SHA')
        if sha in result:
            raise ValueError('Duplicate SHA: ' + sha)
        if type(row['label']) is not int or row['label'] not in (0, 1):
            raise ValueError('Invalid label')
        result[sha] = row
    return result


def verify_row(saved, current):
    if set(saved) != set(current):
        raise ValueError('Score record schema changed')
    maximum = 0.
    for key, expected in saved.items():
        actual = current[key]
        if type(expected) is float:
            if not isinstance(actual, (int, float)) or not math.isfinite(expected) or not math.isfinite(actual):
                raise ValueError('Invalid numeric field: ' + key)
            error = abs(expected - actual)
            maximum = max(maximum, error)
            if error > 1e-9:
                raise ValueError('Recollected score/component changed: ' + key)
        elif actual != expected:
            raise ValueError('Recollected identity/decision changed: ' + key)
    return maximum


def cohort(row):
    primary = row['structural_primary_prediction']
    if row['label'] == 0:
        return 'benign_false_positive' if primary else 'benign_correct'
    if primary:
        return 'malware_detected'
    if not row['structural_primary_routed']:
        return 'malware_gate_miss'
    old = row['v7_prediction']
    expanded = row['v8_import_upper_prediction']
    if old and expanded:
        return 'malware_miss_both_references_detect'
    if old:
        return 'malware_miss_v7_only_detects'
    if expanded:
        return 'malware_miss_expanded_only_detects'
    return 'malware_miss_all_references'


def find_evaluation(root, bundle, sources):
    freeze_sha = digest(bundle / 'freeze-manifest.json')
    sources_sha = digest(sources)
    matches = []
    for path in root.glob('reviewer-v8-structural-evaluation-*'):
        marker = path / 'evaluation-manifest.json'
        summary = path / 'comparison-summary.json'
        if not marker.is_file() or not summary.is_file():
            continue
        record = json.loads(marker.read_text())
        completed = json.loads(summary.read_text())
        if (record.get('complete') is True and completed.get('complete') is True
                and record.get('freeze_manifest_sha256') == freeze_sha
                and record.get('sources_sha256') == sources_sha):
            matches.append(path)
    if not matches:
        raise ValueError('No completed evaluation matching bundle and sources; pass --evaluation')
    return max(matches, key=lambda p: (p.joinpath('comparison-summary.json').stat().st_mtime_ns, str(p)))


def analyze(v, records, features, schema):
    import numpy as np
    keys = sorted(records)
    X = np.asarray([features[k]['vector'] for k in keys], dtype=float)
    groups = {}
    for k in keys:
        # Exact model-input equality only; these are not verified malware families.
        structural = np.asarray(features[k]['vector'][6:], dtype=np.float32).tolist()
        groups[k] = hashlib.sha256(json.dumps(structural, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    assignments = {k: cohort(records[k]) for k in keys}
    result = dict(complete=True, role='post_evaluation_descriptive_feature_diagnostics',
                  threshold_tuning=False, sample_count=len(keys), cohorts={},
                  interpretation='Profiles describe associations, not causal attribution. Exact input groups are not malware families. No thresholds, routes or weights are changed. If used for tuning, this batch becomes development data.')
    for name in sorted(set(assignments.values())):
        ids = [i for i, k in enumerate(keys) if assignments[k] == name]
        selected = [keys[i] for i in ids]
        label = records[selected[0]]['label']
        reference_name = 'malware_detected' if label else 'benign_correct'
        reference = [i for i, k in enumerate(keys) if assignments[k] == reference_name]
        detail = dict(count=len(ids), exact_input_groups=len({groups[k] for k in selected}),
                      sha256=selected, by_source=dict(Counter(records[k]['source'] for k in selected)),
                      reference_cohort=reference_name, reference_count=len(reference),
                      routed=sum(records[k]['structural_primary_routed'] for k in selected),
                      scores={field: v.d.distribution([records[k][field] for k in selected])
                              for field in ('adapter_probability', 'benign_probability', 'structural_primary_score',
                                            'v7_score', 'v8_import_upper_score', 'bounded_logit_correction')})
        if name not in ('benign_correct', 'malware_detected'):
            profile = v.q.feature_profiles(X, schema, ids, reference)
            detail['feature_profiles'] = profile['features']
            detail['largest_standardized_median_shifts'] = profile['largest_standardized_median_shifts']
        result['cohorts'][name] = detail
    grouped = {}
    for k in keys:
        grouped.setdefault(groups[k], []).append(k)
    result['repeated_exact_inputs_containing_errors'] = [
        dict(group=group, samples=members, labels=dict(Counter(str(records[k]['label']) for k in members)),
             cohorts=dict(Counter(assignments[k] for k in members)))
        for group, members in sorted(grouped.items())
        if len(members) > 1 and any(records[k]['label'] != records[k]['structural_primary_prediction'] for k in members)]
    errors = [dict(**records[k], cohort=assignments[k], exact_input_group=groups[k],
                   features=dict(zip(schema, features[k]['vector'])), ordinary_import_libraries=features[k]['libraries'])
              for k in keys if records[k]['label'] != records[k]['structural_primary_prediction']]
    return result, errors


def run(args):
    import numpy as np
    import pyzipper
    import requests
    import reviewer_v8_structural_validation as v
    f, w = v.f, v.w
    root = w.ROOT / 'validation-data'
    args.evaluation = args.evaluation or find_evaluation(root, args.bundle, args.sources)
    args.output = args.output or root / ('reviewer-v8-structural-feature-diagnostics-' +
                                        datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    manifest, structural, bounded, legacy, excluded = v.load_bundle(args.bundle)
    previous = f.read(args.evaluation / 'evaluation-manifest.json')
    summary = f.read(args.evaluation / 'comparison-summary.json')
    if (previous.get('complete') is not True or summary.get('complete') is not True
            or previous.get('threshold_tuning') is not False
            or summary.get('threshold_tuning') is not False
            or summary.get('primary') != v.PRIMARY):
        raise ValueError('Need a completed frozen structural evaluation')
    if (previous['freeze_manifest_sha256'] != digest(args.bundle / 'freeze-manifest.json')
            or previous['sources_sha256'] != digest(args.sources)):
        raise ValueError('Evaluation belongs to a different freeze or acquisition')
    paths = [args.evaluation / name for name in ('evaluation-manifest.json', 'comparison-summary.json',
             'comparison-scores.json', 'run-inputs.json')] + [args.sources, args.bundle / 'freeze-manifest.json']
    hashes = {str(path): digest(path) for path in paths}
    saved = unique_records(f.read(args.evaluation / 'comparison-scores.json'))
    original_samples = unique_records(previous['samples'])
    if set(saved) != set(original_samples) or len(saved) != summary['sample_count']:
        raise ValueError('Completed evaluation coverage differs')
    for k in saved:
        if saved[k]['label'] != original_samples[k]['label'] or saved[k]['source'] != original_samples[k]['source_id']:
            raise ValueError('Completed sample provenance differs')
    for name, report in summary['models'].items():
        if w.metrics(list(saved.values()), [r[name + '_prediction'] for r in saved.values()]) != report['overall']:
            raise ValueError('Completed scores disagree with summary: ' + name)
    v.check_acquisitions(f.read(args.sources), manifest['frozen_at'])
    wanted, acquisition = f.scan_sources(args.sources, excluded, pyzipper.AESZipFile)
    if acquisition['archive_warnings'] or set(wanted) != set(saved):
        raise ValueError('Source read integrity or SHA coverage changed')
    for k in wanted:
        if any(wanted[k][field] != original_samples[k][field] for field in ('label', 'source_id', 'byte_size')):
            raise ValueError('Source label/provenance/size changed')
    f.fresh_output(args.output)
    w.dump(args.output / 'acquisition-audit.json', acquisition)
    inputs = dict(complete=False, role='post_evaluation_descriptive_feature_diagnostics',
                  evaluation=str(args.evaluation), input_sha256=hashes,
                  script_sha256=digest(__file__), threshold_tuning=False)
    w.dump(args.output / 'diagnostic-inputs.json', inputs)
    schema = list(legacy['v7'][0].feature_names) + list(v.g.f.t.e.IMPORT_FEATURES)
    features = {}
    warnings = []
    max_error = 0.
    endpoint = args.service_url.rstrip('/')
    prior_info = f.read(args.evaluation / 'run-inputs.json')['service_model']
    with requests.Session() as session:
        response = session.get(endpoint + '/model', timeout=args.api_timeout)
        response.raise_for_status()
        info = response.json()
        f.c.validate_service(info, legacy['v7'][0])
        if info != prior_info:
            raise ValueError('Service configuration differs from completed evaluation')
        for location in acquisition['input_files']:
            for bytez in w.payloads(Path(location), pyzipper.AESZipFile, on_error=warnings.append):
                sha = hashlib.sha256(bytez).hexdigest()
                if sha not in wanted:
                    continue
                sample = wanted[sha]
                if len(bytez) != sample['byte_size']:
                    raise ValueError('Sample bytes changed')
                response = session.post(endpoint + '/diagnostics/score?include_features=1', data=bytez,
                                        headers={'Content-Type': 'application/octet-stream'}, timeout=args.api_timeout)
                response.raise_for_status()
                details = response.json()
                row = v.compare_one(sample, bytez, details, info, manifest, structural, bounded, legacy)
                max_error = max(max_error, verify_row(saved[sha], row))
                vector = list(map(float, details['reviewer_feature_vector'])) + list(map(float,
                         v.g.f.t.e._import_values({'libraries': details['reviewer_libraries']})))
                if len(vector) != len(schema) or not all(math.isfinite(x) for x in vector):
                    raise ValueError('Invalid feature vector')
                features[sha] = dict(vector=vector, libraries=details['reviewer_libraries'])
                del wanted[sha]
                if len(features) % 25 == 0:
                    print(f'Collected and parity-checked {len(features)}/{len(saved)}', flush=True)
                    w.dump(args.output / 'partial-feature-cache.json',
                           dict(complete=False, feature_names=schema, samples=features))
            if not wanted:
                break
        w.dump(args.output / 'archive-read-warnings.json', warnings)
        if wanted or warnings:
            raise ValueError('Required SHA coverage/read integrity failed')
        response = session.get(endpoint + '/model', timeout=args.api_timeout)
        response.raise_for_status()
        if response.json() != info:
            raise ValueError('Service changed during collection')
    v.load_bundle(args.bundle)
    if any(digest(path) != expected for path, expected in hashes.items()):
        raise ValueError('Input changed during diagnostics')
    report, errors = analyze(v, saved, features, schema)
    report.update(evaluation=str(args.evaluation), recollection_max_abs_error=max_error,
                  feature_schema=schema)
    w.dump(args.output / 'feature-cache.json',
           dict(complete=True, feature_names=schema, samples=features, scores=list(saved.values())))
    w.dump(args.output / 'error-samples.json', dict(feature_names=schema, samples=errors))
    # A separate conservative exclusion union; the frozen bundle is never edited.
    w.dump(args.output / 'excluded-sha256.json', sorted(set(excluded) | set(saved)))
    w.dump(args.output / 'feature-diagnostic-summary.json', report)
    inputs['complete'] = True
    w.dump(args.output / 'diagnostic-inputs.json', inputs)
    print(f'Complete feature diagnostics: {args.output}', flush=True)
    print('Send feature-diagnostic-summary.json and error-samples.json', flush=True)


def main():
    root = Path(__file__).resolve().parents[1] / 'validation-data'
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--evaluation', type=Path, help='Default: latest completed matching evaluation')
    ap.add_argument('--bundle', type=Path, default=root / 'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--sources', type=Path, default=root / 'reviewer-v8-structural-fresh-acquisition/sources.json')
    ap.add_argument('--service-url', required=True)
    ap.add_argument('--api-timeout', type=float, default=30.)
    ap.add_argument('--output', type=Path, help='Default: a new timestamped directory')
    args = ap.parse_args()
    try:
        run(args)
    except Exception as error:
        ap.exit(2, f'V8 structural feature diagnostics stopped: {error}\n')


if __name__ == '__main__':
    main()
