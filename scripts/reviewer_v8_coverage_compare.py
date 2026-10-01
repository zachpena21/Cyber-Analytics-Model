#!/usr/bin/env python3
"""Compare frozen reviewers on an audited coverage pool; never fit or tune."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

import numpy as np

import reviewer_v8_workflow as w
from defender.models.boundary_reviewer import IMPORT_FEATURES, _import_values

NAMES = ('v7', 'v8_import_upper', 'v8_import_midpoint')
CATEGORIES = ('kernel_driver_import', 'linker2_with_symbols',
              'linker2_symbols_no_debug_tls', 'other')


def validate_manifest(manifest):
    if manifest.get('complete') is not True or manifest.get('role') != 'development':
        raise ValueError('Requires a complete development coverage manifest')
    rows = manifest.get('samples', [])
    if not rows or len(rows) != manifest['counts']['unused_pe']:
        raise ValueError('Coverage sample count mismatch')
    seen = set()
    for row in rows:
        sha = row['sha256']
        if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
            raise ValueError('Invalid coverage SHA')
        if sha in seen or row['label'] not in (0, 1):
            raise ValueError('Duplicate SHA or invalid coverage label')
        seen.add(sha)
    if not any(r['label'] == 0 for r in rows) or not any(r['label'] == 1 for r in rows):
        raise ValueError('Comparison requires both classes')
    return {r['sha256']: r for r in rows}


def load_candidates(manifest, root):
    frozen = manifest['frozen_candidate_sha256']
    paths = [root/'defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json',
             root/'validation-data/reviewer-v8-import-features-development/model.json',
             root/'validation-data/reviewer-v8-followup-development/imports-interval_midpoint-model.json']
    result = {}
    for name, path in zip(NAMES, paths):
        key = str(path.relative_to(root))
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != frozen.get(key):
            raise ValueError(f'Frozen candidate changed or missing from manifest: {key}')
        result[name] = (w.BoundaryReviewer(path), json.loads(content))
    if result['v7'][1]['format_version'] != 6:
        raise ValueError('Expected the original format-6 v7 reference')
    if any(result[n][1]['format_version'] != 8 for n in NAMES[1:]):
        raise ValueError('Expected format-8 import candidates')
    return result


def validate_service(info, v7):
    if not info.get('reviewer_feature_diagnostics'):
        raise ValueError('Rebuild the Docker image: reviewer feature diagnostics are missing')
    if not info.get('modern_adapter') or not info.get('score_endpoint_enabled'):
        raise ValueError('Requires modern adapter and DF_ENABLE_SCORE_ENDPOINT=1')
    if info.get('modern_adapter_v2') or not info.get('boundary_reviewer'):
        raise ValueError('Run the original v7 diagnostic service, with adapter v2 disabled')
    if not math.isclose(float(info['reviewer_threshold']), v7.threshold, abs_tol=1e-12, rel_tol=0):
        raise ValueError('Service reviewer threshold differs from frozen v7')
    if float(info['reviewer_route_min']) != 0.:
        raise ValueError('Run start_reviewer_diagnostic.ps1 -Version v7 for all-sample parity (route 0)')
    if not math.isclose(float(info['adapter_threshold']), .7, abs_tol=1e-12, rel_tol=0):
        raise ValueError('Expected original adapter threshold 0.7')


def components(details, info):
    if details.get('error'):
        raise ValueError(f"Service failed to classify: {details['error']}")
    result = {}
    for key in w.SCORE_FEATURES:
        value = details.get(key)
        if key == 'signature_verified' and value is None:
            value = False
        if value is None:
            raise ValueError(f'Missing service component: {key}')
        value = float(value)
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f'Invalid service component: {key}')
        if not key.endswith('probability') and value not in (0., 1.):
            raise ValueError(f'Nonboolean service component: {key}')
        result[key] = value
    if float(details['adapter_threshold']) != float(info['adapter_threshold']):
        raise ValueError('Service adapter threshold changed during run')
    if float(details['reviewer_threshold']) != float(info['reviewer_threshold']):
        raise ValueError('Service reviewer threshold changed during run')
    expected = result['adapter_probability'] >= float(info['reviewer_route_min'])
    if details.get('reviewer_routed') is not expected:
        raise ValueError('Service reviewer routing mismatch')
    return result


def reviewer_score(model, vector):
    # Match the deployed runtime exactly, including Python-float comparisons
    # after float32 conversion (NumPy scalar comparisons vary by version).
    if model.input_dtype == 'float32':
        vector = np.asarray(vector, dtype=np.float32).tolist()
    raw = model.initial_raw_score + model.learning_rate * sum(
        model._tree_leaf(tree, vector, 'raw_value') for tree in model.estimators)
    if raw >= 0.:
        return 1. / (1. + math.exp(-raw))
    value = math.exp(raw)
    return value / (1. + value)


def verdict(score, model, upstream, adapter_threshold):
    routed = upstream['adapter_probability'] >= model.route_min
    return routed, int(score >= model.threshold) if routed else int(upstream['adapter_probability'] >= adapter_threshold)


def compare_one(sample, bytez, details, info, candidates):
    upstream = components(details, info)
    v7 = candidates['v7'][0]
    if details.get('sample_sha256') != sample['sha256']:
        raise ValueError('Service feature payload SHA mismatch')
    if details.get('reviewer_feature_names') != list(v7.feature_names):
        raise ValueError('Service feature schema differs from frozen v7')
    vector = details.get('reviewer_feature_vector')
    if not isinstance(vector, list) or len(vector) != len(v7.feature_names):
        raise ValueError('Missing or invalid Docker reviewer feature vector')
    vector = [float(v) for v in vector]
    if not all(math.isfinite(v) for v in vector):
        raise ValueError('Nonfinite Docker reviewer feature')
    if vector[:len(w.SCORE_FEATURES)] != [upstream[k] for k in w.SCORE_FEATURES]:
        raise ValueError('Docker vector/upstream component mismatch')
    if not isinstance(details.get('reviewer_libraries'), str):
        raise ValueError('Missing Docker ordinary-import libraries')
    imports = list(_import_values({'libraries': details['reviewer_libraries']}))
    row = dict(sha256=sample['sha256'], label=sample['label'], source=sample['source_id'],
               categories=sample['categories'], **upstream,
               adapter_threshold=float(info['adapter_threshold']))
    for name, (model, payload) in candidates.items():
        expected_names = list(v7.feature_names) + (list(IMPORT_FEATURES) if name != 'v7' else [])
        if list(model.feature_names) != expected_names:
            raise ValueError('Candidate feature schema cannot use frozen Docker vector')
        score = reviewer_score(model, vector + (imports if name != 'v7' else []))
        routed, prediction = verdict(score, model, upstream, row['adapter_threshold'])
        row.update({name+'_score': score, name+'_routed': routed, name+'_prediction': prediction})
    if details['reviewer_routed']:
        service_score = float(details['reviewer_probability'])
        if not math.isfinite(service_score):
            raise ValueError('Nonfinite service reviewer score')
        error = abs(service_score-row['v7_score'])
        if error > 1e-9:
            raise ValueError(f"Frozen v7 parity failed for {row['sha256']}: max_abs={error:.12g}")
        expected = int(service_score >= float(info['reviewer_threshold']))
    else:
        error = None
        expected = int(upstream['adapter_probability'] >= row['adapter_threshold'])
    if details['result'] not in (0, 1) or details['result'] != expected:
        raise ValueError('Service result does not match its reported gate/threshold')
    row['v7_service_parity_error'] = error
    return row


def summarize(rows, candidates):
    def rates(selected, name):
        return w.metrics(selected, [r[name+'_prediction'] for r in selected])
    result = dict(sample_count=len(rows), benign=sum(r['label']==0 for r in rows),
                  malicious=sum(r['label']==1 for r in rows), models={})
    for name, (model, _) in candidates.items():
        errors = [r['sha256'] for r in rows if r[name+'_prediction'] != r['label']]
        result['models'][name] = dict(threshold=model.threshold, route_min=model.route_min,
            overall=rates(rows,name), routed=sum(r[name+'_routed'] for r in rows),
            by_category={cat:rates([r for r in rows if cat in r['categories'] or
                (cat=='other' and not r['categories'])],name) for cat in CATEGORIES},
            error_sha256=errors)
    result['paired_changes_vs_v7'] = {}
    for name in NAMES[1:]:
        changes = {}
        for label, cname in ((0,'benign'),(1,'malicious')):
            selected = [r for r in rows if r['label']==label]
            changes[cname] = dict(
                rescued=[r['sha256'] for r in selected if r['v7_prediction']!=label and r[name+'_prediction']==label],
                regressed=[r['sha256'] for r in selected if r['v7_prediction']==label and r[name+'_prediction']!=label])
        result['paired_changes_vs_v7'][name] = changes
    checked = [r['v7_service_parity_error'] for r in rows if r['v7_service_parity_error'] is not None]
    result['v7_service_parity'] = dict(checked=len(checked), max_abs=max(checked, default=None))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, default=w.ROOT/'validation-data/reviewer-v8-coverage-development/coverage-manifest.json')
    ap.add_argument('--service-url', required=True)
    ap.add_argument('--api-timeout', type=float, default=30.)
    ap.add_argument('--output', type=Path, default=w.ROOT/'validation-data/reviewer-v8-coverage-comparison')
    args = ap.parse_args()
    try:
        import requests
        import pyzipper
        if args.output.exists() and any(args.output.iterdir()):
            raise ValueError('Output directory is not empty; use a new --output directory')
        content = args.manifest.read_bytes()
        manifest = json.loads(content)
        wanted = validate_manifest(manifest)
        candidates = load_candidates(manifest, w.ROOT)
        endpoint = args.service_url.rstrip('/')
        with requests.Session() as session:
            response = session.get(endpoint+'/model', timeout=args.api_timeout)
            response.raise_for_status(); info = response.json()
            validate_service(info, candidates['v7'][0])
            rows, warnings = [], []
            w.dump(args.output/'run-inputs.json', dict(manifest_sha256=hashlib.sha256(content).hexdigest(),
                frozen_candidate_sha256=manifest['frozen_candidate_sha256'], service_model=info,
                service_url=endpoint, role='development', threshold_tuning=False))
            for location in dict.fromkeys(manifest['input_files']):
                path = Path(location)
                if not path.is_absolute():path = w.ROOT/path
                for bytez in w.payloads(path, pyzipper.AESZipFile, on_error=warnings.append):
                    sha = hashlib.sha256(bytez).hexdigest()
                    if sha not in wanted:continue
                    sample = wanted[sha]
                    if len(bytez)!=sample['byte_size']:
                        raise ValueError(f'Coverage byte size changed: {sha}')
                    response = session.post(endpoint+'/diagnostics/score?include_features=1', data=bytez,
                        headers={'Content-Type':'application/octet-stream'}, timeout=args.api_timeout)
                    response.raise_for_status()
                    rows.append(compare_one(sample, bytez, response.json(), info, candidates))
                    del wanted[sha]
                    if len(rows)%25==0:
                        print(f'Scored {len(rows)}/{manifest["counts"]["unused_pe"]}', flush=True)
                        w.dump(args.output/'partial-scores.json',rows)
                    if not wanted:break
                if not wanted:break
            w.dump(args.output/'archive-read-warnings.json',warnings)
            if wanted:
                w.dump(args.output/'missing-sha256.json',sorted(wanted))
                raise ValueError(f'Missing {len(wanted)} required coverage samples')
            response=session.get(endpoint+'/model',timeout=args.api_timeout)
            response.raise_for_status()
            if response.json()!=info:raise ValueError('Service configuration changed during comparison')
        summary=summarize(rows,candidates)
        summary.update(complete=True, role='development',
            scope=manifest['scope'], threshold_tuning=False,
            feature_source='Docker original-v7 vector plus fixed ordinary-import indicators',
            warning='Development comparison only. These samples are not reserved independent final evaluation.',
            archive_warning_count=len(warnings),
            frozen_candidate_sha256=manifest['frozen_candidate_sha256'])
        # Final outputs are written only after full SHA coverage and parity pass.
        w.dump(args.output/'comparison-scores.json',rows)
        fields=[k for k in rows[0] if k!='categories']+['categories']
        with (args.output/'comparison-scores.csv').open('w',newline='',encoding='utf-8') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
            for row in rows:writer.writerow(dict(row,categories=' '.join(row['categories'])))
        w.dump(args.output/'comparison-summary.json',summary)
        print(json.dumps(summary,indent=2))
        print(f'Send comparison-summary.json and comparison-scores.csv from {args.output}')
    except Exception as error:
        ap.exit(2,f'V8 frozen coverage comparison stopped: {error}\n')


if __name__=='__main__':main()
