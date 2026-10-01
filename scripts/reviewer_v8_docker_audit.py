#!/usr/bin/env python3
"""Audit Docker features and coverage errors. No fitting, calibration, or gate changes."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import zipfile
from pathlib import Path

import numpy as np
import reviewer_v8_workflow as w
import reviewer_v8_coverage_compare as c
from defender.models.boundary_reviewer import _build_values, _import_values


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collection_paths(manifest):
    """Original benign paths are diagnostic provenance, never model inputs."""
    import pyzipper
    result={}
    for name in manifest.get('input_files',[]):
        path=Path(name)
        if not path.is_absolute():path=w.ROOT/path
        if not path.is_file() or not zipfile.is_zipfile(path):continue
        with pyzipper.AESZipFile(path) as archive:
            if 'collection-manifest.json' not in archive.namelist():continue
            collection=json.loads(archive.read('collection-manifest.json',pwd=b'infected'))
            for row in collection.get('samples',[]):
                if row.get('label')==0 and row.get('original_path'):
                    result[row['sha256']]=row['original_path']
    return result


def service_vector(sample, bytez, details, info, candidates):
    record = c.compare_one(sample, bytez, details, info, candidates)
    names = list(candidates['v7'][0].feature_names)
    vector = [float(v) for v in details['reviewer_feature_vector']]
    attrs = dict(zip(names, vector), libraries=details['reviewer_libraries'])
    build = _build_values(attrs)
    categories = []
    if _import_values(attrs)[-1] > 0: categories.append('kernel_driver_import')
    if build[3] > 0: categories.append('linker2_with_symbols')
    if build[4] > 0: categories.append('linker2_symbols_no_debug_tls')
    record['categories'] = categories
    return dict(record=record, feature_vector=vector, libraries=details['reviewer_libraries'])


def cache_differences(training, docker, cached, candidates):
    names = list(candidates['v7'][0].feature_names)
    structural = names[len(w.SCORE_FEATURES):]
    feature_counts = Counter(); maximum = {}; upstream_counts = Counter()
    score_changes = {}; affected = []; structural_samples=0; import_samples=0
    for row in training:
        sha = row['sha256']; entry = docker[sha]; fresh = entry['record']
        old = cached[sha]['structural_vector']; actual = entry['feature_vector'][len(w.SCORE_FEATURES):]
        if len(old) != len(structural): raise ValueError(f'Cache feature length mismatch: {sha}')
        changes = []
        for name, a, b in zip(structural, old, actual):
            a, b = float(a), float(b)
            if not np.isfinite(a): raise ValueError(f'Nonfinite cache feature: {sha}')
            if a != b:
                feature_counts[name] += 1
                maximum[name] = max(maximum.get(name, 0.), abs(a-b))
                changes.append(dict(feature=name, cached=a, docker=b))
        if changes:structural_samples+=1
        import_attrs = dict(cached[sha].get('attributes', {}))
        import_flags = list(_import_values(import_attrs))
        actual_flags = list(_import_values({'libraries': entry['libraries']}))
        import_changes = []
        for name,a,b in zip(c.IMPORT_FEATURES, import_flags, actual_flags):
            if a != b:
                feature_counts[name]+=1;maximum[name]=max(maximum.get(name,0.),abs(a-b))
                import_changes.append(dict(feature=name,cached=a,docker=b))
        if import_changes:import_samples+=1
        changes.extend(import_changes)
        for name in w.SCORE_FEATURES:
            if abs(float(row[name])-fresh[name]) > 1e-12: upstream_counts[name] += 1
        if changes:
            isolated = [fresh[k] for k in w.SCORE_FEATURES]+list(old)
            impacts = {}
            for name,(model,_) in candidates.items():
                old_score = c.reviewer_score(model, isolated+(import_flags if name!='v7' else []))
                new_score = fresh[name+'_score']
                routed, old_prediction = c.verdict(old_score,model,fresh,fresh['adapter_threshold'])
                impacts[name] = dict(cached_feature_score=old_score, docker_score=new_score,
                                     abs_score_change=abs(old_score-new_score),
                                     prediction_changed=old_prediction!=fresh[name+'_prediction'])
            affected.append(dict(sha256=sha,label=row['label'],source=row['source'],
                                 differences=changes, frozen_model_impacts=impacts))
    for name in candidates:
        impacts=[r['frozen_model_impacts'][name] for r in affected]
        score_changes[name]=dict(max_abs=max((r['abs_score_change'] for r in impacts),default=0.),
            changed_predictions=sum(r['prediction_changed'] for r in impacts))
    return dict(sample_count=len(training),samples_with_structural_differences=structural_samples,
        samples_with_import_indicator_differences=import_samples,samples_with_any_feature_differences=len(affected),
        feature_difference_counts=dict(feature_counts.most_common()),max_abs_by_feature=maximum,
        upstream_component_difference_counts=dict(upstream_counts),isolated_score_impact=score_changes,
        note='Score impact uses fresh Docker upstream components on both sides. Cached import identities are compared with Docker identities for v8. Equality is exact for structural features; upstream differences use 1e-12 tolerance.'),affected


def trace(model, vector):
    x = np.asarray(vector,dtype=np.float32).tolist() if model.input_dtype=='float32' else list(vector)
    stages=[]
    for i,tree in enumerate(model.estimators):
        node=0; path=[]
        while tree['children_left'][node]>=0:
            index=tree['feature'][node];value=x[index];cut=tree['threshold'][node];left=value<=cut
            path.append(dict(feature=model.feature_names[index],value=value,threshold=cut,branch='left' if left else 'right'))
            node=tree['children_left'][node] if left else tree['children_right'][node]
        stages.append(dict(stage=i,raw_score_contribution=model.learning_rate*float(tree['raw_value'][node]),path=path))
    return dict(initial_raw_score=model.initial_raw_score,
        probability=c.reviewer_score(model,vector),
        largest_malware_contributions=sorted([s for s in stages if s['raw_score_contribution']>0],key=lambda s:-s['raw_score_contribution'])[:8],
        largest_benign_contributions=sorted([s for s in stages if s['raw_score_contribution']<0],key=lambda s:s['raw_score_contribution'])[:8],
        note='Additive tree contributions and observed branches; not causal attribution.')


def error_audit(coverage, training, docker, candidates):
    fitting,_=w.preserved_split(training)
    if not fitting:raise ValueError('Empty original fit pool for neighbor audit')
    features=np.array([docker[r['sha256']]['feature_vector'][len(w.SCORE_FEATURES):] for r in fitting])
    transformed=np.log1p(np.maximum(features,0.))
    median=np.median(transformed,axis=0);q=np.quantile(transformed,[.25,.75],axis=0)
    scale=q[1]-q[0];std=np.std(transformed,axis=0)
    scale=np.where(scale>1e-12,scale,np.where(std>1e-12,std,1.))
    scaled=(transformed-median)/scale
    errors=[]
    for sample in coverage:
        entry=docker[sample['sha256']];row=entry['record']
        if row['v8_import_upper_prediction']==row['label']:continue
        v=entry['feature_vector'];flags=list(_import_values({'libraries':entry['libraries']}))
        target=(np.log1p(np.maximum(v[len(w.SCORE_FEATURES):],0.))-median)/scale
        distances=np.mean(np.minimum(np.abs(scaled-target),10.),axis=1)
        neighbors={}
        for label in (0,1):
            eligible=[i for i,r in enumerate(fitting) if r['label']==label
                      and docker[r['sha256']]['record']['v8_import_upper_prediction']==label]
            indices=sorted(eligible,key=lambda i:(distances[i],fitting[i]['sha256']))[:5]
            neighbors[str(label)]=[dict(sha256=fitting[i]['sha256'],source=fitting[i]['source'],
                distance=float(distances[i]),categories=docker[fitting[i]['sha256']]['record']['categories'],
                score=docker[fitting[i]['sha256']]['record']['v8_import_upper_score']) for i in indices]
        errors.append(dict(**row,libraries=entry['libraries'],original_path=entry.get('original_path'),
            selected_features={k:v[j] for j,k in enumerate(candidates['v7'][0].feature_names) if k in (
                'machine_MACHINE_TYPES.AMD64','major_linker_version','minor_linker_version','symbols',
                'has_debug','has_tls','imports','exports','numberof_sections','byte_size','byte_entropy','string_urls')},
            tree_paths={name:trace(model,v+(flags if name!='v7' else [])) for name,(model,_) in candidates.items()},
            nearest_correct_original_fit_samples=neighbors))
    return dict(error_count=len(errors),benign_errors=sum(r['label']==0 for r in errors),
        malware_errors=sum(r['label']==1 for r in errors),
        neighbor_method='Original fit split only; all shared structural features, no upstream scores or appended import flags. log1p, train-only median/IQR with std fallback, clipped mean absolute distance. Neighbors are correct under frozen v8.',
        errors=errors)


def collect(required, locations, candidates, info, session, endpoint, timeout, output, collected):
    import pyzipper
    wanted=set(required)-set(collected);warnings=[]
    total=len(required)
    for location in locations:
        if not wanted:break
        if not location.exists(): raise ValueError(f'Missing input: {location}')
        for bytez in w.payloads(location,pyzipper.AESZipFile,on_error=warnings.append):
            sha=hashlib.sha256(bytez).hexdigest()
            if sha not in wanted:continue
            if len(bytez)>16*1024*1024:raise ValueError(f'Required PE exceeds service size limit: {sha}')
            sample=required[sha]
            if sample.get('byte_size') is not None and len(bytez)!=sample['byte_size']:
                raise ValueError(f'Coverage size mismatch: {sha}')
            response=session.post(endpoint+'/diagnostics/score?include_features=1',data=bytez,
                headers={'Content-Type':'application/octet-stream'},timeout=timeout)
            response.raise_for_status()
            entry=service_vector(sample,bytez,response.json(),info,candidates)
            entry.update(pool=sample['pool'],input_location=str(location),byte_size=len(bytez),
                         original_path=sample.get('original_path'))
            collected[sha]=entry;wanted.remove(sha)
            if len(collected)%25==0:print(f'Docker features {len(collected)}/{total}',flush=True)
            if len(collected)%250==0:w.dump(output/'docker-feature-cache.json',dict(complete=False,samples=collected))
            if not wanted:break
    w.dump(output/'docker-feature-cache.json',dict(complete=not wanted,samples=collected))
    w.dump(output/'archive-read-warnings.json',warnings)
    if wanted:
        w.dump(output/'missing-sha256.json',sorted(wanted))
        raise ValueError(f'Missing {len(wanted)} required PE samples; checkpoint saved')
    return collected


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--service-url',required=True)
    ap.add_argument('--reports-dir',type=Path,default=w.ROOT/'validation-data')
    ap.add_argument('--coverage',type=Path,default=w.ROOT/'validation-data/reviewer-v8-coverage-development/coverage-manifest.json')
    ap.add_argument('--comparison',type=Path,default=w.ROOT/'validation-data/reviewer-v8-coverage-comparison-docker-features')
    ap.add_argument('--cache',type=Path,default=w.ROOT/'validation-data/reviewer-v8-development/feature-cache.json')
    ap.add_argument('--location',type=Path,action='append',help='PE roots/archives; default: validation-data')
    ap.add_argument('--output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-docker-audit')
    ap.add_argument('--api-timeout',type=float,default=30.)
    ap.add_argument('--resume',action='store_true')
    args=ap.parse_args();collected={};bound=None
    try:
        import requests
        manifest=json.loads(args.coverage.read_text());coverage=list(c.validate_manifest(manifest).values())
        candidates=c.load_candidates(manifest,w.ROOT)
        audit,reports=w.load_audit(args.reports_dir);training,old_reports=w.merge_training(args.reports_dir,audit);reports.update(old_reports)
        cached_doc=json.loads(args.cache.read_text());cached=cached_doc['samples']
        if cached_doc['provenance']['feature_names']!=list(candidates['v7'][0].feature_names):
            raise ValueError('Original feature cache has a different schema')
        if any(r['sha256'] not in cached for r in training):raise ValueError('Training cache is incomplete')
        prior=json.loads((args.comparison/'comparison-summary.json').read_text())
        if not prior.get('complete') or prior['frozen_candidate_sha256']!=manifest['frozen_candidate_sha256']:
            raise ValueError('Completed comparison does not match frozen candidates')
        with (args.comparison/'comparison-scores.csv').open(newline='') as stream:prior_rows=list(csv.DictReader(stream))
        prior_scores={r['sha256']:r for r in prior_rows}
        if len(prior_scores)!=len(prior_rows) or set(prior_scores)!={r['sha256'] for r in coverage}:
            raise ValueError('Completed comparison SHA set differs from coverage')
        required={r['sha256']:dict(r,source_id=r['source'],categories=[],pool='original_development') for r in training}
        original_paths=collection_paths(manifest)
        for row in coverage:
            row['original_path']=original_paths.get(row['sha256'])
            if row['sha256'] in required:raise ValueError('Coverage overlaps existing development data')
            label=row['label'];source=row['source_id'] if label==0 else 'coverage-malware:'+Path(row['input_location']).name
            required[row['sha256']]=dict(row,source_id=source,pool='coverage_development')
        if any(int(prior_scores[r['sha256']]['label'])!=r['label'] for r in coverage):
            raise ValueError('Coverage/comparison label conflict')
        endpoint=args.service_url.rstrip('/')
        locations=args.location or [args.reports_dir]
        inputs=dict(coverage_sha256=file_hash(args.coverage),cache_sha256=file_hash(args.cache),
            comparison_sha256=file_hash(args.comparison/'comparison-scores.csv'),
            report_sha256={k:file_hash(Path(v)) for k,v in reports.items()},
            frozen_candidate_sha256=manifest['frozen_candidate_sha256'],service_url=endpoint,
            locations=[str(p.resolve()) for p in locations],required_sha256=sorted(required),
            role='development',training=False,threshold_tuning=False)
        with requests.Session() as session:
            response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status();info=response.json()
            c.validate_service(info,candidates['v7'][0]);inputs['service_model']=info
            if args.resume:
                if json.loads((args.output/'run-inputs.json').read_text())!=inputs:raise ValueError('Resume inputs/service configuration changed')
                collected=json.loads((args.output/'docker-feature-cache.json').read_text())['samples']
                if set(collected)-set(required):raise ValueError('Checkpoint contains unexpected SHA')
                for sha,entry in collected.items():
                    if entry['record']['sha256']!=sha or entry['record']['label']!=required[sha]['label']:
                        raise ValueError('Invalid checkpoint SHA/label')
                    record=entry['record']
                    details=dict(record,reviewer_feature_names=list(candidates['v7'][0].feature_names),
                        reviewer_feature_vector=entry['feature_vector'],reviewer_libraries=entry['libraries'],
                        sample_sha256=sha,reviewer_probability=record['v7_score'],reviewer_routed=True,
                        reviewer_threshold=info['reviewer_threshold'],result=int(record['v7_score']>=info['reviewer_threshold']))
                    checked=c.compare_one(required[sha],b'',details,info,candidates)
                    for name in c.NAMES:
                        if abs(checked[name+'_score']-record[name+'_score'])>1e-12 or checked[name+'_prediction']!=record[name+'_prediction']:
                            raise ValueError('Checkpoint score does not reproduce from its Docker vector')
            elif args.output.exists() and any(args.output.iterdir()):
                raise ValueError('Output directory is not empty; use --resume or a new --output')
            w.dump(args.output/'run-inputs.json',inputs);bound=inputs
            if (args.output/'docker-audit-summary.json').exists():
                (args.output/'docker-audit-summary.json').unlink()
            collect(required,locations,candidates,info,session,endpoint,args.api_timeout,args.output,collected)
            response=session.get(endpoint+'/model',timeout=args.api_timeout);response.raise_for_status()
            if response.json()!=info:raise ValueError('Service configuration changed during audit')
        for sample in coverage:
            sha=sample['sha256'];fresh=collected[sha]['record'];previous=prior_scores[sha]
            for name in c.NAMES:
                if abs(fresh[name+'_score']-float(previous[name+'_score']))>1e-9 or fresh[name+'_prediction']!=int(previous[name+'_prediction']):
                    raise ValueError(f'Coverage comparison no longer reproduces: {sha}')
        differences,affected=cache_differences(training,collected,cached,candidates)
        errors=error_audit(coverage,training,collected,candidates)
        w.dump(args.output/'cache-differences.json',affected)
        w.dump(args.output/'coverage-error-audit.json',errors)
        fresh_rows=[collected[r['sha256']]['record'] for r in coverage]
        comparison=c.summarize(fresh_rows,candidates)
        summary=dict(complete=True,training=False,threshold_tuning=False,
            original_development_count=len(training),coverage_count=len(coverage),
            total_docker_samples=len(collected),cache_alignment=differences,
            coverage_comparison=comparison,coverage_error_counts=dict(benign=errors['benign_errors'],malicious=errors['malware_errors']),
            all_sample_v7_parity_max_abs=max(e['record']['v7_service_parity_error'] for e in collected.values()),
            frozen_candidate_sha256=manifest['frozen_candidate_sha256'],
            warning='Development diagnostic only; no model trained or deployment changed. Exact Docker vectors are preserved separately from the original cache.')
        w.dump(args.output/'docker-audit-summary.json',summary)
        print(json.dumps(summary,indent=2));print(f'Send docker-audit-summary.json, cache-differences.json and coverage-error-audit.json from {args.output}')
    except Exception as error:
        if bound is not None:
            w.dump(args.output/'docker-feature-cache.json',dict(complete=False,samples=collected))
            w.dump(args.output/'failure.json',dict(error=str(error),collected=len(collected)))
        ap.exit(2,f'V8 Docker audit stopped: {error}\n')


if __name__=='__main__':main()
