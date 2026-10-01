#!/usr/bin/env python3
"""Controlled 72-feature training from audited Docker vectors; development only."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

import numpy as np
import reviewer_v8_workflow as w
import reviewer_v8_coverage_compare as c
import reviewer_v8_import_experiment as e
from reviewer_v8_followup import midpoint_threshold

SEED = 2704


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def group_for(entry):
    """Acquisition/software groups affect splitting only, never model features."""
    row=entry['record']
    if row['label']==1:
        return 'malware-acquisition:'+row['source'].removeprefix('coverage-malware:')
    path=str(entry.get('original_path') or '').replace('\\','/').casefold()
    match=re.search(r'/program files(?: \(x86\))?/([^/]+)',path)
    if match:
        # Combine the same installation root across Program Files and x86.
        return 'benign-software:'+match.group(1)
    if '/windows/' in path:return 'benign-windows:'+row['source']
    return 'benign-acquisition:'+row['source']


def grouped_split(rows,groups,fraction=.2):
    by_label=defaultdict(lambda:defaultdict(list))
    for row in rows:by_label[row['label']][groups[row['sha256']]].append(row)
    training,calibration=[],[];assignment={}
    for label,cohorts in sorted(by_label.items()):
        order=sorted(cohorts,key=lambda g:hashlib.sha256(f'{SEED}:{label}:{g}'.encode()).hexdigest())
        target=sum(len(v) for v in cohorts.values())*fraction
        selected=[];count=0
        for group in order:
            proposed=count+len(cohorts[group])
            if abs(proposed-target)<abs(count-target) and len(selected)<len(order)-1:
                selected.append(group);count=proposed
        if not selected and len(order)>1:
            selected=[min(order,key=lambda g:(abs(len(cohorts[g])-target),g))]
        for group in order:
            role='calibration' if group in selected else 'training';assignment[group]=role
            (calibration if role=='calibration' else training).extend(cohorts[group])
    training.sort(key=lambda r:r['sha256']);calibration.sort(key=lambda r:r['sha256'])
    if {groups[r['sha256']] for r in training}&{groups[r['sha256']] for r in calibration}:
        raise ValueError('New acquisition/software group crosses split')
    return training,calibration,assignment


def load_data(audit_dir,coverage_path,reports_dir):
    manifest=json.loads(coverage_path.read_text());coverage=c.validate_manifest(manifest)
    candidates=c.load_candidates(manifest,w.ROOT)
    summary=json.loads((audit_dir/'docker-audit-summary.json').read_text())
    cache=json.loads((audit_dir/'docker-feature-cache.json').read_text())
    inputs=json.loads((audit_dir/'run-inputs.json').read_text())
    if (not summary.get('complete') or not cache.get('complete')
            or summary['frozen_candidate_sha256']!=manifest['frozen_candidate_sha256']
            or inputs['coverage_sha256']!=digest(coverage_path)):
        raise ValueError('Complete matching Docker audit is required')
    audit,reports=w.load_audit(reports_dir);original,paths=w.merge_training(reports_dir,audit);reports.update(paths)
    if {k:digest(Path(v)) for k,v in reports.items()}!=inputs['report_sha256']:
        raise ValueError('Original reports changed after Docker audit')
    old={r['sha256']:r for r in original};samples=cache['samples']
    if set(samples)!=set(old)|set(coverage) or set(old)&set(coverage):
        raise ValueError('Docker cache SHA pool differs from original+coverage pool')
    if summary['total_docker_samples']!=len(samples):raise ValueError('Docker audit count mismatch')
    rows={};structural={};groups={}
    names=list(candidates['v7'][0].feature_names)
    if len(names)!=66:raise ValueError('Expected original 66-feature v7 schema')
    for index,(sha,entry) in enumerate(samples.items(),1):
        if index%1000==0:print(f'Validating frozen Docker cache {index}/{len(samples)}',flush=True)
        row=entry['record'];expected=old.get(sha,coverage.get(sha))
        if row['sha256']!=sha or row['label']!=expected['label']:raise ValueError('Cache label/SHA mismatch')
        vector=entry['feature_vector']
        if len(vector)!=len(names) or not np.isfinite(vector).all():raise ValueError('Invalid Docker feature vector')
        if list(vector[:len(w.SCORE_FEATURES)])!=[row[k] for k in w.SCORE_FEATURES]:raise ValueError('Vector/component mismatch')
        if float(row['adapter_threshold'])!=.7:raise ValueError('Adapter threshold changed')
        if sha in old and row['source']!=old[sha]['source']:raise ValueError('Original source changed')
        extra=list(e._import_values({'libraries':entry['libraries']}))
        for name,(model,_) in candidates.items():
            score=c.reviewer_score(model,list(vector)+(extra if name!='v7' else []))
            routed,pred=c.verdict(score,model,row,.7)
            if abs(score-row[name+'_score'])>1e-9 or routed!=row[name+'_routed'] or pred!=row[name+'_prediction']:
                raise ValueError(f'Frozen score no longer reproduces from Docker cache: {sha}')
        rows[sha]={k:row[k] for k in ('sha256','label','source',*w.SCORE_FEATURES)}
        structural[sha]=dict(structural_vector=list(vector[len(w.SCORE_FEATURES):])+extra)
        if sha in coverage:groups[sha]=group_for(entry)
    original_rows=[rows[r['sha256']] for r in original]
    coverage_rows=sorted([rows[sha] for sha in coverage],key=lambda r:r['sha256'])
    return original_rows,coverage_rows,structural,groups,samples,candidates


def probabilities(clf,rows,cached):
    return clf.predict_proba(np.array([w.vector(r,cached[r['sha256']]) for r in rows]))[:,1]


def gated(rows,scores,threshold,route=.15):
    return np.array([int(p>=threshold) if r['adapter_probability']>=route
                     else int(r['adapter_probability']>=.7) for r,p in zip(rows,scores)])


def calibrate(clf,rows,cached):
    scores=probabilities(clf,rows,cached)
    routed=np.array([r['adapter_probability']>=.15 for r in rows])
    # Below route .15, adapter threshold .7 necessarily yields benign.
    upper,rates,source_rates=w.calibrate(rows,np.where(routed,scores,0.))
    interval=midpoint_threshold(np.where(routed,scores,0.),upper)
    midpoint=interval['threshold']
    if not np.array_equal(gated(rows,scores,upper),gated(rows,scores,midpoint)):
        raise ValueError('Midpoint changes calibration predictions')
    return dict(upper=upper,midpoint=midpoint,midpoint_interval=interval,calibration=rates,by_source=source_rates)


def evaluate(clf,rows,cached,policies,groups=None):
    scores=probabilities(clf,rows,cached)
    thresholds=dict(upper=policies['upper'],midpoint=policies['midpoint'],
                    frozen_import_upper=.639722991937624,frozen_import_midpoint=.6330136993086144)
    result={}
    for name,t in thresholds.items():
        pred=gated(rows,scores,t)
        result[name]=dict(threshold=t,overall=w.metrics(rows,pred),
            by_source={source:w.metrics([r for r in rows if r['source']==source],pred[[i for i,r in enumerate(rows) if r['source']==source]])
                       for source in sorted({r['source'] for r in rows})})
        if groups:
            result[name]['by_new_group']={g:w.metrics([r for r in rows if groups.get(r['sha256'])==g],
                pred[[i for i,r in enumerate(rows) if groups.get(r['sha256'])==g]]) for g in sorted({groups[r['sha256']] for r in rows if r['sha256'] in groups})}
    return result,scores


def export_checked(clf,frozen,threshold,rows,cached,path):
    payload=e.export_imports(clf,frozen,threshold)
    model=w.BoundaryReviewer.__new__(w.BoundaryReviewer);model._load(payload)
    expected=probabilities(clf,rows,cached)
    actual=np.array([c.reviewer_score(model,w.vector(r,cached[r['sha256']])) for r in rows])
    error=float(np.max(np.abs(actual-expected)))
    if error>1e-10:raise ValueError(f'Export parity failed: {error}')
    w.dump(path,payload)
    return error


def related_old_sources(group):
    # Conservative known acquisition links; this is not a malware-family claim.
    if group.startswith('malware-acquisition:malwarebazaar-v10-'):
        return {'reviewer-v5-v10-diagnostic'}
    if group.startswith('malware-acquisition:malwarebazaar-v11-'):
        return {'batch-v11'}
    return set()


def run_experiment(original,new,cached,groups,samples,candidates,output):
    old_fit,old_cal=w.preserved_split(original)
    new_fit,new_cal,assignment=grouped_split(new,groups)
    if {r['sha256'] for r in old_fit}&{r['sha256'] for r in old_cal}:raise ValueError('Original split overlaps')
    all_rows=original+new;frozen=candidates['v7'][1]
    w.dump(output/'split_manifest.json',dict(original_training=[r['sha256'] for r in old_fit],
        original_calibration=[r['sha256'] for r in old_cal],new_training=[r['sha256'] for r in new_fit],
        new_calibration=[r['sha256'] for r in new_cal],new_groups=groups,group_assignment=assignment,
        seed=SEED,group_rule='Entire benign installation/acquisition root or malware acquisition batch; group selection uses counts/labels, never scores or error status. Historical original split is preserved.'))
    print(f'Original fit/cal: {len(old_fit)}/{len(old_cal)}; new grouped fit/cal: {len(new_fit)}/{len(new_cal)}',flush=True)
    control=w.fit(old_fit,cached,.15)
    expanded=w.fit(old_fit+new_fit,cached,.15)
    control_policy=calibrate(control,old_cal,cached)
    expanded_policy=calibrate(expanded,old_cal+new_cal,cached)
    result=dict(completed=False,experiment='reviewer_v8_exact_docker_grouped_expansion',configuration=w.CONFIG,
        route_min=.15,feature_count=len(frozen['feature_names'])+len(e.IMPORT_FEATURES),
        original_samples=len(original),new_samples=len(new),new_group_count=len(assignment),
        source_label_counts=dict(Counter(f"{r['source']}:label_{r['label']}" for r in all_rows)),
        group_counts={g:dict(count=sum(groups[r['sha256']]==g for r in new),role=assignment[g]) for g in assignment},
        models={},group_holdouts=[],
        warning='Development only: coverage informed this experiment. New groups are kept intact; the historical original split may contain related software/families. Acquisition grouping does not prove family independence. Labels are preserved, including samples flagged for further provenance review.')
    score_rows=[]
    for name,clf,policy in (('old_data_control',control,control_policy),('expanded_candidate',expanded,expanded_policy)):
        record=dict(policies=policy,evaluations={},export_parity={})
        for pool,rows in [('original_calibration',old_cal),('new_grouped_calibration',new_cal),('all_new_development',new)]:
            if not rows:continue
            evaluation,scores=evaluate(clf,rows,cached,policy,groups)
            record['evaluations'][pool]=evaluation
            if pool=='all_new_development':
                for row,p in zip(rows,scores):
                    score_rows.append(dict(model=name,sha256=row['sha256'],label=row['label'],group=groups[row['sha256']],
                        split=assignment[groups[row['sha256']]],score=float(p),
                        upper_prediction=int(gated([row],[p],policy['upper'])[0]),
                        midpoint_prediction=int(gated([row],[p],policy['midpoint'])[0])))
        for policy_name in ('upper','midpoint'):
            record['export_parity'][policy_name]=export_checked(clf,frozen,policy[policy_name],all_rows,cached,
                output/(name+'-'+policy_name+'-model.json'))
        result['models'][name]=record
    w.dump(output/'training-summary.json',result)
    # Always test major new benign groups and every new malware acquisition group.
    # Entire held group is excluded from candidate fitting AND calibration.
    eligible=[g for g in sorted(assignment) if g.startswith('malware-acquisition:')
              or sum(groups[r['sha256']]==g for r in new)>=10]
    for group in eligible:
        held=[r for r in new if groups[r['sha256']]==group]
        related=related_old_sources(group)
        fit_old=[r for r in old_fit if r['source'] not in related]
        cal_old=[r for r in old_cal if r['source'] not in related]
        fit_new=[r for r in new_fit if groups[r['sha256']]!=group]
        cal_new=[r for r in new_cal if groups[r['sha256']]!=group]
        print(f'Group holdout {group}: {len(held)} samples; related old sources excluded: {sorted(related)}',flush=True)
        fold_control=w.fit(fit_old,cached,.15) if related else control
        fold_candidate=w.fit(fit_old+fit_new,cached,.15)
        cp=calibrate(fold_control,cal_old,cached);ep=calibrate(fold_candidate,cal_old+cal_new,cached)
        ce,cs=evaluate(fold_control,held,cached,cp,groups);ee,es=evaluate(fold_candidate,held,cached,ep,groups)
        held_sha={r['sha256'] for r in held}
        if held_sha&{r['sha256'] for r in fit_old+cal_old+fit_new+cal_new}:raise ValueError('Group leaked into fold')
        result['group_holdouts'].append(dict(group=group,count=len(held),excluded_old_sources=sorted(related),
            old_fit=len(fit_old),old_calibration=len(cal_old),new_fit=len(fit_new),new_calibration=len(cal_new),
            control=ce,candidate=ee))
        w.dump(output/'training-summary.json',result)
        for name,scores,policy in [('control',cs,cp),('candidate',es,ep)]:
            for row,p in zip(held,scores):
                score_rows.append(dict(model='group_holdout_'+name,sha256=row['sha256'],label=row['label'],
                    group=group,split='held_out_entire_group',score=float(p),
                    upper_prediction=int(gated([row],[p],policy['upper'])[0]),
                    midpoint_prediction=int(gated([row],[p],policy['midpoint'])[0])))
    result['group_holdout_coverage']=dict(groups=len(eligible),samples=sum(f['count'] for f in result['group_holdouts']),
        excluded_small_benign_groups=[g for g in sorted(assignment) if g not in eligible],
        note='All new samples take part in main fit/calibration. Small benign groups are omitted from leave-group-out diagnostics only.')
    result['completed']=True
    w.dump(output/'development-scores.json',score_rows)
    w.dump(output/'training-summary.json',result)
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--audit-dir',type=Path,default=w.ROOT/'validation-data/reviewer-v8-docker-audit')
    ap.add_argument('--coverage',type=Path,default=w.ROOT/'validation-data/reviewer-v8-coverage-development/coverage-manifest.json')
    ap.add_argument('--reports-dir',type=Path,default=w.ROOT/'validation-data')
    ap.add_argument('--output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-docker-training-development')
    args=ap.parse_args()
    try:
        if args.output.exists() and any(args.output.iterdir()):raise ValueError('Output not empty; use a fresh --output directory')
        original,new,cached,groups,samples,candidates=load_data(args.audit_dir,args.coverage,args.reports_dir)
        inputs=dict(docker_cache_sha256=digest(args.audit_dir/'docker-feature-cache.json'),
            docker_audit_summary_sha256=digest(args.audit_dir/'docker-audit-summary.json'),
            coverage_sha256=digest(args.coverage),frozen_candidate_sha256={k:digest(w.ROOT/k) for k in
                json.loads(args.coverage.read_text())['frozen_candidate_sha256']},configuration=w.CONFIG,
            grouping_seed=SEED,script_sha256=digest(Path(__file__)))
        w.dump(args.output/'inputs.json',inputs)
        result=run_experiment(original,new,cached,groups,samples,candidates,args.output)
        print(json.dumps(result,indent=2));print(f'Send training-summary.json and split_manifest.json from {args.output}')
    except Exception as error:ap.exit(2,f'V8 exact Docker training stopped: {error}\n')


if __name__=='__main__':main()
