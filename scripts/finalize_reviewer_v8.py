#!/usr/bin/env python3
"""Finalize the exact frozen structural v8 weights; no fit or threshold search."""
import argparse
import copy
from datetime import datetime,timezone
import json
import math
from pathlib import Path
import zipfile

import numpy as np
import reviewer_v8_structural_validation as frozen
import reviewer_v8_rich_ablation as rich

cache=rich.cache
SELECTED_SHA='ff433712d7bbd0c84a9275846f88b4b0e4f191223e521d7d56440597ad7a9bb4'
THRESHOLD=0.6882517225516912
ROUTE=.15


def runtime_export(structural,reference):
    """Embed the same structural trees in the existing format-8 vector."""
    imports=list(frozen.g.f.t.e.IMPORT_FEATURES)
    if structural['feature_names']!=list(reference.feature_names)[6:]+imports:
        raise ValueError('Frozen structural schema differs from runtime reference')
    if structural['reviewer_threshold']!=THRESHOLD:raise ValueError('Selected threshold differs')
    payload=dict(format_version=8,input_dtype='float32',model_type='gradient_boosting',
        route_min=ROUTE,reviewer_threshold=THRESHOLD,
        feature_names=list(reference.feature_names)+imports,categories=copy.deepcopy(reference.categories),
        derived_features=list(reference.derived_features),import_features=imports,
        learning_rate=structural['learning_rate'],initial_raw_score=structural['initial_raw_score'],
        estimators=copy.deepcopy(structural['estimators']),
        model_id='boundary_reviewer_v8_final',structural_feature_count=len(structural['feature_names']),
        source_structural_sha256=SELECTED_SHA,training=False,
        note='Exact frozen provenance fold-zero structural trees. First six runtime score/signature fields are unused; split feature indices are shifted by six only.')
    for tree in payload['estimators']:
        tree['feature']=[int(i)+6 if int(i)>=0 else int(i) for i in tree['feature']]
    reviewer=frozen.w.BoundaryReviewer.__new__(frozen.w.BoundaryReviewer);reviewer._load(payload)
    if any(i<6 for tree in payload['estimators'] for i,left in zip(tree['feature'],tree['children_left']) if left>=0):
        raise ValueError('Export unexpectedly uses an upstream score')
    return payload,reviewer


def runtime_scores(reviewer,matrix):
    result=[]
    for vector in np.asarray(matrix,dtype=np.float32).tolist():
        raw=reviewer.initial_raw_score+reviewer.learning_rate*sum(reviewer._tree_leaf(tree,vector,'raw_value') for tree in reviewer.estimators)
        result.append(1/(1+math.exp(-raw)) if raw>=0 else math.exp(raw)/(1+math.exp(raw)))
    return np.asarray(result)


def check_parity(structural,reviewer,entries,names):
    if names!=list(reviewer.feature_names)[:-len(reviewer.import_features)]:raise ValueError('Parity cache runtime schema differs')
    keys=sorted(entries);rows=[entries[k]['record'] for k in keys]
    matrix=np.asarray([entries[k]['feature_vector']+list(map(float,frozen.g.f.t.e._import_values(
        {'libraries':entries[k]['libraries']}))) for k in keys])
    expected=frozen.g.exported_scores(structural,matrix[:,6:]);actual=runtime_scores(reviewer,matrix)
    error=float(np.max(abs(expected-actual)))
    if error>1e-12 or not np.array_equal(expected,actual):raise ValueError('Runtime export scores differ from frozen scores')
    before=frozen.g.gated(rows,expected,THRESHOLD);after=frozen.g.gated(rows,actual,THRESHOLD)
    if not np.array_equal(before,after):raise ValueError('Runtime export decisions differ')
    # Tree decisions must be independent of the six unused upstream fields.
    probe=matrix[:min(64,len(matrix))].copy();probe[:,:6]=np.arange(6)+100.
    if not np.array_equal(runtime_scores(reviewer,probe),actual[:len(probe)]):raise ValueError('Unused upstream features change reviewer scores')
    return dict(sample_count=len(keys),max_abs_score_error=error,decision_mismatches=0,
        score_equality='bit-for-bit',upstream_invariance_checked=len(probe),
        raw_pe_docker_parity=False,note='Cached Docker-compatible vectors and runtime tree evaluator. New Python/LIEF extraction still requires end-to-end container parity.')


def candidate_inventory(root):
    result=[]
    for base in (root/'defender/defender/models',root/'validation-data'):
        if not base.exists():continue
        patterns=('boundary_reviewer*/metadata.json',) if base.name=='models' else (
            'reviewer-v8*/freeze-manifest.json','reviewer-v8*/native-coverage-summary.json',
            'reviewer-v8*/targeted-seed-ensemble-summary.json','reviewer-v8*/group-balanced-weighting-summary.json',
            'reviewer-v8*/rich-ablation-comparison-summary.json')
        for pattern in patterns:
            for path in sorted(base.glob(pattern)):
                result.append(dict(path=str(path.relative_to(root)),sha256=cache.digest(path)))
    return result


def run(args):
    manifest,structural,_,legacy,excluded=frozen.load_bundle(args.bundle)
    source=args.bundle/manifest['models'][frozen.PRIMARY]['path']
    if cache.digest(source)!=SELECTED_SHA or manifest['models'][frozen.PRIMARY]!=dict(path='structural-primary-model.json',threshold=THRESHOLD,route_min=ROUTE):
        raise ValueError('Bundle is not the selected, previously evaluated structural primary')
    payload,reviewer=runtime_export(structural,legacy['v7'][0])
    directory=args.cache or rich.find_cache(args.root/'validation-data')
    baseline=cache.read(directory/'development-input-cache.json');summary=cache.read(directory/'rich-feature-summary.json')
    _,hashes=rich.validate_cache(directory,baseline['samples'],baseline['feature_names'],summary['converted_sha256'])
    print(f'Checking exact runtime export on {len(baseline["samples"])} cached vectors...',flush=True)
    parity=check_parity(structural,reviewer,baseline['samples'],baseline['feature_names'])
    catalog=candidate_inventory(args.root)
    hashes[str(source)]=cache.digest(source);hashes[str(args.bundle/'freeze-manifest.json')]=cache.digest(args.bundle/'freeze-manifest.json')
    for module in (frozen,rich,cache):hashes[str(Path(module.__file__).resolve())]=cache.digest(module.__file__)
    hashes[str(Path(__file__).resolve())]=cache.digest(__file__)
    cache.verify_hashes(hashes);frozen.f.fresh_output(args.output)
    modeldir=args.output/'boundary_reviewer_v8_final';cache.dump(modeldir/'model.json',payload)
    metadata=dict(name='Reviewer v8 final: frozen structural primary',source_model_sha256=SELECTED_SHA,
        runtime_model_sha256=cache.digest(modeldir/'model.json'),route_min=ROUTE,reviewer_threshold=THRESHOLD,
        structural_feature_count=66,runtime_vector_count=72,unused_runtime_fields=list(reviewer.feature_names[:6]),
        tree_count=len(payload['estimators']),selection=manifest['selection'],refit=False,threshold_tuning=False,
        observed_evaluation=dict(benign=526,false_positives=2,malware=92,true_positives=75,
            note='Recorded pre-refinement batch; later inspected as development data. Not a hidden-course estimate.'),
        candidate_policy='Retain every historical candidate; final choice is the unchanged structural primary.')
    cache.dump(modeldir/'metadata.json',metadata)
    selection=dict(complete=True,training=False,final_refit=False,deployment_changed=False,
        selected='structural_primary',input_sha256=hashes,parity=parity,candidates=catalog,
        outstanding='Full Docker runtime parity, approved Python base-image compatibility and resource checks; then submit through Canvas.')
    cache.dump(args.output/'reviewer-v8-finalization-summary.json',selection)
    archive=args.output/'reviewer-v8-final-model.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for path in (modeldir/'model.json',modeldir/'metadata.json'):
            info=zipfile.ZipInfo(str(path.relative_to(args.output)),date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(info,path.read_bytes())
    cache.verify_hashes(hashes)
    print(f'Final export: {args.output}\nSend reviewer-v8-final-model.zip and reviewer-v8-finalization-summary.json. This model ZIP is not yet the Docker submission ZIP.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1];ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,default=root/'validation-data/reviewer-v8-structural-frozen-validation')
    ap.add_argument('--cache',type=Path,help='Default: newest completed rich feature cache')
    ap.add_argument('--output',type=Path,default=root/'validation-data'/('reviewer-v8-final-export-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    args=ap.parse_args();args.root=root
    for key in ('bundle','cache','output'):
        if getattr(args,key):setattr(args,key,getattr(args,key).resolve())
    try:run(args)
    except Exception as error:ap.exit(2,f'V8 finalization stopped: {error}\n')


if __name__=='__main__':main()
