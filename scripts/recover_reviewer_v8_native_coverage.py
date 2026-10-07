#!/usr/bin/env python3
"""Resume native coverage without changing its bound experiment dependencies."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import resource
import sys
import traceback
from types import SimpleNamespace

import numpy as np
from scipy.special import expit
import reviewer_v8_native_coverage as n

SCORER_VERSION='float32-input-float64-branch-training-order-v1'


def array_scores(payload,X):
    # Cast to float32 first, then widen: numpy float32/scalar comparison can
    # round a double threshold to float32, unlike sklearn's C++ traversal.
    values=np.asarray(X,dtype=np.float32).astype(np.float64)
    if values.ndim!=2 or values.shape[1]!=len(payload['feature_names']):
        raise ValueError('Recovery scoring schema differs')
    if not np.isfinite(values).all():raise ValueError('Nonfinite recovery features')
    raw=np.full(len(values),float(payload['initial_raw_score']))
    for tree in payload['estimators']:
        left=np.asarray(tree['children_left'],dtype=np.int64)
        right=np.asarray(tree['children_right'],dtype=np.int64)
        features=np.asarray(tree['feature'],dtype=np.int64)
        thresholds=np.asarray(tree['threshold'],dtype=np.float64)
        leaves=np.asarray(tree['raw_value'],dtype=np.float64)
        nodes=np.zeros(len(values),dtype=np.int64)
        for _ in range(len(left)+1):
            active=np.flatnonzero(left[nodes]>=0)
            if not len(active):break
            at=nodes[active]
            go_left=values[active,features[at]]<=thresholds[at]
            nodes[active]=np.where(go_left,left[at],right[at])
        else:raise ValueError('Recovery tree traversal did not terminate')
        # Preserve the original sequential per-tree accumulation exactly.
        raw+=float(payload['learning_rate'])*leaves[nodes]
    return expit(raw)


@contextmanager
def checked_scorer():
    original=n.audit.training_order_scores;calls=0
    def score(payload,X):
        nonlocal calls
        actual=array_scores(payload,X)
        if len(X):
            ids=np.unique(np.linspace(0,len(X)-1,min(32,len(X)),dtype=int))
            expected=original(payload,np.asarray(X)[ids])
            if not np.array_equal(actual[ids],expected):
                raise ValueError('Recovery scorer differs from the bound original scorer')
        calls+=1
        if calls==1 or calls%100==0:
            # Linux reports KiB, macOS bytes; this runner is for the Linux VM.
            print(f'Recovery scoring calls: {calls}; peak RSS: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024:.0f} MiB',flush=True)
        return actual
    n.audit.training_order_scores=score
    try:yield
    finally:n.audit.training_order_scores=original


def completed_count(folder):
    count=0
    for seed in n.s.SEEDS:
        marker=folder/f'seed-{seed}/completion.json'
        if marker.is_file():
            doc=n.cache.read(marker)
            if doc.get('complete') is True and doc.get('seed')==seed:count+=1
    return count


def select_run(root):
    candidates=[]
    for path in root.glob('reviewer-v8-native-coverage-*'):
        if all((path/name).is_file() for name in ('inputs.json','split-manifest.json','excluded-sha256.json')):
            if n.cache.read(path/'split-manifest.json') is not None:
                candidates.append((completed_count(path),(path/'inputs.json').stat().st_mtime_ns,str(path),path))
    if not candidates:raise ValueError('No existing native coverage run; this command never starts a new run')
    return max(candidates)[-1]


def run(args):
    folder=(args.resume or select_run(args.root)).resolve()
    identity=n.cache.read(folder/'inputs.json')
    print(f'Recovering: {folder}\nCompleted seed markers: {completed_count(folder)}/5',flush=True)
    # Preserve all completed output files, including the final report. Source
    # integrity and saved seed artifacts are checked before any work begins.
    n.cache.verify_hashes(identity['input_sha256'])
    for seed in n.s.SEEDS:
        marker=folder/f'seed-{seed}/completion.json'
        if marker.is_file():
            doc=n.cache.read(marker)
            if doc.get('complete') is not True or doc.get('seed')!=seed:raise ValueError('Invalid seed completion')
            n.cache.verify_hashes(doc['artifact_sha256'])
    report=folder/'native-coverage-summary.json'
    if report.is_file() and n.cache.read(report).get('complete') is True:
        print('Already complete. Send native-coverage-summary.json.',flush=True);return
    hashes={str(Path(__file__).resolve()):n.cache.digest(__file__)}
    record=dict(scorer_version=SCORER_VERSION,recovery_sha256=hashes,
        original_input_sha256=identity['input_sha256'],resume=str(folder),
        scoring='Float32 features widened to float64 for double-threshold branches; sequential tree sums. Every call checked bit-for-bit against the original scorer on up to 32 rows; original full control replay/export checks remain enforced.',
        split_changes=False,threshold_search_changes=False,seed_selection=False,complete=False)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    recovery=folder/('recovery-'+stamp+'.json');n.cache.dump(recovery,record)
    settings=SimpleNamespace(root=args.root,run=Path(identity['source_run']),native_cache=Path(identity['native_cache']),
        structural_bundle=args.structural_bundle.resolve(),output=folder,resume=folder,audit_only=False)
    with checked_scorer():n.run(settings)
    n.cache.verify_hashes(hashes);record['complete']=True;n.cache.dump(recovery,record)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--resume',type=Path,help='Default: existing run with the most completed seed markers, then newest inputs')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    args=ap.parse_args();args.root=root
    try:run(args)
    except Exception:
        traceback.print_exc()
        print('Recovery stopped; keep the output directory and share this traceback.',file=sys.stderr)
        raise SystemExit(2)


if __name__=='__main__':main()
