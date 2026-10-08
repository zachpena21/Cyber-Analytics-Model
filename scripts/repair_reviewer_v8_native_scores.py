#!/usr/bin/env python3
"""Restore damaged native held scores only when original checkpoint hashes match."""
import argparse
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import sys
import traceback

import reviewer_v8_native_coverage_audit as audit

n,cache=audit.n,audit.cache


def damaged_scores(source):
    source=source.resolve();identity=cache.read(source/'inputs.json');cache.verify_hashes(identity['input_sha256'])
    saved=cache.read(source/'native-coverage-summary.json')
    if saved.get('complete') is not True or saved['completed_seeds']!=list(n.s.SEEDS):raise ValueError('Need a completed five-seed run')
    repairs={}
    for seed in n.s.SEEDS:
        folder=source/f'seed-{seed}';doc=cache.read(folder/'completion.json')
        if doc.get('complete') is not True or doc['seed']!=seed:raise ValueError('Seed completion differs')
        allowed={str(folder/v/arm/'development-scores.json') for v in n.t.VARIANTS for arm in n.t.ARMS}
        if not allowed<=set(doc['artifact_sha256']):raise ValueError('Completion does not bind every held score file')
        for path,expected in doc['artifact_sha256'].items():
            file=Path(path);actual=cache.digest(file) if file.is_file() else None
            if actual!=expected:
                if path not in allowed:raise ValueError('Refusing repair of changed model/metadata/other artifact: '+path)
                repairs[path]=dict(expected_sha256=expected,damaged_sha256=actual)
    return repairs


def restore(source,repairs,hashes):
    if any('regenerated_bytes' not in record or hashlib.sha256(record['regenerated_bytes']).hexdigest()!=record['expected_sha256'] for record in repairs.values()):
        raise ValueError('Not every proposed repair reproduces its original hash')
    audit.verify_artifacts(hashes,repairs)
    # Guard against another writer changing a file during replay.
    for path,record in repairs.items():
        actual=cache.digest(path) if Path(path).is_file() else None
        if actual!=record['damaged_sha256']:raise ValueError('Damaged file changed during repair: '+path)
    destination=source/('score-repair-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    destination.mkdir()
    report=dict(complete=False,training=False,markers_changed=False,source_run=str(source),
        repair_script_sha256=cache.digest(__file__),files={})
    for i,(path,record) in enumerate(sorted(repairs.items())):
        backup=destination/f'damaged-{i:02d}.bin';file=Path(path)
        if file.is_file():backup.write_bytes(file.read_bytes())
        report['files'][path]=dict(expected_sha256=record['expected_sha256'],damaged_sha256=record['damaged_sha256'],
            backup=str(backup) if backup.is_file() else None)
    cache.dump(destination/'score-repair-summary.json',report)
    for path,record in sorted(repairs.items()):
        file=Path(path);temporary=file.with_suffix('.json.repair-tmp')
        temporary.write_bytes(record['regenerated_bytes'])
        if cache.digest(temporary)!=record['expected_sha256']:raise ValueError('Staged repair hash differs')
        temporary.replace(file)
    cache.verify_hashes(hashes)
    report['complete']=True;cache.dump(destination/'score-repair-summary.json',report)
    return destination


def run(args):
    with audit.named_json_reads():
        source=(args.run or audit.latest(args.root)).resolve();repairs=damaged_scores(source)
        if not repairs:
            audit.check_saved_json(source);print('No damaged checkpoint-bound score files. Run the audit.',flush=True);return
        print(f'Run: {source}\nDamaged held score files: {len(repairs)}. Replaying saved models; no fits.',flush=True)
        args.run=source
        with audit.recovery.checked_scorer():loaded=audit.load(args,repairs)
        destination=restore(source,repairs,loaded[-1])
        audit.check_saved_json(source)
        print(f'Restored original score hashes. Backups and report: {destination}\nRun reviewer_v8_native_coverage_audit.py.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,help='Default: newest completed native coverage run')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    args=ap.parse_args();args.root=root;args.structural_bundle=args.structural_bundle.resolve()
    try:run(args)
    except Exception:
        traceback.print_exc();print('Score repair stopped. No checkpoint hashes are rewritten.',file=sys.stderr)
        raise SystemExit(2)


if __name__=='__main__':main()
