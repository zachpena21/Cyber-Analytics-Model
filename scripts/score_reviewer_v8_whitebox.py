#!/usr/bin/env python3
"""Score the instructor's labeled ZIP through a selected v8; never execute PEs."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import time
import zipfile

import math
import urllib.request


def request(url,data=None):
    headers={'Content-Type':'application/octet-stream'} if data is not None else {}
    with urllib.request.urlopen(urllib.request.Request(url,data=data,headers=headers),timeout=60) as response:return json.load(response)


def model_score(model,vector):
    # IEEE float32 round-trip without numpy, preserving double split thresholds.
    import struct
    values=[struct.unpack('f',struct.pack('f',float(v)))[0] for v in vector];leaves=[]
    for tree in model['estimators']:
        node=0
        while tree['children_left'][node]>=0:
            node=tree['children_left' if values[tree['feature'][node]]<=tree['threshold'][node] else 'children_right'][node]
        leaves.append(tree['raw_value'][node])
    raw=model['initial_raw_score']+model['learning_rate']*sum(leaves)
    return 1/(1+math.exp(-raw)) if raw>=0 else math.exp(raw)/(1+math.exp(raw))


def load_samples(archive):
    """Resolve manifest paths by class/hash: shipped paths use samples/ instead."""
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read('manifest.json', pwd=b'infected'))
        entries = {e.filename: e for e in z.infolist()}
        samples = []
        seen = set()
        for item in manifest['samples']:
            sha = item['sha256']
            if sha in seen:
                raise ValueError('Duplicate manifest hash: ' + sha)
            seen.add(sha)
            if not isinstance(item['is_malware'], bool):
                raise ValueError('Manifest label must be boolean')
            role = 'malware' if item['is_malware'] else 'goodware'
            name = role + '/' + sha + '.bin'
            entry = entries[name]
            if entry.file_size != item['size'] or entry.file_size > 16777216:
                raise ValueError('Invalid sample size: ' + sha)
            raw = z.read(entry, pwd=b'infected')
            if hashlib.sha256(raw).hexdigest() != sha or not raw.startswith(b'MZ'):
                raise ValueError('Invalid sample bytes: ' + sha)
            samples.append((dict(item, archive_member=name), raw))
        counts = {role: sum(item['is_malware'] == role for item, _ in samples) for role in (False, True)}
        if counts != {False: 50, True: 50}:
            raise ValueError('Expected exactly 50 benign and 50 malware samples')
        return samples


def run(args):
    samples = load_samples(args.archive)
    model = json.loads(args.model.read_text())
    service = args.service_url.rstrip('/')
    info = request(service + '/model')
    if (not info.get('score_endpoint_enabled') or not info.get('boundary_reviewer')
            or info.get('reviewer_route_min') != model['route_min']
            or info.get('reviewer_threshold') != model['reviewer_threshold']
            or 'ReviewerV8' not in info.get('classifier', '')):
        raise ValueError('Service must match the selected v8 model with diagnostics enabled')
    rows = []
    target = args.output_prefix.with_suffix('.json')
    target.parent.mkdir(parents=True, exist_ok=True)

    def save(complete):
        valid = [r for r in rows if 'error' not in r]
        tp = sum(r['is_malware'] and r['result'] == 1 for r in valid)
        tn = sum(not r['is_malware'] and r['result'] == 0 for r in valid)
        fn = [r for r in valid if r['is_malware'] and r['result'] == 0]
        fp = [r for r in valid if not r['is_malware'] and r['result'] == 1]
        report = dict(complete=complete, successful=len(valid), errors=len(rows)-len(valid),
            sample_count=len(rows), archive_sha256=hashlib.sha256(args.archive.read_bytes()).hexdigest(),
            model_sha256=hashlib.sha256(args.model.read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
            service_url=service, service_model=info, true_positives=tp, true_negatives=tn,
            false_negatives=fn, false_positives=fp,
            detection_rate=tp/50 if complete and len(valid)==100 else None,
            false_positive_rate=len(fp)/50 if complete and len(valid)==100 else None,
            accuracy=(tp+tn)/100 if complete and len(valid)==100 else None,
            training=False, scope='Selected-v8 runtime measurement on instructor-disclosed whitebox tuning samples; not independent validation.', rows=rows)
        temp = target.with_suffix('.tmp')
        temp.write_text(json.dumps(report, indent=2)+'\n'); temp.replace(target)
        fields = ['sha256','is_malware','family','source_name','size','result','correct',
                  'benign_probability','adapter_probability','reviewer_routed','reviewer_probability',
                  'reviewer_probability_offline','reviewer_threshold','reviewer_margin',
                  'signature_checked','signature_verified','http_seconds','error']
        with args.output_prefix.with_suffix('.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
            writer.writeheader(); writer.writerows(rows)
        return report

    for index, (item, raw) in enumerate(samples, 1):
        row = dict(item)
        try:
            start = time.perf_counter()
            details = request(service + '/diagnostics/score?include_features=1', raw)
            row['http_seconds'] = time.perf_counter()-start
            if details.get('error'):
                raise ValueError(str(details['error']))
            if details.get('sample_sha256') != item['sha256']:
                raise ValueError('Service sample hash differs')
            if details.get('reviewer_feature_names') != model['feature_names']:
                raise ValueError('Service feature schema differs')
            if details.get('result') not in (0, 1):
                raise ValueError('Invalid decision')
            offline = model_score(model, details['reviewer_feature_vector'])
            if details['reviewer_routed'] and abs(offline-details['reviewer_probability']) > 1e-9:
                raise ValueError('Service reviewer score differs from frozen model')
            public = request(service + '/', raw)
            if public.get('result') != details['result']:
                raise ValueError('Public and diagnostic decisions differ')
            row.update(details)
            row.update(correct=details['result']==int(item['is_malware']),
                       reviewer_probability_offline=offline,
                       reviewer_margin=offline-model['reviewer_threshold'])
        except Exception as error:
            row['error'] = str(error)
        rows.append(row); save(False)
        status = 'ERROR' if 'error' in row else ('OK' if row['correct'] else ('MISSED MALWARE' if item['is_malware'] else 'FALSE POSITIVE'))
        print(f"{index}/100 {item['sha256'][:12]} {status}", flush=True)
    report = save(True)
    print('Reports: '+str(target)+' and '+str(args.output_prefix.with_suffix('.csv')))
    if report['errors']:
        raise ValueError('Scoring errors occurred; inspect the saved report')
    print(f"Detected {report['true_positives']}/50 malware; benign correct {report['true_negatives']}/50")
    for row in report['false_negatives']:
        print('MISS '+row['sha256']+' family='+str(row.get('family'))+
              ' adapter='+str(row['adapter_probability'])+' routed='+str(row['reviewer_routed'])+
              ' reviewer='+str(row['reviewer_probability']))


def main():
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--archive', type=Path, required=True)
    ap.add_argument('--service-url', default='http://localhost:8083')
    ap.add_argument('--model', type=Path, default=root/'defender/defender/models/boundary_reviewer_v8_final/model.json')
    ap.add_argument('--output-prefix', type=Path, default=root/'validation-data/whitebox-v8-baseline')
    run(ap.parse_args())


if __name__ == '__main__':
    main()
