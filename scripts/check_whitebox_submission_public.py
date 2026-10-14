#!/usr/bin/env python3
"""Check the standalone image through its public API; diagnostics stay disabled."""
import argparse
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

from score_reviewer_v8_whitebox import load_samples


def request(url, raw=None):
    headers = {'Content-Type': 'application/octet-stream'} if raw is not None else {}
    with urllib.request.urlopen(urllib.request.Request(url, data=raw, headers=headers), timeout=5) as response:
        return json.load(response)


def run(archive, service):
    info = request(service+'/model')
    from defender.reviewer_rescue import POLICY
    if (info.get('score_endpoint_enabled') or info.get('reviewer_threshold') != .6
            or info.get('reviewer_route_min') != .15 or info.get('reviewer_agreement_rescue') != POLICY
            or info.get('threshold') != .510001 or info.get('adapter_threshold') != .7):
        raise ValueError('Standalone public service policy differs')
    try:
        request(service+'/diagnostics/score', b'MZ')
        raise ValueError('Diagnostics unexpectedly available')
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    rows = []
    for item, raw in load_samples(archive):
        row = dict(sha256=item['sha256'], is_malware=item['is_malware'], bytes=len(raw))
        start = time.perf_counter()
        try:
            result = request(service+'/', raw)
            if set(result) != {'result'} or type(result['result']) is not int or result['result'] not in (0, 1):
                raise ValueError('Public response schema differs')
            row.update(result=result['result'], correct=result['result'] == int(item['is_malware']))
        except Exception as error:
            row.update(error=str(error), correct=False)
        row['http_seconds'] = time.perf_counter()-start
        rows.append(row)
    errors = sum('error' in r for r in rows)
    tp = sum(r['is_malware'] and r.get('result') == 1 for r in rows)
    tn = sum(not r['is_malware'] and r.get('result') == 0 for r in rows)
    maximum = max(r['http_seconds'] for r in rows)
    return dict(complete=True, passed=len(rows) == 100 and errors == 0 and tp == tn == 50 and maximum <= 5,
                sample_count=len(rows), errors=errors, malware_detected=tp, benign_correct=tn,
                max_public_http_seconds=maximum, diagnostics_disabled=True, service_model=info, rows=rows,
                scope='Standalone image public-API verification on disclosed TA tuning set; not independent accuracy validation.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--service-url', default='http://127.0.0.1:8080')
    args = parser.parse_args()
    result = run(args.archive, args.service_url.rstrip('/'))
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
