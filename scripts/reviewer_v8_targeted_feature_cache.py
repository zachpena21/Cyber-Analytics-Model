#!/usr/bin/env python3
"""Collect SHA-bound Docker and rich features for filtered targeted benign development data."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

import reviewer_v8_rich_feature_cache as cache

MAX_PE = 16 * 1024 * 1024


def inventory_samples(directory, prior_excluded):
    """Verify inventory lineage and payloads before contacting the service."""
    summary = cache.read(directory / 'targeted-benign-inventory-summary.json')
    marker = cache.read(directory / 'inputs.json')
    if (summary.get('complete') is not True or summary.get('training') is not False
            or summary.get('independent_validation') is not False
            or summary.get('role') != 'targeted_benign_development_inventory'):
        raise ValueError('Need a completed development inventory')
    cache.verify_hashes(marker['input_sha256'])
    exclusion = str(prior_excluded.resolve())
    if marker['input_sha256'].get(exclusion) != cache.digest(prior_excluded):
        # Earlier inventory commands may have used relative paths.
        bound = [p for p,h in marker['input_sha256'].items()
                 if Path(p).resolve() == prior_excluded.resolve() and h == cache.digest(prior_excluded)]
        if len(bound) != 1:
            raise ValueError('Inventory was not filtered against the selected prior cache')
    excluded = set(cache.read(prior_excluded))
    sources_path = directory / 'sources.json'
    sources = cache.read(sources_path)
    artifacts = {str(Path(a['path']).resolve()):a for a in summary['artifacts']}
    if len(artifacts) != len(summary['artifacts']) or len(sources) != len(artifacts):
        raise ValueError('Inventory source/artifact coverage differs')
    hashes = dict(marker['input_sha256'])
    for name in ('inputs.json', 'sources.json', 'targeted-benign-inventory-summary.json'):
        path = directory / name
        hashes[str(path)] = cache.digest(path)
    samples = {}
    seen_paths = set()
    for source in sources:
        path = Path(source['path']).resolve()
        if str(path) in seen_paths or str(path) not in artifacts:
            raise ValueError('Duplicate or unexpected source')
        seen_paths.add(str(path))
        artifact = artifacts[str(path)]
        if cache.digest(path) != artifact['sha256'] or source['label'] != 0 or source.get('development_only') is not True:
            raise ValueError('Inventory archive identity/role changed')
        hashes[str(path)] = artifact['sha256']
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read('collection-manifest.json'))
            if (manifest['provenance'] != source['provenance']
                    or manifest['provenance'].get('development_only') is not True
                    or len(manifest['samples']) != artifact['sample_count']):
                raise ValueError('Archive manifest/provenance mismatch')
            patterns = Counter()
            for row in manifest['samples']:
                sha = row['sha256']
                if (not isinstance(sha, str) or len(sha) != 64
                        or any(c not in '0123456789abcdef' for c in sha)
                        or sha in samples or sha in excluded or row['label'] != 0):
                    raise ValueError('Invalid, duplicate or historically overlapping SHA')
                member = archive.getinfo(row['archive_member'])
                if not 0 < member.file_size <= MAX_PE:
                    raise ValueError('Payload exceeds PE size limit')
                bytez = archive.read(member)
                if (len(bytez) != row['byte_size'] or bytez[:2] != b'MZ'
                        or hashlib.sha256(bytez).hexdigest() != sha):
                    raise ValueError('Payload SHA/size/header mismatch')
                samples[sha] = dict(row=row, bytez=bytez, source=source,
                                    location=str(path)+'!/'+row['archive_member'])
                patterns[row['pattern']] += 1
            if dict(patterns) != artifact['by_pattern']:
                raise ValueError('Archive pattern counts differ')
    patterns = dict(Counter(s['row']['pattern'] for s in samples.values()))
    if (not samples or len(samples) != summary['unique_new_samples']
            or len(artifacts) != summary['product_cohorts'] or patterns != summary['by_pattern']):
        raise ValueError('Inventory summary does not match payloads')
    return samples, hashes


def build_sample(sha, sample, details, info, names, v, bundle):
    manifest, structural, bounded, legacy, _ = bundle
    record_input = dict(sha256=sha, label=0, source_id=sample['source']['source_id'], categories=[])
    row = v.compare_one(record_input, sample['bytez'], details, info, manifest, structural, bounded, legacy)
    entry = dict(record=row, feature_vector=list(map(float, details['reviewer_feature_vector'])),
                 libraries=details['reviewer_libraries'], byte_size=len(sample['bytez']),
                 input_location=sample['location'], provenance=dict(original_member=sample['row']['original_member'],
                    original_path=sample['row'].get('original_path'), provenance=sample['source']['provenance']))
    v.g.checked_entry(sha, entry, names, legacy, historical=False)
    feature = cache.rich.extract(sample['bytez'], entry['libraries'])
    cache.validate_feature(feature)
    feature.update(raw_sha256=sha, byte_size=len(sample['bytez']), location=sample['location'])
    return dict(entry=entry, rich=feature, diagnostic_details=details)


def collect(samples, saved, score, build, checkpoint):
    """Replay saved payloads on resume; checkpoint every completed SHA."""
    if not set(saved) <= set(samples):
        raise ValueError('Resume contains unexpected SHAs')
    for sha in sorted(samples):
        if sha in saved:
            if build(sha, samples[sha], saved[sha]['diagnostic_details']) != saved[sha]:
                raise ValueError('Resume parity/feature mismatch: '+sha)
            continue
        saved[sha] = build(sha, samples[sha], score(samples[sha]['bytez']))
        checkpoint()
        print(f'Collected targeted features {len(saved)}/{len(samples)}', flush=True)
    return saved


def run(args):
    import requests
    import reviewer_v8_rich_ablation as ablation
    import reviewer_v8_structural_validation as v
    prior = cache.read(args.prior_cache / 'development-input-cache.json')
    report = cache.read(args.prior_cache / 'rich-feature-summary.json')
    _, hashes = ablation.validate_cache(args.prior_cache, prior['samples'], prior['feature_names'], report['converted_sha256'])
    samples, inventory_hashes = inventory_samples(args.inventory, args.prior_cache / 'excluded-sha256.json')
    hashes.update(inventory_hashes)
    bundle = v.load_bundle(args.structural_bundle)
    names = list(bundle[3]['v7'][0].feature_names)
    if names != prior['feature_names'] or set(samples) & bundle[4]:
        raise ValueError('Frozen schema/exclusion mismatch')
    # Bind every imported project module; frozen dependencies are read only.
    for module in list(sys.modules.values()):
        path = getattr(module, '__file__', None)
        if path and Path(path).suffix == '.py' and Path(path).resolve().is_relative_to(Path(__file__).resolve().parents[1]):
            hashes[str(Path(path).resolve())] = cache.digest(path)
    hashes[str(Path(__file__).resolve())] = cache.digest(__file__)
    for path in args.structural_bundle.rglob('*'):
        if path.is_file():
            hashes[str(path)] = cache.digest(path)
    endpoint = args.service_url.rstrip('/')
    with requests.Session() as session:
        def model_info():
            response = session.get(endpoint+'/model', timeout=args.api_timeout)
            response.raise_for_status()
            info = response.json()
            v.f.c.validate_service(info, bundle[3]['v7'][0])
            return info
        info = model_info()
        identity = dict(role='targeted_benign_development_feature_collection', input_sha256=hashes,
                        sample_sha256=sorted(samples), baseline_feature_names=names,
                        feature_names=list(cache.rich.FEATURE_NAMES), service_model=info)
        saved = {}
        if args.resume:
            args.output = args.resume
            if cache.read(args.output/'targeted-collection-inputs.json') != identity:
                raise ValueError('Resume input/model/parser identity changed; use a new output')
            saved = cache.read(args.output/'partial-targeted-feature-cache.json')['samples']
        else:
            v.f.fresh_output(args.output)
            cache.dump(args.output/'targeted-collection-inputs.json', identity)
        def checkpoint():
            cache.dump(args.output/'partial-targeted-feature-cache.json', dict(complete=False, samples=saved))
        def score(bytez):
            response = session.post(endpoint+'/diagnostics/score?include_features=1', data=bytez,
                                    headers={'Content-Type':'application/octet-stream'}, timeout=args.api_timeout)
            response.raise_for_status()
            return response.json()
        checkpoint()
        collect(samples, saved, score, lambda sha,sample,details:build_sample(sha,sample,details,info,names,v,bundle), checkpoint)
        if model_info() != info:
            raise ValueError('Diagnostic service changed during collection')
    cache.verify_hashes(hashes)
    v.load_bundle(args.structural_bundle)
    differences = []
    for sha, s in samples.items():
        static = sorted(set(s['row']['metadata']['imports']))
        docker = sorted(set(saved[sha]['entry']['libraries'].lower().split()))
        if static != docker:
            differences.append(dict(sha256=sha, static_imports=static, docker_imports=docker))
    entries = {k:r['entry'] for k,r in saved.items()}
    features = {k:r['rich'] for k,r in saved.items()}
    parity = [r['record']['v7_service_parity_error'] for r in entries.values()]
    if any(e is None for e in parity):
        raise ValueError('All-route service did not check every sample')
    cache.dump(args.output/'targeted-development-input-cache.json', dict(complete=True,feature_names=names,samples=entries))
    cache.dump(args.output/'targeted-rich-feature-cache.json', dict(complete=True,feature_names=list(cache.rich.FEATURE_NAMES),
        blocks={k:list(n) for k,n in cache.rich.BLOCKS.items()},samples=features))
    cache.dump(args.output/'excluded-sha256.json', sorted(set(prior['samples']) | set(samples)))
    summary = dict(complete=True, role='targeted_benign_development_feature_collection', training=False,
        threshold_tuning=False, independent_validation=False, prior_cache=str(args.prior_cache),
        inventory=str(args.inventory), sample_count=len(entries), product_cohorts=len({s['source']['source_id'] for s in samples.values()}),
        by_pattern=dict(Counter(s['row']['pattern'] for s in samples.values())),
        parser_status=dict(Counter(f['status'] for f in features.values())),
        docker_parity_checked=len(parity), docker_parity_max_abs=max(parity),
        static_import_difference_count=len(differences), static_import_differences=differences,
        combined_development_count=len(prior['samples'])+len(entries),
        interpretation='Docker ordinary imports supply model features. Static import differences are diagnostic only. Separate additive development cache; no fitting, threshold search or edits to prior caches/frozen models.')
    cache.dump(args.output/'targeted-feature-summary.json', summary)
    print(f'Complete: {args.output}\nSend targeted-feature-summary.json. No models fitted.', flush=True)


def main():
    root = Path(__file__).resolve().parents[1]/'validation-data'
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inventory', type=Path, required=True)
    ap.add_argument('--prior-cache', type=Path, required=True)
    ap.add_argument('--structural-bundle', type=Path, default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--service-url', required=True)
    ap.add_argument('--api-timeout', type=float, default=60.)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--resume', type=Path)
    args = ap.parse_args()
    if args.output and args.resume:
        ap.error('Use either --output or --resume')
    for key in ('inventory','prior_cache','structural_bundle','resume'):
        value = getattr(args,key)
        if value:
            setattr(args,key,value.resolve())
    args.output = (args.output or root/('reviewer-v8-targeted-feature-cache-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))).resolve()
    try:
        run(args)
    except Exception as error:
        ap.exit(2,f'V8 targeted feature collection stopped: {error}\n')


if __name__ == '__main__':
    main()
