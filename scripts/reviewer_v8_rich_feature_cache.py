#!/usr/bin/env python3
"""Collect section/import/CLR features for the next grouped v8 development experiment.

No API calls, sample execution, fitting, threshold changes, or frozen-bundle edits.
The previously inspected structural evaluation is now development data.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

import reviewer_v8_rich_features as rich


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def verify_hashes(hashes):
    for path, expected in hashes.items():
        if digest(path) != expected:
            raise ValueError('Input changed: ' + path)


def find_diagnostics(root, bundle):
    key = str(bundle / 'freeze-manifest.json')
    expected = digest(key)
    matches = []
    for path in root.glob('reviewer-v8-structural-feature-diagnostics-*'):
        marker = path / 'diagnostic-inputs.json'
        summary = path / 'feature-diagnostic-summary.json'
        cache = path / 'feature-cache.json'
        if marker.is_file() and summary.is_file() and cache.is_file():
            record = read(marker)
            if (record.get('complete') is True and read(summary).get('complete') is True
                    and record.get('input_sha256', {}).get(key) == expected):
                matches.append(path)
    if not matches:
        raise ValueError('No completed matching feature diagnostics; pass --diagnostics')
    return max(matches, key=lambda p: (p.joinpath('feature-diagnostic-summary.json').stat().st_mtime_ns, str(p)))


def validate_feature(feature):
    values = feature['values']
    if (len(values) != len(rich.FEATURE_NAMES)
            or not all(type(x) in (float, int) and math.isfinite(x) for x in values)
            or feature['status'] not in ('invalid_pe_header', 'invalid_section_table',
                                         'parsed', 'parsed_with_raw_bounds_errors')):
        raise ValueError('Invalid rich feature schema/status')


def collect(paths, entries, payloads, reader, features, warnings, checkpoint):
    """SHA matching is authoritative; every requested sample must be recovered."""
    wanted = set(entries) - set(features)
    if not wanted:
        return wanted
    for path in paths:
        for bytez in payloads(path, reader, on_error=warnings.append):
            if len(bytez) > 16 * 1024 * 1024:
                continue
            sha = hashlib.sha256(bytez).hexdigest()
            if sha not in wanted:
                continue
            feature = rich.extract(bytez, entries[sha]['libraries'])
            validate_feature(feature)
            feature.update(raw_sha256=sha, byte_size=len(bytez), location=str(path))
            features[sha] = feature
            wanted.remove(sha)
            if len(features) % 100 == 0:
                print(f'Collected rich features {len(features)}/{len(entries)}', flush=True)
                checkpoint()
        if not wanted:
            break
    return wanted


def candidate_files(roots):
    """Read only file signatures; never load large JSON/report files as payloads."""
    seen = set()
    for root in roots:
        if not root.exists():
            raise ValueError('Missing scan root: ' + str(root))
        paths = sorted(root.rglob('*')) if root.is_dir() else [root]
        for path in paths:
            if not path.is_file() or path.is_symlink():
                continue
            canonical = path.resolve()
            if canonical in seen:
                continue
            seen.add(canonical)
            with path.open('rb') as stream:
                header = stream.read(2)
            if header in (b'MZ', b'PK'):
                yield path


def load_development(args, g, v, diagnostic, audit):
    if len(args.fresh_audit) != len(args.fresh_comparison):
        raise ValueError('Each fresh audit needs a matching comparison')
    entries, names, hashes, previously_converted = g.load_inputs(args)
    manifest, structural, bounded, legacy, excluded = v.load_bundle(args.structural_bundle)
    if set(entries) != excluded:
        raise ValueError('Existing development cache differs from structural frozen exclusions')
    marker = read(args.diagnostics / 'diagnostic-inputs.json')
    summary = read(args.diagnostics / 'feature-diagnostic-summary.json')
    cache = read(args.diagnostics / 'feature-cache.json')
    if (marker.get('complete') is not True or summary.get('complete') is not True
            or cache.get('complete') is not True or marker.get('threshold_tuning') is not False):
        raise ValueError('Feature diagnostics incomplete')
    verify_hashes(marker['input_sha256'])
    freeze_path = str(args.structural_bundle / 'freeze-manifest.json')
    if marker['input_sha256'].get(freeze_path) != digest(freeze_path):
        raise ValueError('Diagnostics belong to a different structural freeze')
    evaluation = Path(marker['evaluation'])
    evaluation_path = evaluation / 'evaluation-manifest.json'
    scores_path = evaluation / 'comparison-scores.json'
    for path in (evaluation_path, scores_path):
        if marker['input_sha256'].get(str(path)) != digest(path):
            raise ValueError('Diagnostics do not bind original evaluation: ' + str(path))
    original = read(evaluation_path)
    if (original.get('complete') is not True or original.get('threshold_tuning') is not False
            or original['freeze_manifest_sha256'] != digest(freeze_path)):
        raise ValueError('Need the completed frozen evaluation')
    saved = diagnostic.unique_records(read(scores_path))
    rows = diagnostic.unique_records(cache['scores'])
    samples = diagnostic.unique_records(original['samples'])
    source_paths = [Path(p) for p in marker['input_sha256'] if Path(p).name == 'sources.json']
    if len(source_paths) != 1:
        raise ValueError('Diagnostics must bind one sources manifest')
    sources = read(source_paths[0])
    provenance = audit.provenance(sources)
    if not set(rows) <= set(provenance):
        raise ValueError('Missing per-sample software/acquisition provenance')
    # Preserve package and hourly-batch identities for the next grouped splits.
    for source in sources:
        path = Path(source['path'])
        metadata = path / 'collection-summary.json' if path.is_dir() else path
        hashes[str(metadata)] = digest(metadata)
    expected_schema = names + list(g.f.t.e.IMPORT_FEATURES)
    if (cache['feature_names'] != expected_schema or set(rows) != set(saved)
            or set(rows) != set(samples) or set(rows) != set(cache['samples'])
            or len(rows) != summary['sample_count'] or set(rows) & set(entries)):
        raise ValueError('New cache schema/SHA coverage/overlap differs')
    # Replay frozen structural and bounded models in batches, with strict score/gate checks.
    keys = sorted(rows)
    X = [cache['samples'][sha]['vector'][6:] for sha in keys]
    base = g.exported_scores(structural, X)
    corrected, offsets = v.b.exported_scores(bounded, X, [rows[k] for k in keys])
    for i, sha in enumerate(keys):
        row, feature, sample = rows[sha], cache['samples'][sha], samples[sha]
        diagnostic.verify_row(saved[sha], row)
        vector = feature['vector']
        if (row['label'] != sample['label'] or row['source'] != sample['source_id']
                or len(vector) != len(expected_schema) or not all(math.isfinite(x) for x in vector)
                or vector[66:] != list(map(float, g.f.t.e._import_values({'libraries': feature['libraries']})))):
            raise ValueError('New cache provenance/features differ: ' + sha)
        entry = dict(record=row, feature_vector=vector[:66], libraries=feature['libraries'],
                     provenance=provenance[sha], input_location=sample['input_location'],
                     byte_size=sample['byte_size'])
        g.checked_entry(sha, entry, names, legacy, historical=False)
        for name, score in ((v.PRIMARY, float(base[i])), (v.COMPARISON, float(corrected[i]))):
            threshold = manifest['models'][name]['threshold']
            pred = int(g.gated([row], [score], threshold)[0])
            if (abs(score - row[name + '_score']) > 1e-9
                    or row[name + '_routed'] != (row['adapter_probability'] >= g.ROUTE)
                    or pred != row[name + '_prediction']):
                raise ValueError('New cache frozen score/gate parity failed: ' + sha)
        if abs(float(offsets[i]) - row['bounded_logit_correction']) > 1e-9:
            raise ValueError('Bounded correction parity failed: ' + sha)
        entries[sha] = entry
    hashes.update(marker['input_sha256'])
    for filename in ('diagnostic-inputs.json', 'feature-diagnostic-summary.json', 'feature-cache.json'):
        path = args.diagnostics / filename
        hashes[str(path)] = digest(path)
    return entries, names, hashes, keys, previously_converted, samples


def run(args):
    import pyzipper
    import reviewer_v8_grouped_experiment as g
    import reviewer_v8_structural_validation as v
    import reviewer_v8_structural_feature_diagnostics as diagnostic
    import reviewer_v8_fresh_error_audit as audit
    args.diagnostics = args.diagnostics or find_diagnostics(args.root, args.structural_bundle)
    entries, names, hashes, converted, previous, new_samples = load_development(args, g, v, diagnostic, audit)
    for module in (rich, g, v, diagnostic, audit):
        hashes[str(Path(module.__file__))] = digest(module.__file__)
    hashes[str(Path(__file__))] = digest(__file__)
    identity = dict(role='development_feature_collection', input_sha256=hashes,
                    scan_roots=[str(p) for p in args.scan_root],
                    feature_names=list(rich.FEATURE_NAMES), baseline_feature_names=names,
                    parser_version=rich.VERSION, sample_sha256=sorted(entries))
    features, warnings = {}, []
    if args.resume:
        args.output = args.resume
        if read(args.output / 'collection-inputs.json') != identity:
            raise ValueError('Resume inputs/configuration changed; use a new output directory')
        partial = read(args.output / 'partial-rich-feature-cache.json')
        features = partial['samples']
        warnings = read(args.output / 'archive-read-warnings.json')
        if not set(features) <= set(entries):
            raise ValueError('Resume has unexpected SHAs')
        for sha, feature in features.items():
            validate_feature(feature)
            if (feature['raw_sha256'] != sha or not 0 < feature['byte_size'] <= 16 * 1024 * 1024
                    or feature['values'][len(rich.SECTION_NAMES):len(rich.SECTION_NAMES)+len(rich.IMPORT_NAMES)]
                    != rich.import_values(entries[sha]['libraries'])):
                raise ValueError('Invalid resume sample: ' + sha)
    else:
        if args.output.exists() and any(args.output.iterdir()):
            raise ValueError('Output is not empty; pass --resume with that directory or use a new one')
        dump(args.output / 'collection-inputs.json', identity)
    def checkpoint():
        dump(args.output / 'partial-rich-feature-cache.json', dict(complete=False, samples=features))
        dump(args.output / 'archive-read-warnings.json', warnings)
    checkpoint()
    print(f'Output: {args.output}\nCollecting {len(entries)} development SHAs; newly converted: {len(converted)}', flush=True)
    try:
        missing = collect(candidate_files(args.scan_root), entries, v.w.payloads, pyzipper.AESZipFile,
                          features, warnings, checkpoint)
    finally:
        checkpoint()
    dump(args.output / 'missing-sha256.json', sorted(missing))
    if missing:
        raise ValueError(f'Missing raw bytes for {len(missing)} required SHAs; see missing-sha256.json. '
                         'Add source locations with --scan-root and use a new output, or restore bytes under the original roots and resume.')
    for sha, sample in new_samples.items():
        if features[sha]['byte_size'] != sample['byte_size']:
            raise ValueError('New sample byte size differs: ' + sha)
    for sha, entry in entries.items():
        if entry.get('byte_size') is not None and features[sha]['byte_size'] != entry['byte_size']:
            raise ValueError('Baseline sample byte size differs: ' + sha)
    verify_hashes(hashes)
    v.load_bundle(args.structural_bundle)
    dump(args.output / 'development-input-cache.json', dict(complete=True, feature_names=names, samples=entries))
    dump(args.output / 'rich-feature-cache.json', dict(complete=True, feature_names=list(rich.FEATURE_NAMES),
                                                    blocks={k:list(n) for k,n in rich.BLOCKS.items()}, samples=features))
    dump(args.output / 'excluded-sha256.json', sorted(entries))
    report = dict(complete=True, role='development_feature_collection', training=False,
                  threshold_tuning=False, sample_count=len(entries), new_development_samples=len(converted),
                  prior_development_samples=len(entries)-len(converted),
                  labels=dict(Counter('malware' if e['record']['label'] else 'benign' for e in entries.values())),
                  by_source=dict(Counter(e['record']['source'] for e in entries.values())),
                  parser_status=dict(Counter(e['status'] for e in features.values())),
                  rich_feature_count=len(rich.FEATURE_NAMES), blocks={k:len(n) for k,n in rich.BLOCKS.items()},
                  archive_warning_count=len(warnings), required_sha_coverage_complete=True,
                  converted_sha256=converted, earlier_converted_count=len(previous),
                  interpretation='All included acquisitions are development data. This cache is not an independent evaluation. CLR flags are header claims, not signature verification.')
    dump(args.output / 'rich-feature-summary.json', report)
    print(f'Complete: {args.output}\nSend rich-feature-summary.json. No models were fitted.', flush=True)


def main():
    root = Path(__file__).resolve().parents[1] / 'validation-data'
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle', type=Path, default=root / 'reviewer-v8-frozen-validation')
    ap.add_argument('--structural-bundle', type=Path, default=root / 'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--training-cache', type=Path, default=root / 'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit', type=Path, action='append')
    ap.add_argument('--fresh-comparison', type=Path, action='append')
    ap.add_argument('--diagnostics', type=Path, help='Default: newest completed matching diagnostics')
    ap.add_argument('--scan-root', type=Path, action='append', help='Repeat for sample files/directories; default validation-data')
    ap.add_argument('--output', type=Path)
    ap.add_argument('--resume', type=Path, help='Resume interrupted collection in this output directory')
    args = ap.parse_args()
    args.root = root
    args.scan_root = [p.resolve() for p in (args.scan_root or [root])]
    args.bundle = args.bundle.resolve()
    args.structural_bundle = args.structural_bundle.resolve()
    if args.diagnostics:
        args.diagnostics = args.diagnostics.resolve()
    args.fresh_audit = args.fresh_audit or [root / 'reviewer-v8-fresh-error-audit', root / 'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison = args.fresh_comparison or [root / 'reviewer-v8-fresh-evaluation', root / 'reviewer-v8-fresh-git-evaluation']
    if args.output and args.resume:
        ap.error('Use either --output or --resume')
    args.output = args.output or root / ('reviewer-v8-rich-feature-cache-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f'))
    try:
        run(args)
    except Exception as error:
        ap.exit(2, f'V8 rich feature collection stopped: {error}\n')


if __name__ == '__main__':
    main()
