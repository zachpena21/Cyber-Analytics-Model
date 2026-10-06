#!/usr/bin/env python3
"""Matched grouped development ablations of section/import/managed PE features.

All included acquisitions are development data. No frozen models are changed.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import itertools
import json
from pathlib import Path
import traceback

import numpy as np
import reviewer_v8_group_diagnostics as d
import reviewer_v8_rich_feature_cache as cache

a, c, g, s = d.a, d.c, d.g, d.s
rich = cache.rich
VARIANTS = ('structural_control', 'plus_sections', 'plus_imports', 'plus_managed', 'plus_all')
ADDITIONS = dict(structural_control=(), plus_sections=('sections',), plus_imports=('imports',),
                 plus_managed=('managed',), plus_all=('sections', 'imports', 'managed'))
POLICIES = ('ordinary', 'software', 'fixed')
# Count/flag shape grouping deliberately omits timestamps, byte lengths, entropy,
# raw/virtual size ratios, URL densities and CLR metadata size. No label or score.
SHAPE_NAMES = ('pe_header_valid', 'section_table_valid', 'section_executable_count',
               'section_writable_count', 'section_wx_count', 'section_zero_raw_count',
               'section_uninitialized_count') + rich.IMPORT_NAMES + tuple(
                   n for n in rich.MANAGED_NAMES if n != 'clr_metadata_size_to_file_ratio')


def find_cache(root):
    matches = []
    for path in root.glob('reviewer-v8-rich-feature-cache-*'):
        marker = path / 'rich-feature-summary.json'
        if marker.is_file() and cache.read(marker).get('complete') is True:
            matches.append(path)
    if not matches:
        raise ValueError('No completed rich feature cache; pass --cache')
    return max(matches, key=lambda p:(p.joinpath('rich-feature-summary.json').stat().st_mtime_ns, str(p)))


def validate_cache(directory, entries, names, converted):
    baseline = cache.read(directory / 'development-input-cache.json')
    extra = cache.read(directory / 'rich-feature-cache.json')
    report = cache.read(directory / 'rich-feature-summary.json')
    identity = cache.read(directory / 'collection-inputs.json')
    if any(doc.get('complete') is not True for doc in (baseline, extra, report)):
        raise ValueError('Rich feature collection incomplete')
    cache.verify_hashes(identity['input_sha256'])
    for module in (rich, cache):
        if identity['input_sha256'].get(str(Path(module.__file__))) != cache.digest(module.__file__):
            raise ValueError('Collection parser/collector binding missing or changed')
    if (baseline['feature_names'] != names or baseline['samples'] != entries
            or identity['baseline_feature_names'] != names
            or identity['feature_names'] != list(rich.FEATURE_NAMES)
            or identity['parser_version'] != rich.VERSION
            or identity['sample_sha256'] != sorted(entries)
            or extra['feature_names'] != list(rich.FEATURE_NAMES)
            or extra['blocks'] != {k:list(v) for k,v in rich.BLOCKS.items()}
            or set(extra['samples']) != set(entries)
            or cache.read(directory / 'excluded-sha256.json') != sorted(entries)):
        raise ValueError('Rich cache differs from reproduced baseline/schema/SHA coverage')
    features = extra['samples']
    for sha, feature in features.items():
        cache.validate_feature(feature)
        start = len(rich.SECTION_NAMES)
        if (feature['raw_sha256'] != sha or not 0 < feature['byte_size'] <= 16*1024*1024
                or feature['values'][start:start+len(rich.IMPORT_NAMES)] != rich.import_values(entries[sha]['libraries'])
                or (entries[sha].get('byte_size') is not None and feature['byte_size'] != entries[sha]['byte_size'])):
            raise ValueError('Rich cache byte/import identity differs: ' + sha)
    expected_labels = dict(Counter('malware' if e['record']['label'] else 'benign' for e in entries.values()))
    if (report['sample_count'] != len(entries) or report['labels'] != expected_labels
            or report['by_source'] != dict(Counter(e['record']['source'] for e in entries.values()))
            or report['parser_status'] != dict(Counter(f['status'] for f in features.values()))
            or report['converted_sha256'] != converted or report['new_development_samples'] != len(converted)
            or report['prior_development_samples'] != len(entries)-len(converted)
            or report['required_sha_coverage_complete'] is not True
            or report['archive_warning_count'] != len(cache.read(directory/'archive-read-warnings.json'))
            or report['training'] is not False or report['threshold_tuning'] is not False):
        raise ValueError('Rich summary does not match its caches')
    hashes = dict(identity['input_sha256'])
    for filename in ('collection-inputs.json', 'development-input-cache.json', 'rich-feature-cache.json',
                     'rich-feature-summary.json', 'excluded-sha256.json', 'archive-read-warnings.json'):
        path = directory / filename
        hashes[str(path)] = cache.digest(path)
    return features, hashes


def matrices(entries, names, features):
    keys = sorted(entries)
    # The control is the existing structural-only 66-feature schema: discard all
    # six upstream score/signature indicators and append the six driver flags.
    base_schema = names[6:] + list(g.f.t.e.IMPORT_FEATURES)
    base = np.asarray([entries[k]['feature_vector'][6:] + list(map(float,
        g.f.t.e._import_values({'libraries':entries[k]['libraries']}))) for k in keys], dtype=float)
    extra = np.asarray([features[k]['values'] for k in keys], dtype=float)
    result = {}
    for variant in VARIANTS:
        added = [n for block in ADDITIONS[variant] for n in rich.BLOCKS[block]]
        indices = [rich.FEATURE_NAMES.index(n) for n in added]
        X = np.c_[base, extra[:,indices]] if indices else base.copy()
        schema = base_schema + added
        if X.shape != (len(keys), len(schema)) or not np.isfinite(X).all() or len(schema) != len(set(schema)):
            raise ValueError('Invalid ablation matrix/schema: ' + variant)
        result[variant] = X, schema
    return result


def shape_fingerprint(entry, names, feature):
    values = dict(zip(rich.FEATURE_NAMES, feature['values']))
    shape = [g.structural_template(entry, names), [values[n] for n in SHAPE_NAMES]]
    return hashlib.sha256(json.dumps(shape, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def matched_groups(entries, names, features, mode):
    prior = s.stable_groups(entries, names, mode)
    parent = {k:k for k in entries}
    def find(k):
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k
    seen = {}
    for sha in sorted(entries):
        for tag in (('prior_group', prior[sha]), ('rich_shape', shape_fingerprint(entries[sha], names, features[sha]))):
            if tag in seen:
                x,y = find(sha), find(seen[tag])
                parent[max(x,y)] = min(x,y)
            seen[tag] = sha
    return {k:find(k) for k in entries}


def make_plan(entries, names, features, mode, output):
    keys = sorted(entries)
    rows = [entries[k]['record'] for k in keys]
    groups = matched_groups(entries, names, features, mode)
    fingerprints = {k:s.stable_fingerprint(entries[k], names) for k in keys}
    shapes = {k:shape_fingerprint(entries[k], names, features[k]) for k in keys}
    overview = c.group_overview(entries, groups)
    cache.dump(output / 'group-overview.json', overview)
    cache.dump(output / 'grouping-audit.json', dict(mode=mode, sample_count=len(keys),
        group_count=len(overview), prior_group_count=len(set(s.stable_groups(entries,names,mode).values())),
        rich_shape_count=len(set(shapes.values())),
        largest_groups=[dict(group=k,**v) for k,v in sorted(overview.items(),key=lambda x:-x[1]['count'])[:15]],
        grouping_rule='Union prior entropy-invariant panel groups with coarse build+section/import/CLR shapes. These are conservative split links, not verified malware families.'))
    fold_ids = g.group_folds(rows, groups, 5)
    plan = s.split_plan(rows, groups, fingerprints, fold_ids, entries)
    manifest = dict(role='rich_feature_development', mode=mode, seed=g.SEED, groups=groups, folds=[])
    for fold in plan:
        roles = [fold[k] for k in ('fit','calibration','held')]
        c.assert_split(rows, groups, roles)
        for lookup in (fingerprints, shapes):
            tags = [{lookup[rows[i]['sha256']] for i in ids} for ids in roles]
            if any(x & y for x,y in itertools.combinations(tags,2)):
                raise ValueError('Representation/build-shape crossed split roles')
        manifest['folds'].append({k:([rows[i]['sha256'] for i in v] if k in ('fit','calibration','held') else v)
                                 for k,v in fold.items()})
    held = [sha for fold in manifest['folds'] for sha in fold['held']]
    if len(held) != len(keys) or set(held) != set(keys):
        raise ValueError('Plan must hold every SHA exactly once')
    cache.dump(output / 'split-manifest.json', manifest)
    return groups, plan


def software_rates(rows, pred, entries):
    return {name:dict(count=len(ids), fp=int(pred[ids].sum()), fpr=float(pred[ids].mean()))
            for name,ids in s.software_ids(rows,entries).items()}


def panel(entries, names, features, converted, output, mode, groups, plan):
    keys = sorted(entries)
    rows = [entries[k]['record'] for k in keys]
    data = matrices(entries, names, features)
    summary = dict(complete=False, role='matched_rich_feature_development', mode=mode,
                   sample_count=len(keys), group_count=len(set(groups.values())), configuration=g.f.w.CONFIG,
                   seed=g.SEED, route_min=g.ROUTE, adapter_threshold=g.ADAPTER_THRESHOLD,
                   variants={}, paired_vs_control={},
                   limitations='Post-hoc development. No independent validation or final refit. Approximately 40% fit/40% calibration/20% held per fold. New pool and conservative links prevent direct score parity with older fits. Fixed threshold is diagnostic; upstream base/adapter historical overlap remains.')
    scores_by_variant = {}
    converted = set(converted)
    for variant in VARIANTS:
        X,schema = data[variant]
        records,folds = [],[]
        for fold in plan:
            n = fold['fold']
            print(f'{mode} {variant} fold {n+1}/5: fit={len(fold["fit"])}, calibration={len(fold["calibration"])}, held={len(fold["held"])}', flush=True)
            fr,cr,hr = ([rows[i] for i in fold[k]] for k in ('fit','calibration','held'))
            clf = g.fit_model(X[fold['fit']], fr)
            cp = clf.predict_proba(X[fold['calibration']])[:,1]
            hp = clf.predict_proba(X[fold['held']])[:,1]
            policies = dict(ordinary=g.calibration(cr,cp,lambda t:g.gated(cr,cp,t)),
                            software=s.software_calibration(cr,cp,entries))
            policies = {k:c.assess_policy(v,fold['calibration_diversity']) for k,v in policies.items()}
            preds = {k:g.gated(hr,hp,v['threshold']) for k,v in policies.items()}
            preds['fixed'] = g.gated(hr,hp,g.REFERENCE_THRESHOLD)
            parity = g.export_checked(clf,schema,policies['software']['threshold'],X,
                                      output/variant/f'fold-{n:02d}-model.json')
            folds.append(dict(fold=n, calibration=policies, calibration_diversity=fold['calibration_diversity'],
                              calibration_software=fold['calibration_software'], export_parity=parity,
                              held={k:dict(**d.group_metrics(hr,pred,groups),
                                           software_benign=software_rates(hr,pred,entries)) for k,pred in preds.items()}))
            for i,row in enumerate(hr):
                records.append(dict(sha256=row['sha256'], label=row['label'], source=row['source'],
                                    group=groups[row['sha256']], fold=n, reviewer_score=float(hp[i]),
                                    **{k+'_prediction':int(pred[i]) for k,pred in preds.items()}))
            summary['variants'][variant] = dict(complete=False, feature_count=len(schema), features=schema,
                                               added_blocks=list(ADDITIONS[variant]), folds=folds)
            cache.dump(output / 'rich-ablation-summary.json', summary)
            cache.dump(output / variant / 'development-scores.json', records)
        if len(records) != len(keys) or {r['sha256'] for r in records} != set(keys):
            raise ValueError('Variant held SHA coverage failed: ' + variant)
        lookup = {r['sha256']:r for r in records}
        ordered = [lookup[k] for k in keys]
        pooled = {}
        fresh_ids = np.asarray([i for i,k in enumerate(keys) if k in converted],dtype=int)
        for policy in POLICIES:
            pred = np.asarray([r[policy+'_prediction'] for r in ordered])
            pooled[policy] = dict(**d.group_metrics(rows,pred,groups),
                                 software_benign=software_rates(rows,pred,entries),
                                 by_source=d.indexed_rates(rows,pred,groups)['by_source'],
                                 newly_converted=g.f.w.metrics([rows[i] for i in fresh_ids],pred[fresh_ids]) if len(fresh_ids) else None)
        summary['variants'][variant].update(complete=True, pooled=pooled,
            all_policies_eligible={k:all(f['calibration'][k]['eligible_development_policy'] for f in folds)
                                  for k in ('ordinary','software')})
        scores_by_variant[variant] = lookup
        print(f'  {variant} software policy: {json.dumps(pooled["software"]["sample_metrics"])}',flush=True)
        cache.dump(output / 'rich-ablation-summary.json', summary)
    for variant in VARIANTS[1:]:
        summary['paired_vs_control'][variant] = {}
        for policy in POLICIES:
            before = np.asarray([scores_by_variant['structural_control'][k][policy+'_prediction'] for k in keys])
            after = np.asarray([scores_by_variant[variant][k][policy+'_prediction'] for k in keys])
            paired = a.paired(rows,before,after)
            if len(fresh_ids):
                paired['newly_converted'] = a.paired([rows[i] for i in fresh_ids],before[fresh_ids],after[fresh_ids])['overall']
            summary['paired_vs_control'][variant][policy] = paired
    summary['complete'] = True
    cache.dump(output / 'rich-ablation-summary.json', summary)
    return summary


def run(args):
    import reviewer_v8_structural_validation as v
    import reviewer_v8_structural_feature_diagnostics as diagnostic
    import reviewer_v8_fresh_error_audit as audit
    args.cache = args.cache or find_cache(args.root)
    identity = cache.read(args.cache / 'collection-inputs.json')
    markers = [Path(p) for p in identity['input_sha256'] if Path(p).name == 'diagnostic-inputs.json']
    if len(markers) != 1:
        raise ValueError('Cache must bind one diagnostic input manifest')
    args.diagnostics = markers[0].parent
    entries,names,_,converted,_,_ = cache.load_development(args,g,v,diagnostic,audit)
    features,hashes = validate_cache(args.cache,entries,names,converted)
    modules = (d,d.p,a,c,g,s,cache,rich,v,diagnostic,audit)
    for module in modules:
        hashes[str(Path(module.__file__))] = cache.digest(module.__file__)
    hashes[str(Path(__file__))] = cache.digest(__file__)
    g.f.fresh_output(args.output)
    cache.dump(args.output/'inputs.json', dict(role='development', rich_cache=str(args.cache), input_sha256=hashes,
        converted_acquisition_sha256=converted, modes=args.mode, variants=list(VARIANTS),
        grouping_shape_features=list(SHAPE_NAMES), configuration=g.f.w.CONFIG, seed=g.SEED,
        dependency_versions={name:importlib.metadata.version(name) for name in ('numpy','scikit-learn','scipy')},
        threshold_policy='Max calibration recall subject to <=1% overall/source FPR; software policy also caps identified software groups. Five outer folds, two calibration folds chosen by counts/provenance only.'))
    cache.dump(args.output/'excluded-sha256.json',sorted(entries))
    # Preflight every requested panel before fitting any model.
    plans = {mode:make_plan(entries,names,features,mode,args.output/mode) for mode in args.mode}
    combined = dict(complete=False, role='matched_rich_feature_development', sample_count=len(entries),
                    rich_cache=str(args.cache), new_development_samples=len(converted), modes={},
                    deployment_changed=False, final_refit=False, independent_validation=False)
    for mode,(groups,plan) in plans.items():
        result = panel(entries,names,features,converted,args.output/mode,mode,groups,plan)
        combined['modes'][mode] = dict(group_count=result['group_count'],
            variants={k:dict(feature_count=r['feature_count'], all_policies_eligible=r['all_policies_eligible'],
                              pooled=r['pooled'], export_max_abs_error=max(f['export_parity'] for f in r['folds']))
                      for k,r in result['variants'].items()},
            paired_vs_control={k:{p:dict(overall=r['overall'], newly_converted=r.get('newly_converted'))
                                 for p,r in policies.items()} for k,policies in result['paired_vs_control'].items()})
        cache.dump(args.output/'rich-ablation-comparison-summary.json',combined)
    cache.verify_hashes(hashes)
    v.load_bundle(args.structural_bundle)
    combined['complete'] = True
    cache.dump(args.output/'rich-ablation-comparison-summary.json',combined)
    print(f'Complete: {args.output}\nSend rich-ablation-comparison-summary.json.',flush=True)


def main():
    root = Path(__file__).resolve().parents[1]/'validation-data'
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cache',type=Path,help='Default: newest completed rich feature collection')
    ap.add_argument('--bundle',type=Path,default=root/'reviewer-v8-frozen-validation')
    ap.add_argument('--structural-bundle',type=Path,default=root/'reviewer-v8-structural-frozen-validation')
    ap.add_argument('--training-cache',type=Path,default=root/'reviewer-v8-docker-audit/docker-feature-cache.json')
    ap.add_argument('--fresh-audit',type=Path,action='append')
    ap.add_argument('--fresh-comparison',type=Path,action='append')
    ap.add_argument('--mode',choices=c.MODES,action='append',help='Default: provenance and template panels')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-rich-ablation-development-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    ap.add_argument('--debug',action='store_true')
    args = ap.parse_args()
    args.root = root
    args.mode = args.mode or list(c.MODES)
    if len(args.mode) != len(set(args.mode)):
        ap.error('Do not repeat a grouping mode')
    args.bundle = args.bundle.resolve()
    args.structural_bundle = args.structural_bundle.resolve()
    args.fresh_audit = args.fresh_audit or [root/'reviewer-v8-fresh-error-audit',root/'reviewer-v8-fresh-git-error-audit']
    args.fresh_comparison = args.fresh_comparison or [root/'reviewer-v8-fresh-evaluation',root/'reviewer-v8-fresh-git-evaluation']
    try:
        run(args)
    except Exception as error:
        if args.debug:
            traceback.print_exc()
        ap.exit(2,f'V8 rich ablation stopped: {error}\n')


if __name__ == '__main__':
    main()
