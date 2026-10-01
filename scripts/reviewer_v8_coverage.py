#!/usr/bin/env python3
"""Inventory unused PE samples for reviewer category coverage; no training/scoring.

Labels come from the supplied benign/malicious input roots. Only trusted benign
inputs belong under --benign. Keep evaluation acquisition sources separate.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

import reviewer_v8_workflow as w
from defender.models.boundary_reviewer import _import_values, _build_values


def valid_sha(value):
    return len(value)==64 and all(c in '0123456789abcdef' for c in value)


def known_samples(directory):
    audit, _ = w.load_audit(directory)
    training, _ = w.merge_training(directory, audit)
    labels = {r['sha256']:r['label'] for r in training+audit}
    sources = []
    # Exclude other previously recorded evaluation/score batches too. Files
    # lacking a SHA column are unrelated and ignored.
    for path in sorted(directory.rglob('*.csv')):
        with path.open(newline='',encoding='utf-8-sig') as stream:
            reader=csv.DictReader(stream)
            if 'sha256' not in (reader.fieldnames or []):
                continue
            count=0
            for raw in reader:
                sha=str(raw.get('sha256','')).strip().lower()
                if not valid_sha(sha):
                    raise ValueError(f'Invalid SHA in recorded CSV: {path}')
                label=raw.get('label')
                if label not in (None,''):
                    if label not in ('0','1'):
                        raise ValueError(f'Invalid label in recorded CSV: {path}')
                    label=int(label)
                    if sha in labels and labels[sha] is not None and labels[sha]!=label:
                        raise ValueError(f'Conflicting recorded label for {sha}')
                    labels[sha]=label
                else:
                    labels.setdefault(sha,None)
                count+=1
            sources.append(dict(path=str(path),rows=count))
    return labels,sources


def inspect_inputs(inputs, known, source_id, role, exclude=None, extractor=None):
    import pyzipper
    if extractor is None:
        from defender.models.attribute_extractor import PEAttributeExtractor
        extractor=PEAttributeExtractor
    excluded=dict(exclude or {})
    seen, accepted, warnings, parse_errors = {},[],[],[]
    counts=Counter()
    for label,path in inputs:
        if not path.exists():
            raise ValueError(f'Missing input: {path}')
        for bytez in w.payloads(path,pyzipper.AESZipFile,on_error=warnings.append):
            sha=hashlib.sha256(bytez).hexdigest()
            if sha in seen:
                if seen[sha]!=label:
                    raise ValueError(f'Input class conflict for {sha}')
                counts['duplicate_input']+=1;continue
            seen[sha]=label
            if sha in known:
                if known[sha] is not None and known[sha]!=label:
                    raise ValueError(f'Known/input class conflict for {sha}')
                counts['previously_recorded']+=1;continue
            if sha in excluded:
                if excluded[sha] is not None and excluded[sha]!=label:
                    raise ValueError(f'Excluded/input class conflict for {sha}')
                counts['reserved_in_other_manifest']+=1;continue
            if len(bytez)>16*1024*1024:
                counts['over_size_limit']+=1;continue
            try:
                parsed=extractor(bytez)
                attrs=w.legacy_import_attributes(parsed,parsed.extract())
                imports=_import_values(attrs);build=_build_values(attrs)
                categories=[]
                if imports[-1]>0:categories.append('kernel_driver_import')
                if build[3]>0:categories.append('linker2_with_symbols')
                if build[4]>0:categories.append('linker2_symbols_no_debug_tls')
                target=bool(categories)
                accepted.append(dict(sha256=sha,label=label,source_id=source_id,role=role,
                    input_location=str(path),byte_size=len(bytez),categories=categories,
                    selected_for_development=role=='development' and target,
                    reserved_for_evaluation=role=='evaluation',
                    import_flags=list(imports),build_flags=list(build),
                    attributes={k:attrs.get(k) for k in ('libraries','machine','major_linker_version','minor_linker_version','symbols','has_debug','has_tls','numberof_sections')}))
                counts['unused_pe']+=1
            except (ValueError,RuntimeError,AttributeError,TypeError) as error:
                parse_errors.append(dict(sha256=sha,input_location=str(path),error=str(error)))
    category_counts={}
    for category in ('kernel_driver_import','linker2_with_symbols','linker2_symbols_no_debug_tls','other'):
        rows=[r for r in accepted if (category in r['categories'] if category!='other' else not r['categories'])]
        category_counts[category]=dict(benign=sum(r['label']==0 for r in rows),malicious=sum(r['label']==1 for r in rows))
    return dict(source_id=source_id,role=role,complete=not warnings and not parse_errors,
        scope='Disjoint from recorded reviewer development/evaluation SHA pools and supplied manifests. Does not establish absence from upstream legacy/base training or malware-family independence.',
        counts=dict(counts),category_counts=category_counts,archive_warnings=warnings,
        parse_errors=parse_errors,samples=accepted)


def load_exclusions(paths, source_id):
    labels={}
    for path in paths:
        manifest=json.loads(path.read_text(encoding='utf-8'))
        if manifest.get('source_id')==source_id:
            raise ValueError('Acquisition source already used in excluded manifest; use an independent source')
        for row in manifest.get('samples',[]):
            sha=row['sha256'];label=row['label']
            if sha in labels and labels[sha]!=label:
                raise ValueError('Excluded manifests have conflicting labels')
            labels[sha]=label
    return labels


def collection_provenance(inputs, source_id, role):
    import pyzipper
    import zipfile
    records=[]
    for label,path in inputs:
        if not path.is_file() or not zipfile.is_zipfile(path):
            continue
        with pyzipper.AESZipFile(str(path)) as archive:
            if 'collection-manifest.json' not in archive.namelist():
                continue
            manifest=json.loads(archive.read('collection-manifest.json',pwd=b'infected'))
            if manifest.get('source_id')!=source_id or manifest.get('role')!=role:
                raise ValueError('Collection source-id/role differs from audit arguments')
            if any(row.get('label')!=label for row in manifest.get('samples',[])):
                raise ValueError('Collection manifest label differs from benign/malicious input')
            records.append(dict(path=str(path),sample_count=manifest.get('sample_count'),
                                label_basis=manifest.get('label_basis'),roots=manifest.get('roots'),
                                read_error_count=len(manifest.get('read_errors',[])),
                                enumeration_error_count=len(manifest.get('enumeration_errors',[]))))
    return records


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--benign',type=Path,nargs='+',default=[])
    ap.add_argument('--malicious',type=Path,nargs='+',default=[])
    ap.add_argument('--source-id',required=True)
    ap.add_argument('--role',choices=('development','evaluation'),default='development')
    ap.add_argument('--reports-dir',type=Path,default=w.ROOT/'validation-data')
    ap.add_argument('--exclude-manifest',type=Path,action='append',default=[])
    ap.add_argument('--output',type=Path,default=w.ROOT/'validation-data/reviewer-v8-coverage-development')
    args=ap.parse_args()
    try:
        if not args.benign and not args.malicious:
            raise ValueError('Supply at least one benign or malicious input')
        if args.role=='evaluation' and not args.exclude_manifest:
            raise ValueError('Evaluation collection requires --exclude-manifest pointing to the development coverage manifest')
        if (args.output/'coverage-manifest.json').exists():
            raise ValueError('Output manifest exists; use a new --output directory')
        known,recorded=known_samples(args.reports_dir)
        exclusions=load_exclusions(args.exclude_manifest,args.source_id)
        inputs=[(0,p) for p in args.benign]+[(1,p) for p in args.malicious]
        provenance=collection_provenance(inputs,args.source_id,args.role)
        result=inspect_inputs(inputs,
                              known,args.source_id,args.role,exclusions)
        result['recorded_sha_count']=len(known);result['recorded_csv_inputs']=recorded
        result['collection_provenance']=provenance
        candidates=(w.ROOT/'defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json',
                    w.ROOT/'validation-data/reviewer-v8-import-features-development/model.json',
                    w.ROOT/'validation-data/reviewer-v8-followup-development/imports-interval_midpoint-model.json')
        if any(not p.is_file() for p in candidates):
            raise ValueError('Missing frozen comparison candidate; complete v8 experiments before collection audit')
        result['frozen_candidate_sha256']={str(p.relative_to(w.ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in candidates}
        result['input_files']=[str(p) for p in args.benign+args.malicious]
        summary={k:v for k,v in result.items() if k not in ('samples','recorded_csv_inputs')}
        w.dump(args.output/'coverage-manifest.json',result)
        w.dump(args.output/'coverage-summary.json',summary)
        print(json.dumps(summary,indent=2))
        print(f'Send coverage-summary.json from {args.output}. No model trained or sample executed.')
        if not result['complete']:
            ap.exit(2,'Inventory incomplete: archive/parser failures recorded; do not treat this as a complete clean pool.\n')
    except (ValueError,OSError,ImportError,RuntimeError,KeyError) as error:
        ap.exit(2,f'V8 coverage audit stopped: {error}\n')


if __name__=='__main__':
    main()
