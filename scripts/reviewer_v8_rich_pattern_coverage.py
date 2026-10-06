#!/usr/bin/env python3
"""Recover blocker archive names and describe original fit/calibration coverage."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import traceback
import zipfile
import numpy as np
import reviewer_v8_rich_blocker_profile as b

r,g,cache=b.r,b.g,b.cache


def patterns(values,libraries):
    """Post-hoc descriptive strata; never routing rules or class assignments."""
    clr=values['clr_metadata_signature_valid']==1
    size=values['byte_size'];libs=set(libraries.lower().split())
    return dict(tiny_managed=bool(clr and size<=8192 and values['numberof_sections']<=3 and len(libs)<=1),
        large_sparse_import_native=bool(not clr and 10*1024*1024<=size<=20*1024*1024
                                       and 8<=values['numberof_sections']<=10 and len(libs)<=1),
        managed_no_cached_imports=bool(clr and not libs and 64*1024<=size<=512*1024))


def named_archive_payloads(archive,reader,warnings,origin,depth=0):
    if depth>5:
        warnings.append(dict(archive=origin,error='NestedDepthLimit'));return
    for entry in archive.infolist():
        if entry.filename.endswith('/'):continue
        member=entry.filename or '<empty-name>'
        chain=origin+'!/'+member
        if entry.file_size>256*1024*1024:
            warnings.append(dict(archive=origin,member=entry.filename,error='MemberSizeLimit'));continue
        try:
            data=archive.read(entry,pwd=b'infected')
            if data[:2]==b'MZ':
                if len(data)<=16*1024*1024:
                    yield data,chain,entry.filename,bool(entry.filename)
                continue
            stream=io.BytesIO(data)
            if zipfile.is_zipfile(stream):
                stream.seek(0)
                with reader(stream) as nested:
                    yield from named_archive_payloads(nested,reader,warnings,chain,depth+1)
        except Exception as e:
            warnings.append(dict(archive=origin,member=entry.filename,compression_method=entry.compress_type,
                                 error=type(e).__name__,message=str(e)))


def recover_names(paths,targets,reader):
    found={};warnings=[];scanned={}
    for path in paths:
        path=Path(path)
        if not path.is_file():
            warnings.append(dict(archive=str(path),error='MissingCachedLocation'));continue
        print('Recovering archive names: '+str(path),flush=True)
        scanned[str(path.resolve())]=cache.digest(path)
        try:
            with path.open('rb') as stream:header=stream.read(2)
            if header==b'MZ':
                iterator=[(path.read_bytes(),str(path),path.name,True)]
            elif zipfile.is_zipfile(path):
                archive=reader(str(path))
                try:
                    for data,chain,member,usable in named_archive_payloads(archive,reader,warnings,str(path)):
                        sha=hashlib.sha256(data).hexdigest()
                        if sha in targets:
                            found.setdefault(sha,[]).append(dict(archive=str(path),member_chain=chain,
                                member=member,usable_name=usable,byte_size=len(data),raw_sha256=sha))
                finally:archive.close()
                continue
            else:
                warnings.append(dict(archive=str(path),error='NotPEOrZIP'));continue
            for data,chain,member,usable in iterator:
                if len(data)>16*1024*1024:continue
                sha=hashlib.sha256(data).hexdigest()
                if sha in targets:found.setdefault(sha,[]).append(dict(archive=str(path),member_chain=chain,
                    member=member,usable_name=usable,byte_size=len(data),raw_sha256=sha))
        except Exception as e:
            warnings.append(dict(archive=str(path),error=type(e).__name__,message=str(e)))
    return found,warnings,scanned


def coverage(ids,keys,entries,mask,scores,threshold,groups):
    chosen=[i for i in ids if mask[i]];rows=[entries[keys[i]]['record'] for i in chosen]
    selected_scores=np.asarray([scores[i] for i in chosen],dtype=float)
    pred=g.gated(rows,selected_scores,threshold)
    result=dict(count=len(chosen),labels=dict(Counter('malware' if row['label'] else 'benign' for row in rows)),
        groups=len({groups[keys[i]] for i in chosen}),
        benign_groups=len({groups[keys[i]] for i in chosen if entries[keys[i]]['record']['label']==0}),
        malware_groups=len({groups[keys[i]] for i in chosen if entries[keys[i]]['record']['label']==1}),
        sources=dict(Counter(row['source'] for row in rows)),software=dict(Counter(g.software_group(entries[keys[i]]) or 'unidentified' for i in chosen)),
        recorded_filename_count=sum(bool(entries[keys[i]].get('original_path')) for i in chosen),
        known_resource_dll_path_count=sum(str(entries[keys[i]].get('original_path') or '').lower().endswith('.resources.dll') for i in chosen),
        benign_false_positives=int(sum(int(p)==1 and row['label']==0 for row,p in zip(rows,pred))),
        malware_detected=int(sum(int(p)==1 and row['label']==1 for row,p in zip(rows,pred))),
        role_metrics_note='Fit predictions are training diagnostics, not validation. Calibration uses the already saved threshold.')
    result['score_quantiles']=dict(zip(('min','p25','median','p75','max'),map(float,np.quantile(selected_scores,[0,.25,.5,.75,1])))) if chosen else None
    return result


def latest_profile(root):
    paths=[p for p in root.glob('reviewer-v8-rich-blocker-profile-*')
        if (p/'rich-blocker-profile-summary.json').is_file()
        and cache.read(p/'rich-blocker-profile-summary.json').get('complete') is True]
    if not paths:raise ValueError('No completed blocker profile; supply --profile')
    return max(paths,key=lambda p:((p/'rich-blocker-profile-summary.json').stat().st_mtime_ns,str(p)))


def run(args):
    import pyzipper
    profile=(args.profile or latest_profile(args.root)).resolve();binding=cache.read(profile/'inputs.json')
    cache.verify_hashes(binding['input_sha256']);cache.verify_hashes(binding['original_input_sha256'])
    audit_binding=cache.read(Path(binding['audit'])/'inputs.json')
    cache.verify_hashes(audit_binding['input_sha256']);cache.verify_hashes(audit_binding['original_input_sha256'])
    prior=cache.read(profile/'rich-blocker-profile-summary.json')
    if prior.get('complete') is not True or prior.get('held_samples_profiled') is not False:
        raise ValueError('Requires completed calibration-only blocker profile')
    source=Path(binding['source_run']);identity=cache.read(source/'inputs.json');cache.verify_hashes(identity['input_sha256'])
    directory=Path(identity['rich_cache']);baseline=cache.read(directory/'development-input-cache.json')
    entries,names=baseline['samples'],baseline['feature_names']
    features,_=r.validate_cache(directory,entries,names,identity['converted_acquisition_sha256'])
    data=r.matrices(entries,names,features);full,full_names=data['plus_all']
    keys=sorted(entries);index={sha:i for i,sha in enumerate(keys)}
    strata=[patterns(dict(zip(full_names,vector)),entries[sha]['libraries']) for sha,vector in zip(keys,full)]
    masks={name:[p[name] for p in strata] for name in strata[0]}
    panel=source/prior['mode'];manifest=cache.read(panel/'split-manifest.json')
    blockers=sorted({sha for folds in prior['variants'].values() for fold in folds for p in fold['profiles'] for sha in p['blocker_sha256']})
    if not set(blockers)<=set(entries):raise ValueError('Unknown blocker SHA')
    missing=[sha for sha in blockers if not entries[sha].get('original_path') and not entries[sha]['record'].get('path')]
    paths=sorted({features[sha]['location'] for sha in missing})
    if args.scan_root:
        paths=list(dict.fromkeys(paths+[str(p) for p in cache.candidate_files(args.scan_root)]))
    g.f.fresh_output(args.output)
    recovered,warnings,scanned=recover_names(paths,set(missing),pyzipper.AESZipFile)
    recovered_rows={}
    for sha in blockers:
        e=entries[sha];matches=recovered.get(sha,[])
        if any(m['byte_size']!=features[sha]['byte_size'] for m in matches):raise ValueError('Recovered size mismatch: '+sha)
        recovered_rows[sha]=dict(sha256=sha,label=e['record']['label'],source=e['record']['source'],
            recorded_original_path=e.get('original_path') or e['record'].get('path'),recovered_members=matches,
            software=g.software_group(e),patterns=strata[index[sha]],
            name_recovery_required=sha in missing,label_status='inherited; not independently verified')
    still_missing=[sha for sha in missing if not any(m['usable_name'] for m in recovered.get(sha,[]))]
    report=dict(complete=False,role='development_pattern_coverage_and_name_recovery',mode=prior['mode'],
        training=False,threshold_tuning=False,model_changes=False,held_samples_analyzed=False,
        unique_blockers=len(blockers),name_recovery_required=len(missing),recovered_name_count=len(missing)-len(still_missing),
        all_required_names_recovered=not still_missing,missing_name_sha256=still_missing,
        archive_warning_count=len(warnings),blockers=recovered_rows,variants={},
        pattern_rules=dict(tiny_managed='Valid CLR metadata; <=8192 bytes; <=3 sections; <=1 cached DLL import.',
            large_sparse_import_native='No valid CLR metadata; 10–20 MiB; 8–10 sections; <=1 cached DLL import.',
            managed_no_cached_imports='Valid CLR metadata; 64–512 KiB; no cached DLL imports.'),
        limitations='Post-hoc descriptive strata, not routing or labeling rules. Broad coverage does not establish exact-template or software-family coverage. Fit metrics are training diagnostics. Recovered archive names and original paths are evidence, not authenticity verification. Held roles are excluded.')
    for variant in args.variant:
        if variant not in prior['variants']:raise ValueError('Variant absent from profile: '+variant)
        X,schema=data[variant];report['variants'][variant]=[]
        old={f['fold']:f for f in prior['variants'][variant]}
        for fold in manifest['folds']:
            n=fold['fold'];print(f'Checking {variant} pattern coverage fold {n+1}/5',flush=True)
            roles=[[index[k] for k in fold[role]] for role in ('fit','calibration','held')]
            r.c.assert_split([entries[k]['record'] for k in keys],manifest['groups'],roles)
            fi,ci,_=roles;path=panel/variant/f'fold-{n:02d}-model.json';payload=cache.read(path)
            if payload['feature_names']!=schema or payload.get('development_only') is not True:raise ValueError('Model/schema mismatch')
            threshold=old[n]['selected_threshold'];ids=fi+ci
            scores=b.a.training_order_scores(payload,X[ids]);lookup=dict(zip(ids,map(float,scores)))
            stats={name:dict(fit=coverage(fi,keys,entries,mask,lookup,threshold,manifest['groups']),
                            calibration=coverage(ci,keys,entries,mask,lookup,threshold,manifest['groups'])) for name,mask in masks.items()}
            scaled=b.transform(X[ids],b.normalizer(X[fi]));position={i:j for j,i in enumerate(ids)}
            neighbors=[]
            for p in old[n]['profiles']:
                sha=p['representative_sha256'];i=index[sha]
                if i not in ci:raise ValueError('Representative not in original calibration split')
                options={}
                for label in (0,1):
                    candidates=[j for j in fi if entries[keys[j]]['record']['label']==label]
                    closest=sorted(candidates,key=lambda j:(float(np.abs(scaled[position[i]]-scaled[position[j]]).mean()),keys[j]))[:3]
                    options['benign' if label==0 else 'malware']=[dict(sha256=keys[j],source=entries[keys[j]]['record']['source'],
                        original_path=entries[keys[j]].get('original_path'),software=g.software_group(entries[keys[j]]),
                        reviewer_score=lookup[j],normalized_model_feature_distance=float(np.abs(scaled[position[i]]-scaled[position[j]]).mean()),
                        patterns=strata[j]) for j in closest]
                neighbors.append(dict(calibration_representative_sha256=sha,nearest_original_fit_samples=options))
            report['variants'][variant].append(dict(fold=n,threshold=threshold,patterns=stats,fit_neighbors=neighbors))
            cache.dump(args.output/'rich-pattern-coverage-summary.json',report)
    cache.dump(args.output/'archive-read-warnings.json',warnings)
    cache.dump(args.output/'inputs.json',dict(profile=str(profile),source_run=str(source),
        input_sha256={str(profile/'inputs.json'):cache.digest(profile/'inputs.json'),
                      str(profile/'rich-blocker-profile-summary.json'):cache.digest(profile/'rich-blocker-profile-summary.json'),
                      str(Path(__file__)):cache.digest(__file__)},
        original_input_sha256=identity['input_sha256'],scanned_file_sha256=scanned,variants=args.variant,
        scan_roots=[str(p) for p in args.scan_root or []]))
    report['complete']=True;cache.dump(args.output/'rich-pattern-coverage-summary.json',report)
    print(f'Complete: {args.output}\nRecovered missing names: {report["recovered_name_count"]}/{len(missing)}\nSend rich-pattern-coverage-summary.json.',flush=True)


def main():
    root=Path(__file__).resolve().parents[1]/'validation-data';ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--profile',type=Path,help='Default newest completed blocker profile')
    ap.add_argument('--variant',choices=r.VARIANTS,action='append',help='Default plus_imports')
    ap.add_argument('--scan-root',type=Path,action='append',help='Optional additional paths if cached archive locations moved')
    ap.add_argument('--output',type=Path,default=root/('reviewer-v8-rich-pattern-coverage-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')))
    ap.add_argument('--debug',action='store_true');args=ap.parse_args();args.root=root;args.variant=args.variant or ['plus_imports']
    if len(set(args.variant))!=len(args.variant):ap.error('Do not repeat variants')
    try:run(args)
    except Exception as e:
        if args.debug:traceback.print_exc()
        raise SystemExit(f'V8 rich pattern coverage stopped: {e}')


if __name__=='__main__':main()
