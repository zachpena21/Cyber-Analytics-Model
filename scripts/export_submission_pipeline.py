#!/usr/bin/env python3
"""Run inside the existing Python-3.9 reference image to export its pipeline."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import pickle
import numpy as np
import pandas as pd
from defender.models.nfs_model import NeedForSpeedModel  # original pickle symbol


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--module',type=Path,required=True);args=ap.parse_args()
    spec=importlib.util.spec_from_file_location('portable_export',args.module);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with gzip.open(args.input,'rb') as stream:pipeline=pickle.load(stream)
    payload=module.export_pipeline(pipeline);args.output.write_text(json.dumps(payload,indent=2)+'\n')
    portable=module.PortableFeaturePipeline(args.output)
    records=[]
    texts=['',' kernel32.dll  USER32.dll ',' Alpha beta  Alpha ','éé x Y',' kernel32.dll  kernel32.dll ord123 ']
    for i in range(20):
        record={name:float((i+1)*(j+1)) for j,name in enumerate(pipeline.NUMERICAL_ATTRIBUTES)}
        for j,name in enumerate(pipeline.CATEGORICAL_ATTRIBUTES):
            values=pipeline.categorical_extractor.categories_[j];record[name]=values[i%len(values)] if i<15 else 'UNKNOWN'
        record.update({name:texts[(i+j)%len(texts)] for j,name in enumerate(pipeline.TEXTUAL_ATTRIBUTES)});records.append(record)
    frame=pd.DataFrame(records);expected=pipeline._extract_features(frame).tocsr();actual=portable._extract_features(frame)
    difference=(expected-actual).tocsr();difference.eliminate_zeros()
    if difference.nnz:raise ValueError('Portable preprocessing differs from original reference pipeline')
    summary=dict(complete=True,feature_count=len(portable.scale),synthetic_records=len(records),max_abs_error=0.,
        original_pipeline_sha256=hashlib.sha256(args.input.read_bytes()).hexdigest(),export_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        raw_pe_parity=False,training=False)
    args.output.with_name('pipeline-export-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))


if __name__=='__main__':main()
