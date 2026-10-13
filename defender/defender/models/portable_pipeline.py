"""Parameter-only legacy feature pipeline; no cross-version sklearn pickle."""
import json
from pathlib import Path
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer


class PortableFeaturePipeline:
    def __init__(self,path):
        payload=json.loads(Path(path).read_text())
        if payload['format_version']!=1:raise ValueError('Unsupported portable feature pipeline')
        self.numerical=payload['numerical'];self.categorical=payload['categorical'];self.textual=payload['textual']
        self.categories=payload['categories'];self.scale=np.asarray(payload['scale'],dtype=np.float64)
        if not np.isfinite(self.scale).all() or np.any(self.scale<=0):raise ValueError('Invalid pipeline scale')
        self.vectorizers={}
        for name in self.textual:
            config=dict(payload['hashing'][name]);config['ngram_range']=tuple(config['ngram_range'])
            self.vectorizers[name]=HashingVectorizer(dtype=np.float64,**config)
        count=len(self.numerical)+sum(len(x) for x in self.categories)+sum(v.n_features for v in self.vectorizers.values())
        if count!=len(self.scale) or len(self.categories)!=len(self.categorical):raise ValueError('Portable pipeline feature count differs')
        self.lookups=[{value:i for i,value in enumerate(values)} for values in self.categories]

    def _extract_features(self,data):
        numeric=sparse.csr_matrix(data[self.numerical].values,dtype=np.float64)
        rows=[];cols=[];offset=0
        for name,lookup,values in zip(self.categorical,self.lookups,self.categories):
            for row,value in enumerate(data[name].values):
                if value in lookup:rows.append(row);cols.append(offset+lookup[value])
            offset+=len(values)
        categorical=sparse.csr_matrix((np.ones(len(rows)),(rows,cols)),shape=(len(data),offset))
        textual=[self.vectorizers[name].transform(data[name].values) for name in self.textual]
        matrix=sparse.hstack([numeric,categorical]+textual,format='csr')
        matrix.data*=np.reciprocal(self.scale)[matrix.indices]
        return matrix


def export_pipeline(pipeline):
    encoder=pipeline.categorical_extractor
    if (type(encoder).__name__!='OneHotEncoder' or encoder.handle_unknown!='ignore'
            or encoder.drop is not None or type(pipeline.feature_scaler).__name__!='MaxAbsScaler'):
        raise ValueError('Unsupported original categorical/scaler configuration')
    hashing={}
    for name in pipeline.TEXTUAL_ATTRIBUTES:
        vectorizer=pipeline.textual_extractors[name]
        if type(vectorizer).__name__!='HashingVectorizer':raise ValueError('Expected original hashing vectorizer: '+name)
        config=vectorizer.get_params()
        if any(config.get(k) is not None for k in ('preprocessor','tokenizer')) or not isinstance(config['analyzer'],str):
            raise ValueError('Custom analyzer functions cannot be exported')
        config.pop('dtype');config.pop('preprocessor',None);config.pop('tokenizer',None)
        hashing[name]=config
    return dict(format_version=1,numerical=list(pipeline.NUMERICAL_ATTRIBUTES),categorical=list(pipeline.CATEGORICAL_ATTRIBUTES),
        textual=list(pipeline.TEXTUAL_ATTRIBUTES),categories=[x.tolist() for x in encoder.categories_],
        hashing=hashing,scale=pipeline.feature_scaler.scale_.tolist())
