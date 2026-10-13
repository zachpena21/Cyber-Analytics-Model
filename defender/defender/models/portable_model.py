"""Unchanged compact forest/adapter inference with exported preprocessing."""
import json
from pathlib import Path
import numpy as np
from defender.models.compact_model import CompactNeedForSpeedModel
from defender.models.modern_adapter import ModernAdapterModel
from defender.models.portable_pipeline import PortableFeaturePipeline


class PortableCompactModel(CompactNeedForSpeedModel):
    def __init__(self,model_dir):
        root=Path(model_dir);self.pipeline=PortableFeaturePipeline(root/'feature-pipeline.json')
        self.metadata=json.loads((root/'metadata.json').read_text())
        for attr,name in (('offsets','offsets'),('children_left','children_left'),('children_right','children_right'),
                          ('features','features'),('thresholds','thresholds'),('malware_probability','malware_probability')):
            setattr(self,attr,np.load(root/(name+'.npy'),mmap_mode='r'))
        if len(self.pipeline.scale)!=self.metadata['feature_count']:raise ValueError('Forest/pipeline width differs')


class PortableModernAdapter(ModernAdapterModel):
    classifier_name='CompactRandomForest+LinearModernAdapter+ReviewerV8'
    def __init__(self,model_dir,adapter_dir):
        self.base=PortableCompactModel(model_dir);root=Path(adapter_dir)
        self.adapter_metadata=json.loads((root/'metadata.json').read_text())
        self.coefficients=np.load(root/'coefficients.npy',mmap_mode='r')
        self.intercept=float(np.load(root/'intercept.npy')[0]);self.adapter_threshold=float(self.adapter_metadata['adapter_threshold'])
        expected=int(self.adapter_metadata['feature_count'])
        if self.coefficients.shape!=(expected,) or expected!=self.base.metadata['feature_count']+1:
            raise ValueError('Portable adapter width differs')
