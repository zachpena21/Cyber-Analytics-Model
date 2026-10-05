from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import collect_reviewer_v8_structural as c


class StructuralCollectorTests(unittest.TestCase):
    def fixture(self,root):
        now=datetime.now(timezone.utc);started=(now-timedelta(minutes=1)).isoformat()
        manifest=dict(frozen_at=(now-timedelta(hours=1)).isoformat())
        bundle=root/'bundle';c.v.w.dump(bundle/'freeze-manifest.json',manifest);digest=c.v.g.digest(bundle/'freeze-manifest.json')
        benign=root/'benign/new.zip';malware=root/'malware-batches/new.zip'
        benign.parent.mkdir(parents=True);malware.parent.mkdir(parents=True)
        benign.write_bytes(b'benign');malware.write_bytes(b'malware')
        bs=dict(complete=True,started_utc=started,freeze_manifest_sha256=digest,artifacts=[dict(
            path=str(benign),sha256=c.v.g.digest(benign),source_id='specific-version',provenance=dict(collected_utc=started))])
        ms=dict(complete=True,started_utc=started,freeze_manifest_sha256=digest,label_basis='test',
                samples=[dict(path=str(malware),archive_sha256=c.v.g.digest(malware),collected_utc=started)],batches=[dict(url='test')])
        c.v.w.dump(root/'benign/collection-summary.json',bs);c.v.w.dump(root/'malware-batches/collection-summary.json',ms)
        args=SimpleNamespace(output=root,bundle=bundle,command='sources',versions=2,count=200,hours=48,
            max_download_mb=1024,max_batch_mb=256,connect_timeout=20,read_timeout=120,attempts=2,abis=['cp313'],resume=False)
        return args,manifest

    def test_sources_have_actual_post_freeze_timestamps_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory,patch('builtins.print'):
            args,manifest=self.fixture(Path(directory));c.sources(args,manifest)
            rows=c.v.f.read(args.output/'sources.json');self.assertEqual([r['label'] for r in rows],[0,1])
            c.v.check_acquisitions(rows,manifest['frozen_at'])
            (args.output/'benign/new.zip').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'Benign archive changed'):c.sources(args,manifest)

    def test_old_collection_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            args,manifest=self.fixture(Path(directory));bs=c.v.f.read(args.output/'benign/collection-summary.json')
            bs['started_utc']=manifest['frozen_at'];c.v.w.dump(args.output/'benign/collection-summary.json',bs)
            with self.assertRaisesRegex(ValueError,'acquired after freeze'):c.sources(args,manifest)

    def test_malware_facade_uses_new_exclusions_and_is_restored(self):
        with tempfile.TemporaryDirectory() as directory,patch('builtins.print'):
            args,manifest=self.fixture(Path(directory));args.command='malware';original=c.batches.f
            def collect(_):
                self.assertEqual(c.batches.f.load_bundle(args.bundle)[2],{'a'*64})
                self.assertIs(c.v.f.load_bundle,original.load_bundle)
            with patch.object(c.v,'load_bundle',return_value=(manifest,{}, {},{}, {'a'*64})),patch.object(c.batches,'collect',side_effect=collect):
                c.run(args)
            self.assertIs(c.batches.f,original)


if __name__=='__main__':unittest.main()
