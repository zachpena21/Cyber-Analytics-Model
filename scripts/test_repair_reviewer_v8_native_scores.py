#!/usr/bin/env python3
"""Original-hash restoration, backups, refusal of changed models and races."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import repair_reviewer_v8_native_scores as repair


class RepairTests(unittest.TestCase):
    def test_restore_original_hash_and_preserve_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);file=root/'seed-8707/structural_control/prior_only/development-scores.json'
            repair.cache.dump(file,[dict(sha256='sample',reviewer_score=.9)])
            expected=repair.cache.digest(file);original=file.read_bytes();file.write_bytes(b'')
            marker=root/'completion.json';repair.cache.dump(marker,dict(artifact_sha256={str(file):expected}))
            marker_hash=repair.cache.digest(marker)
            proposed={str(file):dict(expected_sha256=expected,damaged_sha256=repair.cache.digest(file),regenerated_bytes=original)}
            destination=repair.restore(root,proposed,{str(file):expected,str(marker):marker_hash})
            self.assertEqual(file.read_bytes(),original);self.assertEqual(repair.cache.digest(marker),marker_hash)
            report=repair.cache.read(destination/'score-repair-summary.json')
            self.assertTrue(report['complete']);self.assertFalse(report['markers_changed'])
            self.assertEqual(Path(report['files'][str(file)]['backup']).read_bytes(),b'')

    def test_refuse_wrong_replay_hash_and_concurrent_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);file=root/'scores.json';file.write_bytes(b'broken')
            expected=hashlib.sha256(b'original').hexdigest()
            proposed={str(file):dict(expected_sha256=expected,damaged_sha256=repair.cache.digest(file),regenerated_bytes=b'wrong')}
            with self.assertRaisesRegex(ValueError,'original hash'):repair.restore(root,proposed,{str(file):expected})
            self.assertEqual(file.read_bytes(),b'broken');self.assertFalse(list(root.glob('score-repair-*')))
            proposed[str(file)]['regenerated_bytes']=b'original';file.write_bytes(b'new change')
            with self.assertRaisesRegex(ValueError,'changed during repair'):repair.restore(root,proposed,{str(file):expected})
            self.assertEqual(file.read_bytes(),b'new change')

    def test_only_scores_can_be_repaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repair.cache.dump(root/'inputs.json',dict(input_sha256={}))
            repair.cache.dump(root/'native-coverage-summary.json',dict(complete=True,completed_seeds=list(repair.n.s.SEEDS)))
            for seed in repair.n.s.SEEDS:
                folder=root/f'seed-{seed}';hashes={}
                for v in repair.n.t.VARIANTS:
                    for arm in repair.n.t.ARMS:
                        file=folder/v/arm/'development-scores.json';repair.cache.dump(file,[]);hashes[str(file)]=repair.cache.digest(file)
                model=folder/'model.json';repair.cache.dump(model,dict(model=True));hashes[str(model)]=repair.cache.digest(model)
                repair.cache.dump(folder/'completion.json',dict(complete=True,seed=seed,artifact_sha256=hashes))
            score=root/'seed-8707/structural_control/prior_only/development-scores.json';score.write_bytes(b'')
            self.assertEqual(set(repair.damaged_scores(root)),{str(score)})
            model=root/'seed-8707/model.json';model.write_text('{}')
            with self.assertRaisesRegex(ValueError,'changed model/metadata'):repair.damaged_scores(root)

    def test_regenerated_scores_must_match_checkpoint_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);built=root/'built';source=root/'source';hashes={};proposed={}
            for v in repair.n.t.VARIANTS:
                for arm in repair.n.t.ARMS:
                    relative=Path(v)/arm/'development-scores.json'
                    repair.cache.dump(built/relative,[dict(score=.5)]);repair.cache.dump(source/relative,[dict(score=.5)])
            path=source/'structural_control/prior_only/development-scores.json'
            proposed[str(path)]=dict(expected_sha256=repair.cache.digest(path));path.write_text('')
            repair.audit.verify_scores(built,source,hashes,proposed)
            self.assertIn('regenerated_bytes',proposed[str(path)])
            repair.cache.dump(built/'structural_control/prior_only/development-scores.json',[dict(score=.6)])
            with self.assertRaisesRegex(ValueError,'original recorded hash'):repair.audit.verify_scores(built,source,hashes,proposed)


if __name__=='__main__':unittest.main()
