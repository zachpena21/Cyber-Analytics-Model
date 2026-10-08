# Repair a changed held-score artifact

This restores only checkpoint-bound `development-scores.json` files. It rejects
changed models, metadata or other artifacts. All five saved seeds and the final
ensemble are replayed before restoration. The regenerated score bytes must
reproduce each damaged file's **original recorded SHA256**; neither completion
markers nor their hashes are edited. No models are fitted.

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_repair_reviewer_v8_native_scores.py
./.venv/bin/python scripts/repair_reviewer_v8_native_scores.py --run validation-data/reviewer-v8-native-coverage-20261007-200408-226910
./.venv/bin/python scripts/reviewer_v8_native_coverage_audit.py --run validation-data/reviewer-v8-native-coverage-20261007-200408-226910
```

The default is the newest completed native coverage run; an explicit `--run` is
recommended when a traceback names the damaged run. Keep other writers stopped.
If the regenerated hash differs, the script stops without replacing any score
file. Do not delete or regenerate completion markers to bypass that failure.

Damaged bytes are backed up in a timestamped `score-repair-*` directory inside
the run, alongside `score-repair-summary.json`. Valid original files stay intact.
Restoration uses staged replacement and checks all recorded hashes afterward.
Missing held-score files can also be restored after the same hash proof.
This does not determine what changed the file; it reconstructs the historical
artifact from intact saved models and verified inputs.
