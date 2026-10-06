# Equal-weight five-seed development ensemble

This offline comparison averages probabilities from all five saved training seeds
(8704–8708), equally, within each original held fold. It performs no new fits,
chooses no seed or weight, and preserves the deployed v7 and frozen v8 bundles.
All four arms are retained: structural control / imports, with prior-only /
targeted-added fit coverage.

From the repository root on the VM:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_targeted_seed_ensemble.py
./.venv/bin/python scripts/reviewer_v8_targeted_seed_ensemble.py
```

The default selects the newest completed five-seed stability directory. To choose
one explicitly, add `--run validation-data/<stability-directory>`. Original source
runs, caches, acquisition archives, and frozen dependencies must remain available.
Docker need not be running: features and saved models are replayed offline.

Before computing the ensemble, the script verifies source hashes, split roles,
held scores and gates, calibration counts, and each saved seed summary. It rejects
incomplete, changed, or inconsistent sources. It creates a new timestamped output;
`--output` must point to an empty or nonexistent directory.

For each arm and fold, it averages the five probabilities on the same original
calibration samples, applies the existing software-aware calibration policy, then
scores held samples at that threshold. Targeted samples assigned calibration roles
remain excluded from calibration. The historical fixed threshold is reported only
as a diagnostic. No held score is used to choose thresholds, weights, or seeds.

Send `targeted-seed-ensemble-summary.json` from the printed output directory. It
contains pooled prior/targeted metrics, paired coverage/imports changes, the same
largest ten malware representation groups watched in the stability study, and
single-seed variation for reference. Full held scores and hash-bound inputs are
also saved. Representation groups are not verified malware families. This remains
post-hoc development on inspected data, not independent validation or a promoted
runtime model; the five held-fold ensembles cannot be treated as one final model.
