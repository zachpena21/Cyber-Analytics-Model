# V8 error neighbors and threshold sensitivity

Run after completing the baseline and fixed import feature experiment:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_diagnostics.py
```

No Docker or archive extraction is needed. The script reads the existing baseline
feature cache and reports, reproduces both completed models exactly, and refits
the paired source holdouts to reproduce their thresholds and FP/FN counts.
A mismatch stops diagnostics. No trained model or deployment configuration is saved.

Results go to `validation-data/reviewer-v8-diagnostics/`:

- `diagnostics.json`: calibration threshold distributions for the completed models
  and each source refit; held-out FP/FN ranges as those thresholds change; samples
  whose predictions change; structural difference frequencies among errors.
- `neighbor-audit.json`: every import candidate source-holdout error, including
  persistent v11 false positives, new v9 false positives and malware misses. Each
  includes upstream scores, import indicators, PE attributes, threshold margin,
  and up to five correctly classified same-class and opposite-class neighbors.
- `inputs.json`: report/model SHA fingerprints.

Neighbor distances use the original structural features, excluding upstream
scores and the six new import indicators. Features are transformed with log1p
and scaled using only that source fold's training rows. Distance is clipped
absolute difference averaged over features. Correct neighbors come from the
same held-out source and are scored by the same candidate refit. Labels select
comparison groups; they do not fit the distance metric. Empty groups remain
explicitly empty. Similarity is descriptive, not a causal explanation, family
assignment, or independent performance estimate. Difference-frequency counts
are descriptive rather than a feature-significance test.

Threshold sensitivity uses 100 bootstrap resamples within each calibration
source/class group, preserving their original sizes. The fitted model stays
fixed. Each resample uses the workflow's existing calibration objective and
FPR caps; the script verifies its fast weighted implementation against the
original selected threshold before running. Paired model comparisons use the
same bootstrap seed. Results separately report any resamples with no feasible
threshold. Quantiles and
prediction ranges use feasible resamples only. Below the route minimum, a zero
score is a policy placeholder rather than an evaluated reviewer probability.
These distributions measure calibration sample sensitivity,
not uncertainty from retraining, malware-family duplication or unseen sources.
Reported holdout changes are post-hoc diagnostics; the script does not choose a
threshold using holdouts or recommend a new production threshold.

Send `diagnostics.json` and `neighbor-audit.json` for review. Keep production v7
unchanged. Previous holdouts informed this experiment; fresh data is still
needed to evaluate any proposed improvement independently.

Optional arguments: `--reports-dir`, `--baseline-output`, `--candidate-output`,
`--v7-model`, `--output`, and `--bootstrap-repeats` (10 to 1000).
The output must differ from both experiment directories.

Tests:

```bash
./.venv/bin/python scripts/test_reviewer_v8_diagnostics.py
```

Tests compare weighted calibration with the original objective on tied and
continuous scores, exercise zero bootstrap weights, and run the complete
synthetic baseline/import/diagnostic workflow with runtime and split checks.
