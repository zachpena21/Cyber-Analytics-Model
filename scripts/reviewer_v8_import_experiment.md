# V8 fixed import feature experiment

Run after `reviewer_v8_workflow.py train` successfully writes the runtime-aligned
baseline to `validation-data/reviewer-v8-development`.

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_import_experiment.py
```

No Docker service is needed. The experiment reuses the baseline feature cache;
it reproduces the completed baseline's trees, calibrated threshold, and ordered
split exactly before fitting a candidate. A mismatch stops the experiment.
Original v7 and baseline model files remain unchanged.

The six appended features are presence indicators for ordinary imports of
`ntoskrnl.exe`, `hal.dll`, `ndis.sys`, `wdfldr.sys`, and `ks.sys`, plus the sum of
those five indicators. Library names are compared as case-insensitive basenames.
Duplicate libraries count once. Missing libraries give zero indicators. Neither
sample filenames nor labels enter these features. A kernel import does not
force a benign decision; the reviewer learns from both classes.

The candidate uses the same GBDT configuration, seeds, training/calibration SHA
membership and order, route minimum, and source FPR calibration caps as the
baseline. The six additions keep `sqrt` feature sampling at eight features per
split for the actual 66-to-72 feature schemas. Format 8 explicitly declares the
import feature order and float32 tree inputs. Legacy model formats keep their
existing feature vectors and scoring behavior. Docker must be rebuilt with the
updated runtime before a format 8 model can be tested through the service.

Outputs go to `validation-data/reviewer-v8-import-features-development/`:

- `metadata.json`: shared calibration results, changed calibration predictions,
  and paired leave-one-source-out comparisons for data v7, v11, v9 and v10.
- `source-holdout-errors.json`: SHA, class, probability, threshold and import
  indicators for every error from both models in the source holdouts.
- `reviewer-source-heldout-scores.csv`: every held-out sample, both model scores
  and predictions, and the six indicators.
- `model.json`: experimental candidate, format 8.
- `split_manifest.json`: SHA split, identical to the baseline.
- `error-audit.json`, `features.csv`, `parity-diagnostics.json`, `inputs.json`:
  frozen-v7 audit and input provenance.

Each holdout refits both models with that source excluded from training and
calibration. Each model selects its threshold using only the remaining sources.
The reports also evaluate each fold at the pre-existing v7 threshold
`0.6312998096487621`, to distinguish threshold changes from representation changes.
Category summaries distinguish samples importing at least one of the five fixed
libraries from all others, with benign/malware counts and FP/FN counts. These are
import categories, not proof that a binary is a driver or benign.

The feature hypothesis was informed by previous source-holdout results, so these
comparisons remain development diagnostics. Calibration also selects thresholds.
Use a fresh batch to confirm any proposed improvement before replacing v7.
This script trains no skimmer and provides no upstream out-of-fold guarantees.

To review the run, send `metadata.json` and `source-holdout-errors.json` from the
new output directory. Keep production v7 unchanged while evaluating the results.

Optional paths:

```bash
./.venv/bin/python scripts/reviewer_v8_import_experiment.py \
  --baseline-output validation-data/reviewer-v8-development \
  --output validation-data/reviewer-v8-import-features-development \
  --reports-dir validation-data
```

`--location` may be repeated for PE roots or ZIPs, and `--v7-model` selects the
original frozen v7 model. The output directory must differ from the baseline.
If archive reads are needed, tolerant member reads still enforce complete SHA
coverage; no PE is executed or extracted to disk.

Regression checks:

```bash
./.venv/bin/python scripts/test_reviewer_v8_imports.py
./.venv/bin/python scripts/test_reviewer_v8_archives.py
```
