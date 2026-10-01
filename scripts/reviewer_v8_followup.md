# V8 threshold interval and build-category experiments

Run after the baseline and fixed import feature experiment are complete:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_followup.py
```

No Docker is needed. Reports and the existing baseline feature cache supply the
inputs, with no archive reads, PE execution, or new data. The script reproduces
the completed baseline/import models and source holdout results before comparing
changes. Existing model directories and the deployed v7 remain unchanged.

## Two independent comparisons

For each of the baseline (66 features), import model (72 features), and new build
model (77 features), compare these threshold rules:

1. The existing highest threshold selected by the calibration objective.
2. The midpoint of the interval giving exactly the same calibration predictions:
   `(largest score below the selected threshold, selected threshold]`.

Both rules retain the same calibration objective and global/per-source FPR caps.
The midpoint changes only the location within an identical-prediction interval.
If there is no representable interior float, it retains the upper endpoint.
Holdout predictions may differ. No holdout label or score selects a threshold.
Paired bootstrap comparisons resample within source/class groups 100 times,
keeping the model fixed. Infeasible resamples are reported separately. This
measures calibration sample sensitivity, not retraining or unseen-source risk.

The build model adds exactly five predefined features on top of the import model:

- linker major version equals 2;
- COFF symbols present (`symbols > 0`);
- debug directory absent (`has_debug == 0`);
- linker version 2 with symbols;
- linker version 2 with symbols, no debug directory, and TLS present.

The indicators describe PE attributes; they do not establish a compiler family,
and none forces a benign decision. The configuration, seeds, route minimum and
ordered SHA split are held fixed. All three actual feature counts keep `sqrt`
sampling at eight features per split. The build candidate uses explicit runtime
format 9, with float32 inputs and validated import/build feature order. Previous
formats keep their feature vectors and scoring behavior. Rebuild Docker with the
updated runtime before any later format 9 service evaluation.

## Results

Outputs go to `validation-data/reviewer-v8-followup-development/`:

- `metadata.json`: paired calibration and source-holdout comparisons, original
  v7 threshold comparisons, bootstrap sensitivity, and class/source coverage of
  the kernel-import and build categories. Check `completed: true` before review.
- `tree-path-audit.json`: reference import-model errors and nearest correctly
  classified same-class peers. Each sample is traced through the import and build
  refits, with the eight largest positive and negative additive stage contributions
  and their actual split paths. Trace sums reproduce sklearn scores. Stage
  contributions are raw-score terms, not causal feature attributions. Below-route
  traces are hypothetical; the reviewer would not run for those samples.
- `source-heldout-scores.csv`: all samples, scores and both policies for all three
  refits. Each source is excluded from both fitting and calibration.
- `split_manifest.json`: unchanged training/calibration membership and order.
- `build_categories-upper_endpoint-model.json` and
  `build_categories-interval_midpoint-model.json`: build candidate variants.
- `baseline-interval_midpoint-model.json` and `imports-interval_midpoint-model.json`:
  threshold-only reference variants.
- `inputs.json`: report and original-model fingerprints.

Send `metadata.json` and `tree-path-audit.json`. These are development experiments
informed by previous holdouts. Keep production v7 unchanged and use a fresh batch
before promoting a candidate. The script adds no specialist or skimmer, and
provides no upstream out-of-fold guarantees. It does not automatically select a
winning candidate or deploy anything.

Optional arguments: `--reports-dir`, `--baseline-output`, `--candidate-output`,
`--v7-model`, `--output`, `--bootstrap-repeats` (10 to 1000).

Regression checks:

```bash
./.venv/bin/python scripts/test_reviewer_v8_followup.py
./.venv/bin/python scripts/test_reviewer_v8_archives.py
```
