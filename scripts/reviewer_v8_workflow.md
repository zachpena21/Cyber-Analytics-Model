# Reviewer v8 development workflow

Run from the VM repository. Docker is not needed for these commands.

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_workflow.py audit
```

The audit reads the five reviewer-v7 score reports for data batches v7 through
v11. It finds PE payloads under `validation-data`, supports AES/nested ZIPs with
the existing `pyzipper` dependency, and parses files in memory without executing
them or extracting them to disk. Every required SHA must be found and parsed.
Report class counts must match the recorded batches (v7: 1000/8; v8: 1000/7;
v9: 1000/3; v10: 1000/20; v11: 589/13, benign/malware). Original training
reports must also contain their complete recorded unique row counts.
Routed scores must reproduce the frozen v7 model within 1e-8 before the audit
is accepted. A mismatched model, extractor, or report stops the workflow.

Outputs go to `validation-data/reviewer-v8-development/`:

- `error-audit.json`: every error, PE attributes, closest correct samples from
  each class, descriptive feature differences, batch metrics, and zone coverage.
- `features.csv`: the original v7 model's feature vector for every audit sample.
- `feature-cache.json`: reusable structural features, without labels or scores.
- `inputs.json`: report paths and frozen model digest.

Distances use log-transformed, robustly scaled structural features. Scores and
labels do not enter the distance. The scaling uses the audit population and is
descriptive only; it is not a preprocessing model for training or evaluation.
Neighbors do not establish malware families or explain causation. Zone summaries
overlap and must not be added together. The audit never changes predictions.

After reviewing the audit, train the data-expansion baseline:

```bash
./.venv/bin/python scripts/reviewer_v8_workflow.py train
```

Training uses the eight original source reports plus complete data batches v7
and v11. It keeps v7's feature specification, route minimum 0.15, balanced class
weights, and selected GBDT configuration (128 stages, learning rate 0.1, depth 3,
minimum leaf size 8). It preserves the original source/class split (seed 704,
20% calibration) and splits the two added batches separately with seed 1704.
New-batch overlap with the original pool and conflicting source labels/scores
are rejected. The original v7 fit must be reconstructed successfully before
the expanded-data baseline is trained.

The original decision threshold is reported as a comparison. The exported
candidate threshold is recalibrated solely on the reserved calibration data,
maximizing recall subject to <=1% overall FPR and <=1% FPR for each calibration
source with at least 100 benign samples. The candidate may still fail the recall
target or held-out-source targets; inspect the metrics before using it.

Four additional fits leave out the complete v7, v11, v9, and v10 sources in turn.
Their thresholds are selected on calibration data from the remaining sources.
These results do not select hyperparameters or alter the final candidate. They
evaluate the reviewer configuration, not an entirely unseen upstream pipeline.
Same-family variants are not yet grouped: a fresh disjoint evaluation is still
required, and family grouping should be added if reliable family labels exist.

Additional training outputs in the same directory:

- `model.json`: development v8 baseline, compatible with the current format-6 runtime.
- `metadata.json`: settings, calibration results, source holdouts, reconstruction
  check, and numerical export parity check.
- `split_manifest.json`: exact training/calibration SHA membership.
- `reviewer-source-heldout-scores.csv`: reviewer predictions with each reported
  source excluded from reviewer fitting and calibration. These are development
  scores, not proof of leakage-free predictions from every upstream model.

Send `error-audit.json` and, after training, `metadata.json` for comparison. No
skimmer is fitted in this first experiment. Existing score reports are never
passed to the classifier as targets or as reviewer-score input features.

All original reports/models and production Docker configuration remain unchanged.
The output directory is local development data, not a new production deployment.
The default v11 report preference is `reviewer-v7-v11-fresh(1).csv`, then
`reviewer-v7-v11-fresh.csv`; score reproduction guards against a stale copy.

Options allow different roots without editing the script:

```bash
./.venv/bin/python scripts/reviewer_v8_workflow.py audit \
  --reports-dir validation-data \
  --location validation-data \
  --v7-model defender/defender/models/boundary_reviewer_v7_gbdt_candidate/model.json \
  --output validation-data/reviewer-v8-development
```

The VM needs its existing numpy, scipy, scikit-learn, pandas, LIEF and pyzipper
dependencies. If extraction is interrupted, the cache is checkpointed every
100 additional samples and reused on the next run. A changed feature
specification, extractor/runtime source, LIEF version, or size limit invalidates it.
