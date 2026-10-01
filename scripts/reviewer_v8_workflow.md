# Reviewer v8 development workflow

Run from the VM repository. Docker is not needed for these commands.

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_workflow.py audit
```

The audit reads the five reviewer-v7 score reports for data batches v7 through
v11. It finds PE payloads under `validation-data`, supports AES/nested ZIPs with
the existing `pyzipper` dependency, and parses files in memory without executing
them or extracting them to disk. Unreadable ZIP entries are logged to
`archive-read-warnings.json` and scanning continues through later members,
including members in nested ZIPs. Every required SHA must still be found and
parsed; a missing required payload stops the workflow. This tolerance is
enabled only for the v8 feature scan. The overlap checker remains strict so
an unreadable archive cannot hide a possible training overlap.
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

Archive regression checks (standard library only):

```bash
./.venv/bin/python scripts/test_reviewer_v8_archives.py
```

These check strict overlap scanning, recovery past a damaged member, nested ZIP
path diagnostics, and rejection when a required SHA is unavailable. Existing
feature checkpoints can be reused after this scanner fix.

If the frozen-model score check fails, send
`validation-data/reviewer-v8-development/parity-diagnostics.json`. This file is
written before the workflow stops and includes differences by batch, the largest
sample mismatches and their local PE features, dependency versions, Docker
requirement pins, report paths, and the frozen model digest. Dependency differences
are clues, not established causes. The workflow does not replace recorded scores
or loosen the parity requirement. Existing feature cache entries can be reused.

### LIEF flag text compatibility

The VM may use a newer LIEF than the Docker service (which pins 0.11.5).
New versions can render DLL flags as decimal numbers and add `CHARACTERISTICS.`
to header flag names. V7 uses token counts and character lengths of these fields.
The workflow restores the legacy flag spelling in structural vectors for both
existing cache entries and newly extracted samples. Raw cached attributes remain
unchanged. Existing caches are reused; deleting the cache or downgrading Python
is unnecessary. The normalization reproduced all 30 largest mismatches in the
uploaded diagnostics to floating-point precision. Full report score parity is
still required before the audit or training can proceed; other parser differences
may remain outside those 30 samples.

Pull and rerun `audit`. If successful, send
`validation-data/reviewer-v8-development/error-audit.json` for the error analysis
before selecting additional features. Regression checks can be run with
`python3 scripts/test_reviewer_v8_archives.py`.

### Ordinary import compatibility

LIEF 0.11.5 aggregates ordinary imports only. LIEF 1.0.0 appends delayed
libraries and delayed named functions. The workflow removes the exact delayed
suffix from newly parsed aggregate text, preserving ordinary ordinal names
already resolved by LIEF. An unexpected suffix raises an extraction error.
Production extractor code and stored reports are unchanged.

Old cache samples with more library tokens than ordinary import descriptors
are selectively reparsed when needed by the current command. Other cached
samples are reused. Refreshed entries record `legacy_imports_compatible: true`,
retain `raw_attributes`, and vectorize corrected `attributes`. The flag-text
normalization still runs afterward. A repeat run reuses the refreshed cache.
Full report parity, required SHA coverage and original-model reconstruction
checks remain mandatory.

After pulling, rerun the same `audit` command. If parity passes, share
`error-audit.json`. If it fails, share the new `parity-diagnostics.json`.

### Legacy flag alias and export name limit

Two additional LIEF 0.11.5 rules apply to cached features: its 32-bit-machine
flag string is `CHARA_32BIT_MACHINE` (newer versions use `NEED_32BIT_MACHINE`),
and its export parser removes entries with names longer than 300 bytes.
The workflow normalizes the flag alias and removes oversized export names,
updating the named-export count, text summaries, and dependent reviewer features.
It retains raw attributes and rejects count/text inconsistencies rather than
inventing an export count. These corrections reproduced the two remaining
uploaded mismatches to floating-point precision. They operate on existing cached
attributes, so another archive scan is unnecessary for already covered samples.
Full-dataset report parity remains required. Run the same `audit` command after
pulling; send `error-audit.json` when successful.

Reference implementations:
- https://github.com/lief-project/LIEF/blob/0.11.5/src/PE/EnumToString.cpp
- https://github.com/lief-project/LIEF/blob/0.11.5/src/PE/Parser.cpp
- https://github.com/lief-project/LIEF/blob/0.11.5/src/PE/Binary.cpp
