# Controlled v8 training from exact Docker features

Train an old-data control and an expanded-data candidate using the completed
Docker feature audit. The configuration stays at 72 features, 128 GBDT stages,
learning rate 0.1, depth 3, minimum leaf size 8, sqrt feature sampling, seed 704,
balanced training weights, original route minimum 0.15, and adapter threshold 0.7.
No binaries are parsed or executed, no network/Docker scoring is required, and
existing models and deployed containers are unchanged.

Run on the VM after the completed Docker audit:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_docker_train.py
```

Inputs default to:

- `validation-data/reviewer-v8-docker-audit/`: completed audit summary, exact
  Docker feature cache, and recorded input hashes.
- `validation-data/reviewer-v8-coverage-development/coverage-manifest.json`.
- Original source CSVs under `validation-data/`.
- The same three frozen candidates recorded in the coverage manifest.

Use `--audit-dir`, `--coverage`, or `--reports-dir` for alternate successful-run
locations. Output defaults to `validation-data/reviewer-v8-docker-training-development`.
The script refuses a nonempty output directory. A failed training run can be
repeated with a fresh `--output`; it does not resume partially fitted estimators.

## Split and comparison

The existing 10,650-sample historical fit/calibration split is preserved. The
control fits only that original fitting split. The expanded candidate adds the
fitting portion of all 684 new development samples; the remainder participates
in calibration. Correctly classified and misclassified new samples are included.
Labels are preserved; this script does not relabel the Adobe-like sample flagged
for provenance review or infer labels from predictions, paths, or signatures.

New benign files are grouped by their Program Files installation root, combining
the same root across Program Files and Program Files (x86). Windows files share
the Windows acquisition group; files without original paths use their acquisition
source. New malware is grouped by its recorded acquisition batch. Paths and group
IDs are used for splitting/reporting only, never as classifier inputs.

Whole groups are assigned using seed 2704 and class counts to approximate 20%
calibration while keeping fitting and calibration groups separate. Actual class
fractions may differ substantially when groups are large. No frozen scores,
error status, or model outcomes influence group assignment. For a class with only
one new group, that group stays in fitting and calibration relies on the original
pool. All assignments and counts are saved in the split manifest.

Each model's upper threshold is selected on its own calibration pool using the
existing overall 1% benign FPR cap plus the 1% cap for sources with at least 100
benign calibration samples. A midpoint version is also saved, with an explicit
check that it leaves calibration predictions unchanged. Both models are reported
at the two existing frozen import thresholds as well, separating training-data
changes from recalibration changes.

Main reports include original calibration, grouped new calibration, and all new
development samples. **All-new metrics include fitting samples** and must not be
reported as held-out performance. Neither calibration set is fresh final testing.

## Group holdouts

Every new malware acquisition group and every new benign group with at least ten
samples gets a leave-group-out comparison. The held group is excluded from fitting
and calibration. Known corresponding old acquisition sources are also removed for
v10/v11 malware holdouts (`reviewer-v5-v10-diagnostic` / `batch-v11`). The old-data
control is refitted when those old sources are removed, giving both models the
same source exclusion. Each fold recalibrates without the held group.

This keeps new groups intact but does not retroactively fix group leakage in the
historical split. Old files may contain related software; malware families may
span acquisition batches. Group holdouts are development diagnostics, not proof
of package/family independence or an unbiased final test. Small benign groups are
omitted from leave-group-out diagnostics only, and their counts are disclosed.

The importer checks all frozen scores and gated predictions against the exact
Docker cache, along with input hashes, schemas, labels, SHA disjointness, and pool
coverage. Each exported model reproduces sklearn probabilities on the complete
11,334-sample pool within 1e-10 using the deployed float32 traversal behavior.

## Outputs

- `training-summary.json`: policies, calibration rates, fixed-threshold
  comparisons, group holdouts, export parity, source/group counts, and completion.
- `split_manifest.json`: preserved old assignments and grouped new assignments.
- Four format-8 artifacts: `old_data_control-upper-model.json`,
  `old_data_control-midpoint-model.json`, `expanded_candidate-upper-model.json`,
  and `expanded_candidate-midpoint-model.json`.
- `development-scores.json`: main development scores with split roles, plus
  group holdout scores clearly marked as such.
- `inputs.json`: input/model hashes, script hash, configuration, and grouping seed.

Send `training-summary.json` and `split_manifest.json`. Wait for
`"completed": true` before interpreting the full experiment. These are separate
development artifacts; no model is installed in the production model folders.

Tests:

```bash
./.venv/bin/python scripts/test_reviewer_v8_docker_train.py
```
