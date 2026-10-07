# Group-balanced training-weight experiment

This development experiment changes only the routed reviewer's training sample
weights. It retains the existing representation groups, fit/calibration/held SHA
roles, tree configuration, five seeds (8704–8708), equal-probability ensembles,
software-aware calibration caps, and diagnostic fixed threshold. All four arms
remain: structural control / imports, with prior-only / targeted-added coverage.

For each routed fit class, every representation group receives equal total mass.
A sample's weight is `N / (2 * G_label * n_label_group)`, where `N` is the routed
fit count, `G_label` is the number of routed fit groups in its class, and
`n_label_group` counts routed fit samples in its class/group. Each class keeps
mass `N/2`. Calibration and held membership counts never enter these weights.
Grouping describes representation similarity, not verified malware families.

From the repository root on the VM:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_group_balanced_weighting.py
./.venv/bin/python scripts/reviewer_v8_group_balanced_weighting.py
```

The default uses the newest completed class-balanced five-seed ensemble run.
Add `--run validation-data/<ensemble-directory>` to select explicitly. Original
archives, caches, seed study, and frozen dependencies must remain available.
The baseline training library versions and configuration must match the current
environment. Docker is unnecessary.

The script first replays saved class-balanced seeds and reproduces the entire
baseline ensemble summary and held scores. Then it performs **100 new fits**:
five seeds × five folds × two variants × two coverage arms. It saves fit sample
weights, each seed's models and held predictions, individual-seed variation,
equal-weight ensemble results, paired weighting changes, and the watched groups.
Thresholds are calibrated separately for each changed model/ensemble using the
same original calibration samples and unchanged selection rule. No held search,
seed selection, split search, or relaxed calibration constraint is performed.

A new timestamped output directory is printed before training. To resume:

```bash
./.venv/bin/python scripts/reviewer_v8_group_balanced_weighting.py \
  --resume validation-data/<printed-weighting-directory>
```

Completed seeds are hash-verified and replayed without fitting; an interrupted
seed restarts its 20 fits. If the newest baseline changed, also pass `--run` with
the original baseline directory. Changed inputs or completed artifacts cause
an error. An explicit `--output` must be empty or nonexistent.

Send `group-balanced-weighting-summary.json` from the printed output directory
once complete. This remains a controlled experiment on inspected development
data, not independent validation, a final refit, or a promoted runtime model.
Deployed v7, frozen v8 bundles, prior scripts, and baseline outputs are preserved.
