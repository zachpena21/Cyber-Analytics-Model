# Script workflow index

For model status and measured results, start with the [repository README](../README.md).
Run commands from the repository root; generated data stays in `validation-data/`.

## Current structural v8 workflow

| Tool | Purpose |
|---|---|
| [start_reviewer_diagnostic.ps1](start_reviewer_diagnostic.ps1) | Original-v7 all-route Docker diagnostics on Windows; no change to original weights |
| [reviewer_v8_structural_validation.py](reviewer_v8_structural_validation.py) | Freeze fixed provenance fold 0 and evaluate fresh acquisitions; [instructions](reviewer_v8_structural_validation.md) |
| [collect_reviewer_v8_structural.py](collect_reviewer_v8_structural.py) | Collect against structural frozen exclusions and acquisition cutoff; [instructions](collect_reviewer_v8_structural.md) |
| [collect_reviewer_v8_official_native.py](collect_reviewer_v8_official_native.py) | Resumable checksum-bound official release acquisition of unused large native Windows binaries; [instructions](collect_reviewer_v8_official_native.md) |
| [collect_reviewer_v8_targeted_benign.py](collect_reviewer_v8_targeted_benign.py) | Stage installed Windows target patterns and remove development overlaps on VM; [instructions](collect_reviewer_v8_targeted_benign.md) |
| [reviewer_v8_group_balanced_weighting.py](reviewer_v8_group_balanced_weighting.py) | Fixed-split five-seed experiment changing routed fit weights to equal representation-group mass; [instructions](reviewer_v8_group_balanced_weighting.md) |
| [reviewer_v8_seed_ensemble_calibration_audit.py](reviewer_v8_seed_ensemble_calibration_audit.py) | Read-only ensemble threshold blockers and paired benign calibration score shifts; [instructions](reviewer_v8_seed_ensemble_calibration_audit.md) |
| [reviewer_v8_targeted_seed_ensemble.py](reviewer_v8_targeted_seed_ensemble.py) | Offline equal-probability average of all five seeds with common calibration and fixed splits; [instructions](reviewer_v8_targeted_seed_ensemble.md) |
| [reviewer_v8_targeted_seed_stability.py](reviewer_v8_targeted_seed_stability.py) | Prespecified five-training-seed stability study with fixed coverage splits and resumable seeds; [instructions](reviewer_v8_targeted_seed_stability.md) |
| [reviewer_v8_targeted_coverage_audit.py](reviewer_v8_targeted_coverage_audit.py) | Read-only saved-model audit of coverage regressions and remaining benign misses; [instructions](reviewer_v8_targeted_coverage_audit.md) |
| [reviewer_v8_targeted_coverage_experiment.py](reviewer_v8_targeted_coverage_experiment.py) | Matched control/imports fits with and without targeted benign training coverage; [instructions](reviewer_v8_targeted_coverage_experiment.md) |
| [reviewer_v8_targeted_feature_cache.py](reviewer_v8_targeted_feature_cache.py) | Resumable Docker-parity feature collection for filtered targeted benign samples; [instructions](reviewer_v8_targeted_feature_cache.md) |
| [reviewer_v8_blocker_metadata.py](reviewer_v8_blocker_metadata.py) | Read hash-matched blocker version/import metadata from cached archives |
| [reviewer_v8_rich_pattern_coverage.py](reviewer_v8_rich_pattern_coverage.py) | Recover blocker archive names and inspect original fit/calibration coverage; [instructions](reviewer_v8_rich_pattern_coverage.md) |
| [reviewer_v8_rich_blocker_profile.py](reviewer_v8_rich_blocker_profile.py) | Profile blocking calibration benign files and nearby malware with cached features/tree paths; [instructions](reviewer_v8_rich_blocker_profile.md) |
| [reviewer_v8_rich_calibration_audit.py](reviewer_v8_rich_calibration_audit.py) | Read-only saved-model replay to explain calibration thresholds; [instructions](reviewer_v8_rich_calibration_audit.md) |
| [reviewer_v8_rich_ablation.py](reviewer_v8_rich_ablation.py) | Matched five-way section/import/managed-feature development comparison; [instructions](reviewer_v8_rich_ablation.md) |
| [reviewer_v8_rich_feature_cache.py](reviewer_v8_rich_feature_cache.py) | Collect section/import/CLR features for the next development ablations; [instructions](reviewer_v8_rich_feature_cache.md) |
| [reviewer_v8_structural_feature_diagnostics.py](reviewer_v8_structural_feature_diagnostics.py) | Recollect parity-checked features and analyze completed evaluation errors; [instructions](reviewer_v8_structural_feature_diagnostics.md) |

Keep successful frozen bundles and their dependency files unchanged. New scripts
may be added alongside them. Do not move old scripts into an archive directory:
existing workflows import them and frozen manifests bind their paths/hashes.

## Supporting grouped development experiments

These remain reproducibility tools, not independent final validation:

| Documentation | Experiment |
|---|---|
| [Docker audit](reviewer_v8_docker_audit.md) | Verify frozen reports against runtime features |
| [Docker training](reviewer_v8_docker_train.md) | Runtime-aligned control and expanded-data model |
| [Import experiment](reviewer_v8_import_experiment.md) | Fixed driver-import additions |
| [Grouped experiment](reviewer_v8_grouped_experiment.md) | Group-disjoint development |
| [Grouping controls](reviewer_v8_grouping_controls.md) | Provenance and template split controls |
| [Software calibration](reviewer_v8_software_calibration.md) | Benign software-group constraints |
| [Score ablation](reviewer_v8_score_ablation.md) | Full upstream scores versus structural inputs |
| [Partial ablation](reviewer_v8_partial_ablation.md) | Individual upstream-score removals |
| [Group diagnostics](reviewer_v8_group_diagnostics.md) | Group-weighted metrics and paired changes |
| [Sample diagnostics](reviewer_v8_sample_diagnostics.md) | Feature profiles and score/threshold changes |
| [Bounded upstream](reviewer_v8_bounded_upstream.md) | Constrained score correction with fixed structural trees |

## Earlier references and collectors

The original [v8 workflow](reviewer_v8_workflow.md),
[expanded frozen validation](reviewer_v8_fresh_validation.md) and their related
audits remain intact. They describe earlier stages; use the structural workflow
above for the current primary.

`collect_reviewer_v8_fresh.py`, `collect_reviewer_v8_batches.py` and related
collectors support the current wrapper. The direct MalwareBazaar API collector
may fail with 502 responses; the structural malware command uses hourly batches.

`train_boundary_reviewer*.py/.sh`, `train_modern_adapter*.py/.sh`,
`train_fn_rescue_v1.py/.sh`, earlier evaluators and collection tools are retained
for historical reconstruction. Running them does not deploy a current candidate.

## Tests and local files

Synthetic tests are named `test_*.py`; run the test for the workflow being changed.
For example:

```bash
./.venv/bin/python scripts/test_reviewer_v8_structural_feature_diagnostics.py
```

Some tests require VM development dependencies or local artifacts; blanket test
discovery is not a substitute for the specific workflow's prerequisites.
Model weights and historical split manifests are deliberate tracked inputs.
Sample archives, caches, reports, credentials, and frozen bundles remain local.




