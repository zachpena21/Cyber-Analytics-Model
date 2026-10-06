# Matched targeted benign fit-coverage experiment

This development experiment compares structural control (66 features) and added
imports (90 features), each trained with and without targeted benign fit coverage.
It runs offline from completed caches; Docker does not need to remain running.
No deployed or frozen models, thresholds, or original caches are changed.

From the repository root on the VM:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_targeted_coverage_experiment.py
./.venv/bin/python scripts/reviewer_v8_targeted_coverage_experiment.py \
  --prior-cache validation-data/reviewer-v8-rich-feature-cache-20261006-050159-967490
```

The script automatically selects the newest completed targeted feature cache
matching that prior cache. Override with `--targeted-cache PATH` if needed.
Outputs use a new timestamped `validation-data/reviewer-v8-targeted-coverage-development-*`
directory. To perform a split-only audit, add `--audit-only`; a subsequent training
run must use a new output directory. Send `targeted-coverage-summary.json` after
training, or `coverage-split-audit-summary.json` if planning is blocked.

## Comparison design

- Group the combined pool before assigning five outer template folds, using the
  existing entropy-invariant and rich-shape links. Linked new files cannot cross
  fit, calibration, and held roles. These links are not verified malware families.
- Choose two calibration folds by counts/provenance only. Require the existing
  malware and software diversity checks to pass for both fits and the common
  calibration pool before fitting any model. No seed search or relaxed constraints.
- Within each fold, `prior_only` fits only original samples; `targeted_fit_added`
  also fits new benign samples assigned to that fit role. Both arms use identical
  original calibration and held SHAs. New files assigned to calibration are
  excluded from calibration in both arms; they are not reassigned to fit.
- Calibrate each fit separately on the same original calibration samples under
  the existing overall/source/software FPR caps. This isolates added training
  coverage while allowing the resulting scores to determine their operating point.
- Evaluate original held samples and added held benign samples separately. Every
  SHA is held once per arm. Report paired rescues/regressions for coverage and
  imports; retain the fixed reference threshold only as a diagnostic.

Twenty small GBDT fits use the existing model settings and seed. Fit counts vary
by fold; each summary records how many new files were actually available for fit.
Joint grouping can change splits from the earlier rich experiment. Compare the
matched arms within this run, not raw results against the earlier split panel.

The collector-only `installed:` prefix is removed from package identities in local
working copies for grouping/calibration, so a new installed-directory acquisition
matches the same older directory-derived cohort. No fuzzy aliases or publisher-based
merges are introduced. Directory cohorts remain acquisition evidence rather than
verified independent software/build families, and do not become model inputs.

Before training, the script validates original rich-cache hash bindings, inventory
lineage and raw payload SHAs, targeted schema/coverage, and all saved targeted
Docker features and frozen comparison scores. It replays saved diagnostic payloads
without new service requests. Export parity is checked for every fold/arm, and input
hashes are checked again before marking the final summary complete.

Outputs include `inputs.json`, `split-manifest.json`, `coverage-split-audit-summary.json`,
conservative `excluded-sha256.json`, per-fold development models and held scores,
and `targeted-coverage-summary.json`. Generated models remain development artifacts
and are not runtime candidates or final refits. This post-hoc study requires later
untouched validation; the added batch supplies no new large-native benign coverage.
