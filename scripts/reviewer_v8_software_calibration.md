# Software calibration development experiment

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_software_calibration.py
```

Uses existing verified Docker feature caches offline. No Docker service or sample
execution is needed. Previous results, deployed v7 and frozen v8 are unchanged.
Requires the completed provenance control in the default previous directory.

Output: `validation-data/reviewer-v8-software-calibration-development/`.
Send `software-error-audit.json`, `grouping-summary.json`,
`calibration-comparison-summary.json` and both panel `control-summary.json` files
(rename uploaded copies to identify provenance/template).

The descriptive audit uses previous provenance fixed-threshold false positives
for Git and SciPy, comparing feature quantiles with correctly classified samples
of the same software, other correctly classified routed benign samples, malware
sharing coarse templates, and all routed malware. Contrasts are exploratory
median differences scaled by pooled feature standard deviations. They are not
causal explanations, feature importance, or independent validation. Package names
are used for analysis and splitting; they are not model inputs or bypass rules.

Both holdout panels retain their previous grouping rules and also link identical
float32 structural/import representations after excluding the six upstream scores
and byte entropy. Entropy remains a model input. This conservative grouping
captures entropy-only variants but does not prove byte-level relatedness or
capture all near duplicates. It applies without label filtering, in both panels.

Each of five outer folds is held out once. Two remaining folds calibrate and two
fit, so the approximate allocation is 40/40/20. Both fitting and calibration must
pass the previous malware diversity checks using entropy-invariant fingerprints,
and contain at least three identified software groups with at least 20 benign
samples each. Fold choice maximizes count-based software coverage without seeing
scores/errors. Unknown software provenance is reported, not invented. If these
checks cannot be met the workflow stops and preserves completed diagnostics;
use a new `--output` for reruns. `--audit-only` skips training.

Each fold fits just one 72-feature reviewer. Ordinary calibration retains the
existing overall 1% FPR cap and per-source 1% caps for sources with at least 100
benign samples. Software-aware calibration adds 1% caps for identified software
cohorts with at least 20 benign samples. With fewer than 100 benign samples, this
permits zero false positives, an intentionally strict development sensitivity
check. These thresholds are empirical constraints, not statistical guarantees.
Both policies maximize calibration recall subject to their constraints. Neither
uses held-out scores to choose thresholds. Infeasible and zero-recall policies
are explicitly ineligible but their diagnostic results remain reported.

The existing fixed threshold .639722991937624 is also evaluated. Policies within
this run share the same fitting, calibration and held-out partitions, enabling
paired comparisons. Previous runs used other grouping/fitting allocations; their
numbers cannot isolate the effect of the new calibration policy. Pooled scores
combine different fold models and thresholds, not a deployable single model.
Generic development-only exports are verified against sklearn on the full pool;
the deployed reviewer loader does not support them. No skimmer is trained.

Legacy base/adapter historical training overlap remains. Recent acquisitions are
already development data. Outputs record hashes, split manifests and every reused
SHA in the exclusion list. Final validation requires untouched acquisitions after
freezing a chosen single candidate and its policy.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_software_calibration.py' -v
```
