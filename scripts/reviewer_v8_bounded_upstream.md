# Bounded upstream correction development experiment

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_bounded_upstream.py
```

Selects the latest completed sample-diagnostic run; `--previous` overrides it.
Outputs go to a new timestamped directory. Cached features and completed model
exports are required. Docker, collection and sample execution are not needed.

Upload `bounded-upstream-comparison-summary.json` and both provenance/template
`bounded-upstream-summary.json` panel files.

## Candidate defined before this run

Reuse each outer fold's existing structural-only 128-tree model. Fit a four-parameter
logistic correction on that fold's routed fitting rows only. Inputs are the base
benign probability, adapter probability and two signature indicators, centered
within [-1,1]. Redundant base-trigger flags are omitted. No intercept or category
gate is fitted. Each coefficient is constrained to [-0.125,0.125], so the entire
correction is bounded by +/-0.5 log-odds for any valid input. This is a meaningful
influence limit, not a rescaling of features offered to unrestricted trees.

Fit uses class-balanced logistic loss with the structural logit as a fixed offset,
L2 penalty 0.01, deterministic zero initialization and bounded L-BFGS-B. Only one
budget/configuration is tested; no parameter sweep or held-data selection occurs.
Structural fitting predictions are in-sample, so this is a limited residual-fit
experiment, not an independently cross-fitted stacking study. A saturated structural
fit may produce weak corrections; report that result rather than changing the budget
after examining held outcomes. Base/adapter historical training overlap remains.

The structural trees and upstream models are not retrained. Calibration uses the
same held-out calibration rows and existing ordinary/software FPR constraints.
Each candidate gets its own calibration thresholds, plus the fixed diagnostic
threshold. A bound on score correction does not constrain threshold movement or
guarantee a bound on false positives. Probabilities are clipped to [1e-12,1-1e-12]
before computing logits; zero correction preserves them to numerical precision.

Prior hashes, group/split identity, all four existing fold exports, stored held
scores, predictions and metrics must reproduce before correction fitting. Each
new fold export includes its structural model and correction, and is checked after
JSON round-trip on the entire development pool. These are unsupported development
exports; they cannot be loaded as production reviewers.

Reports include full/structural/no-adapter controls, source errors, sample/group
recall, sensitivity excluding the known 76-malware cluster, paired rescues/regressions
against every control, fold coefficients, correction distributions and calibration
eligibility. The full dataset remains the primary result; excluding the cluster is
a sensitivity analysis. Compare policies within each grouping panel. Group metrics
do not establish malware-family generalization.

All reused SHAs remain excluded from future final validation. Neither deployed v7
nor frozen v8 is modified. A favorable development result still requires a single
candidate/policy freeze and untouched acquisitions before deployment.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_bounded_upstream.py' -v
```
