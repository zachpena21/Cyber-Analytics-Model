# Paired sample diagnostics for the two broader challengers

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_sample_diagnostics.py
```

Uses the latest completed group-diagnostic run; override with `--previous`.
Creates a timestamped output directory. No Docker, acquisition, sample execution,
fitting, threshold selection or deployment is required.

Upload `sample-diagnostic-comparison-summary.json` and both provenance/template
`sample-diagnostic-summary.json` files. The panel summaries contain feature profiles;
the comparison contains compact counts, threshold margins and overlap tables.
Detailed `structural_66-*-changed-samples.json` and
`without_adapter_71-*-changed-samples.json` files contain exact changed SHAs,
all 72 cached diagnostic features, source/group/fold, scores, thresholds and margins.
Removed upstream features are retained only for analysis of the sample cohorts.

Prior cache/input/script hashes and every held score, gate and prediction are
verified through the original partial-ablation exports before analysis. Group
definitions, split identities and original paired/pooled metrics must reproduce.
The full and structural controls are verified without retraining.

For each challenger and policy, cohorts are rescued, regressed, unchanged wrong
and unchanged correct, separately for benign and malware. Overlap tables show
which outcomes both challengers share on identical SHAs. Source/fold counts and
group counts are included. Profiles describe sample-weighted feature distributions
against unchanged-correct samples of the same label, with median shifts divided
by reference IQR where nonzero. Constant features retain raw statistics; they are
not ranked using an arbitrary denominator. No significance or causal claim is made.
Small cohorts and repeated groups can distort these descriptive contrasts.

Reviewer margin is score minus that fold's threshold, only for routed samples.
Margin delta equals score delta minus threshold delta. Correctness contributions
reverse the sign for benign samples, since lower margins help benign classification.
Counterfactuals hold either the old threshold or the old score fixed while retaining
the original adapter gate. A flip can occur with either change alone, both, or
require the combined changes. These describe arithmetic decision boundaries,
not feature attribution, calibrated probability quality or tested routing policies.
They must not be used to select thresholds on held data.

All cohorts remain post-hoc development data, including former fresh acquisitions.
No deployed v7/frozen v8 changes occur. Final validation still requires untouched
acquisitions after a candidate/policy freeze.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_sample_diagnostics.py' -v
```
