# Offline group diagnostics for completed partial ablations

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_group_diagnostics.py
```

Selects the most recent completed partial-ablation run and prints its path.
Override with `--previous` if needed. Automatically creates a timestamped output
directory. Requires the cached features, prior reports and exported fold models
on the VM. No Docker service, collection, sample execution or fitting occurs.

Send `group-diagnostic-comparison-summary.json` and both panel
`group-diagnostic-summary.json` files. Identify provenance/template when uploading.
Detailed changed-group files remain available for further investigation.

Before analysis, checks prior input/dependency hashes, current frozen-cache
provenance, pool coverage, schemas, group/split identity, labels, sources, fold
metrics, and complete pooled source/group metrics. Each stored held score is
reproduced from its exported fold model with float32 tree traversal, with maximum
absolute error <=1e-10. Every prediction must match stored scores, original adapter
routing and the recorded threshold. This is verification, not retraining.

For every variant and ordinary/software/fixed policy, reports sample-weighted
metrics and equal-weight recall across all groups containing malware, plus counts
of groups with zero/full recall. Each malware group contributes equally regardless
of size, including mixed benign/malware groups. It also reports equal-weight benign
group FPR. Group definitions differ between panels and are not verified malware
families; singleton groups can make these descriptive metrics noisy. Do not treat
them as confidence estimates or directly compare groups across panel definitions.

The same metrics are reported for all samples, excluding the preidentified
76-malware cluster, and for that cluster alone. Exclusion is a sensitivity report,
not permission to drop hard cases from training or replace headline results.
The full dataset remains the primary report and all reused SHAs stay excluded from
future final validation. The audit stops if the expected cluster identity/count
changes.

Changed-group records compare each challenger with the full reviewer, separately
under each policy, on the same held SHAs. They include sources, counts, benign and
malware rescues/regressions, minimum/p10/median/p90/maximum scores, fold thresholds
and exact changed SHA records. Summary files show the eight largest changes and
counts of malware groups improved/worsened. Detailed files include every changed
group. Score contrasts may span separately calibrated policies and are descriptive
rather than causal explanations. No threshold is chosen using these held results.

Legacy upstream training overlap and the post-hoc development status remain.
No model selection, new model, deployment, skimmer, whitelist, or change to deployed
v7/frozen v8 occurs. Choosing a single candidate and policy still requires a freeze
followed by untouched acquisition data.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_group_diagnostics.py' -v
```
