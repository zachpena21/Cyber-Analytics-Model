# Matched upstream-score feature ablation

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_score_ablation.py
```

The script finds the most recently completed software-calibration development
run and prints its path. Use `--previous validation-data/<run-directory>` to
choose explicitly. It creates a new timestamped output directory automatically,
preserving earlier results. No Docker service or sample execution is needed.

Send `ablation-comparison-summary.json` and the `provenance/ablation-summary.json`
and `template/ablation-summary.json` files from the printed output directory.
Rename uploaded copies so the two panel summaries can be distinguished.

The comparison uses the completed run's exact fitting/calibration/held SHA lists,
including their training order, for both panels. Previous input hashes,
dependencies, feature schema, configuration, seed, group identity, complete SHA
coverage, entropy-invariant group isolation, labels and sources are checked.
All five 72-feature control folds in a panel must reproduce previous held scores
(max absolute error <=1e-10), calibrated thresholds/calibration metrics and all
three policies' held predictions before the ablated model is fitted in that panel.
Dependency drift or reproduction failure stops the workflow; do not loosen checks
to make a changed experiment look matched.

Variants:

| Variant | Reviewer inputs |
| --- | --- |
| `full_72` | Six upstream scores, 60 structural features, six import features |
| `structural_66` | The same 60 structural features and six import features |

Only the reviewer's input matrix changes. Both use the same 128-tree configuration,
seed, class weighting and fitting rows. The adapter remains fixed and determines
routing at .15, including routed fitting samples. Removing upstream inputs does
not remove the adapter's influence on routing. Legacy base/adapter historical
training overlap is unchanged. `max_features=sqrt` remains configured identically;
the feature space and resulting random feature choices differ between variants.

Each variant selects ordinary and software-aware thresholds separately using
identical calibration rows and procedures; calibration, not held-out errors,
determines these thresholds. The existing fixed .639722991937624 threshold is also
reported, although the same numeric threshold need not imply the same operating
point across different models. Infeasible or zero-recall policies are ineligible
and still reported diagnostically. This experiment is not a search for the best
threshold on held-out data.

Outputs include per-fold calibration, eligibility, overall/source/group held
metrics, exact split manifests, per-SHA held scores, paired benign/malware rescues
and regressions, input hashes, excluded SHAs, and development-only generic model
exports. Every export is checked against sklearn on the complete feature pool.
Exports are not supported by the deployed reviewer loader. Paired comparisons use
the same held SHA under each variant's policy in each fold.

This remains development analysis on reused data. Pooled metrics combine distinct
fold models/policies, not one deployable model. No adapter retraining, deployment,
skimmer, package whitelist or modification to frozen v8 is performed. New untouched
data are needed after choosing and freezing a single candidate.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_score_ablation.py' -v
```
