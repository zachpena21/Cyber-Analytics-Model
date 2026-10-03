# Matched partial upstream feature ablations

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_partial_ablation.py
```

Automatically selects the most recently completed score-ablation run, prints its
path, and creates a timestamped output directory. Override with `--previous` or
`--output` if needed. Requires all prior artifacts on the VM. No Docker service,
network collection or sample execution is needed.

Send `partial-ablation-comparison-summary.json` and each panel's
`partial-ablation-summary.json`. Identify provenance/template when uploading.

| Variant | Removed from the full reviewer |
| --- | --- |
| `full_72` | Nothing; reproduced control |
| `structural_66` | All six upstream features; reproduced challenger |
| `without_adapter_71` | Only `adapter_probability` |
| `without_base_69` | `benign_probability`, `base_trigger_raw`, `base_trigger_adjusted` |

Both partial variants retain `signature_checked` and `signature_verified`, the
same structural/import features, and byte entropy. The upstream block includes
probabilities and indicators, not six probabilities. This does not separately
ablate the signature indicators or identify causal mechanisms.

The exact fitting/calibration/held SHA lists and training order come from the
completed software-calibration run associated with the previous ablation. Inputs,
dependency hashes, split manifests, labels, sources, group isolation, configuration
and seed are verified. Both previous controls must reproduce all five held score
folds (max absolute error <=1e-10), calibration thresholds/metrics and policy
predictions in a panel before either new partial variant is fitted in that panel.
Failure stops the experiment instead of relaxing parity or splitting groups.

All four models use the same fitting rows, balanced class weights, 128-tree
configuration and seed. `max_features=sqrt` selects eight features per node for
all four schemas, but feature identity/random draws and fitted trees still
differ. Compare predictions, not equal tree paths.

The adapter still supplies .15 routing and routed fitting selection even when its
probability is excluded from reviewer inputs. Base/adapter weights and all gates
are fixed. Legacy historical upstream-training overlap remains.

Each model calibrates its own ordinary/software-aware threshold on identical
calibration SHAs, using the existing procedures; no held-out score or error picks
thresholds. The fixed .639722991937624 policy is also reported, although equal
numeric thresholds do not guarantee equal operating points. Infeasible/zero-recall
policies remain explicitly ineligible. Results include fold/source/group metrics,
paired rescues/regressions against both controls, complete per-SHA held scores,
excluded SHAs, input hashes and generic development-only exports checked against
sklearn on the complete feature pool. Exports are unsupported by the deployed
reviewer loader.

This is post-hoc development on reused data, not independent final validation.
Pooled results combine fold models/policies. No deployment, skimmer, software
whitelist, adapter retraining or modification of frozen v8 is performed. A chosen
single candidate and policy must be frozen before new untouched validation data.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_partial_ablation.py' -v
```
