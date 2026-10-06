# Read-only targeted coverage regression audit

Run offline on the VM after completing the matched coverage experiment:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_targeted_coverage_audit.py
./.venv/bin/python scripts/reviewer_v8_targeted_coverage_audit.py
```

The default selects the newest completed targeted coverage run. Override with
`--run PATH` if needed. Send `targeted-coverage-audit-summary.json` from the new
printed `validation-data/reviewer-v8-targeted-coverage-audit-*` directory.
Docker is not needed. Original cache and inventory source archives must remain
available for their existing integrity checks.

The audit binds and verifies the experiment scripts, original/targeted caches,
raw SHA provenance, saved models, split manifest and held score files. It replays
all 20 saved models and checks calibration decisions, held scores/predictions,
fold metrics and pooled metrics before describing the regressions. Float32 inputs
are compared as Python floats against the exported double thresholds; raw scores
accumulate tree contributions in training order.

The summary includes:

- Imports coverage rescues/regressions by fold, grouped by the existing joint
  representation links, with member SHAs and score ranges.
- Four fixed descriptive contrasts per fold: each old/new model at each saved
  old/new threshold. These distinguish model-score changes from threshold changes;
  there is no held threshold search and these contrasts propose no new policy.
- A representative of each of the largest 12 fold-4 regression groups, plus
  every remaining added benign false positive under the augmented imports model.
- For those representatives: cached features/provenance, the largest five tree
  contribution changes with before/after paths, and up to three nearest added
  fit files under normalization learned only from that fold's original fit rows.

Tree indices across refits are comparative contributions, not aligned semantic
rules. Nearby training files are not evidence of causal influence. Representation
links are not verified malware families; inherited benign labels and recorded
publisher metadata are not independently verified ground truth. The analysis is
post-hoc development and does not justify promotion without untouched validation.

No models are trained, thresholds changed, samples executed, or source files
modified. Outputs are only the new audit summary and its input-hash manifest.
