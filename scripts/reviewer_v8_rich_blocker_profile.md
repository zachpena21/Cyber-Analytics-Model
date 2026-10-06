# Rich v8 calibration blocker profile

Profiles the benign calibration files that prevent the import-feature reviewer
from detecting the next malware sample at a lower threshold. Uses only a completed
calibration audit, original cached features and saved fold models. No Docker,
archive reads, downloads, fitting, threshold selection or sample execution.

From the VM repository root:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_rich_blocker_profile.py
./.venv/bin/python scripts/reviewer_v8_rich_blocker_profile.py --debug
```

The default selects the newest completed rich calibration audit and profiles
`plus_imports`. It writes a fresh timestamped
`validation-data/reviewer-v8-rich-blocker-profile-*` directory and prints its path.
Send `rich-blocker-profile-summary.json` for analysis.

Explicit selection:

```bash
./.venv/bin/python scripts/reviewer_v8_rich_blocker_profile.py \
  --audit validation-data/reviewer-v8-rich-calibration-audit-YOUR-RUN \
  --variant plus_imports --variant structural_control --debug
```

A requested variant must have been included in that completed calibration audit.
`--neighbors` defaults to three (allowed 1–10); `--output` must be new or empty.

For each original fold, the report:

- Replays the selected and next-recall calibration counts and finds new benign
  errors in the breached source/software/overall constraints.
- Groups blockers by their entire vector of saved tree leaf IDs. Counts distinct
  float32 model input vectors separately, so a shared prediction is not mistaken
  for identical inputs.
- Records source, inherited label, available filename/path, cached acquisition
  provenance, imports, parser status and all 116 structural/rich feature values.
- Summarizes the representative's most-used path features and largest positive
  tree contributions. Compares blockers with nearby missed calibration malware
  and correctly classified calibration benign files, including different leaves,
  contribution differences and branch decisions.
- Includes differences in the unused section/managed features as potential
  development hypotheses. These are not deployed rules or feature selections.

Nearest neighbors use the selected model's input features. Each original fit
split alone fixes log1p choices, median/IQR normalization (standard deviation
fallback), and clipping to [-20,20]; distance is mean L1. Calibration labels
identify descriptive comparison pools only. Held files are never profiled or
used for neighbor selection. SHA references may appear in several folds in their
original calibration role; they are not independent repeated acquisitions.

Input hashes, source models and completed cache integrity are verified. The audit
and original run remain unchanged. `inputs.json` binds source inputs and the new
script. A failed integrity or replay check stops the workflow.

This exposes available label/provenance evidence; it does not independently
verify publisher identity or ground truth, relabel files, or establish malware
families. Equal leaves and feature differences describe model behavior, not
causal explanations. Missing provenance remains explicit. A future hypothesis
requires a separate controlled development experiment and untouched validation.
