# Rich v8 calibration audit

This read-only development audit uses a completed rich ablation's saved trees,
SHA split manifest, rich feature cache and recorded thresholds. It fits nothing,
changes no saved models, and evaluates alternative thresholds only on the
original calibration rows. Held scores are replayed solely to verify model parity.
No Docker service, archive scan, collection or network access is required.

Run from the repository root using the VM's existing environment:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_rich_calibration_audit.py
./.venv/bin/python scripts/reviewer_v8_rich_calibration_audit.py --debug
```

By default this selects the newest completed template rich ablation, audits the
structural control and plus-imports variant, and creates a fresh timestamped
`validation-data/reviewer-v8-rich-calibration-audit-*` directory. It prints its
path; send `rich-calibration-audit-summary.json` for analysis. The report contains
source/software cohorts and sample SHA references but no sample bytes.

To select a particular completed run:

```bash
./.venv/bin/python scripts/reviewer_v8_rich_calibration_audit.py \
  --run validation-data/reviewer-v8-rich-ablation-development-YOUR-RUN \
  --mode template --debug
```

`--variant` may be repeated to inspect other pre-existing variants. `--output`
must be new or empty. A failed audit never edits a prior run; resolve the cause
before rerunning into another new output directory.

## What the report distinguishes

For each saved fold and ordinary/software policy it reports:

- The reproduced selected threshold and calibration counts.
- The lowest feasible threshold with the same maximum calibration recall.
- The lowest threshold with the same recall, worst constrained FPR and overall
  FPR: this isolates the final preference for a higher threshold.
- The next lower candidate threshold that adds malware detections, its violated
  source/software/overall caps, and up to 100 newly misclassified benign SHA
  references per violated constraint (total counts and truncation are explicit).
- Calibration metrics and constraint violations at the previously fixed diagnostic
  threshold, `0.6397229919376241`.

The candidate grid and lexicographic objective match the existing workflows:
maximize calibration recall subject to at most 1% overall and eligible cohort FPR;
then minimize worst eligible cohort FPR, minimize overall FPR, and prefer the
higher threshold. Sources need at least 100 calibration benign samples to be
constrained; software groups need at least 20. Small groups may effectively allow
zero errors under the cap.

Trees are evaluated with float32 inputs and sklearn's sequential raw-score
accumulation order. This preserves decisions at unique-score/nextafter threshold
boundaries that can be sensitive to floating-point summation. The audit checks
original input hashes, completed cache integrity, disjoint split roles, saved
held score parity, and reconstructed calibration thresholds/counts; discrepancies
stop the workflow. Model exports, manifests and source report hashes are recorded
in the audit's `inputs.json`.

A wide calibration plateau does not demonstrate that its lower edge generalizes
better. These alternatives are explanations, not selected replacement policies.
No held-label threshold tuning, final refit, deployment or independent validation
is performed. Conservative template groups are not verified malware families.
