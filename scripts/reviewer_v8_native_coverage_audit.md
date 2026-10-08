# Native coverage regression audit

Run from the repository root after native coverage recovery finishes:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_native_coverage_audit.py
./.venv/bin/python scripts/reviewer_v8_native_coverage_audit.py
```

The default is the newest completed native coverage run; use `--run PATH` for
an explicit run. Docker is unnecessary. This command neither trains models nor
modifies existing experiment files, calibration, splits, or deployment.

For a quick saved-JSON and hash check without feature replay or scoring:

```bash
./.venv/bin/python scripts/reviewer_v8_native_coverage_audit.py --check-json-only
```

The full audit also performs this preflight. Parse failures identify the exact
filename, its byte size, and the full traceback. If preflight passes but the full
audit fails, retain that traceback: it will distinguish a saved input from a
temporary replay artifact. Do not delete or replace the reported file before
the failure is diagnosed.

Input, cache, split and completion hashes are checked. Every saved seed summary,
held score and decision, plus the equal five-seed ensemble, must reproduce before
the audit writes a new output directory. The verified recovery array scorer is
used for replay. A changed ensemble score is rejected even if its gate is unchanged.

Send **native-coverage-audit-summary.json** from the printed directory. It includes:

- All malware regressions/rescues and benign rescues/regressions under software
  calibration and the historical fixed threshold, with fold-specific SHA lists.
- Descriptive old/new threshold swaps to separate score and threshold shifts.
- Structural/import model inputs and rich section/import/CLR feature profiles.
- Raw sample medians and medians of representation-group medians, with cohort
  and library counts; groups do not establish malware family identity.
- Nearest native files eligible for fit in that held fold only. IQR scaling
  uses the previous fit rows, with unit scale for constant features.
- Per-seed changed tree paths and raw leaf contributions, plus the existing
  76-sample watch group representative even if its decision never changed.

The main detailed comparison uses the imports model. Both structural and imports
arms are replayed. Distances and tree-path changes describe associations; they do
not prove why a file is benign or malicious. Per-seed raw contributions do not
sum to the change in ensemble probability. Threshold swaps are diagnostics,
not suggested thresholds. These remain inspected development data.
