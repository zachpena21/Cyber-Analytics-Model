# Frozen expanded v8 validation

Keep deployed v7 unchanged. This script freezes the **completed expanded 72-feature candidate**, its calibrated threshold (currently 0.3181019231722836), and a threshold-only variant at **0.639722991937624**. It includes original v7 as a reference. It never trains, recalibrates, or changes routing (0.15).

On the VM:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_fresh_validation.py freeze
```

The command verifies the complete Docker audit, unchanged training input hashes, development split coverage, candidate export schema/parity, and reproduction of stored expanded development scores. It freezes all 11,334 development SHAs and every SHA in CSV reports under `validation-data`. Models and exclusions are hash checked at evaluation. Outputs are local, not deployed or committed.

## Obtain fresh sources

Use different verified software versions or independent trusted installations, especially SciPy/Python extension modules, Git/GNU utilities, and Cura/KiCad. Renaming source IDs or copying the same installations does not create independent data. Use newly acquired malware with recorded collection dates and label provenance; do not execute samples. SHA disjointness alone does not establish software-version or malware-family independence. Preserve existing labels pending a separate provenance review.

Existing Windows benign collector supports explicit roots and evaluation role. After trusted new versions/roots are available, adapt this PowerShell command (the path is an example, not an existing directory):

```powershell
.\scripts\collect_reviewer_v8_benign.ps1 -Roots @("C:\FreshValidation\TrustedSoftware") -SourceId "windows-new-versions-eval" -Role evaluation -Output "validation-data\benign-v8-fresh-evaluation.zip"
```

Transfer the ZIP to VM `validation-data`. Put a JSON source array at `validation-data/v8-fresh-sources.json`. Paths are relative to this JSON file, or absolute. Replace the examples with **actual fresh acquisitions and specific versions/dates/origins**:

```json
[
  {
    "path": "benign-v8-fresh-evaluation.zip",
    "label": 0,
    "source_id": "windows-new-versions-eval",
    "provenance": "Record installer origins and exact software versions; acquired after freezing"
  },
  {
    "path": "malwarebazaar-NEW-EVALUATION-BATCH",
    "label": 1,
    "source_id": "malware-new-acquisition-eval",
    "provenance": "Record actual batch date, acquisition source and label provenance"
  }
]
```

Sources may be files, directories or nested ZIP archives. The existing encrypted-archive reader is reused. Duplicate fresh SHAs are counted; conflicting fresh labels stop evaluation. All recorded development/report overlaps and samples over 16 MiB are excluded and recorded. Both classes must remain after exclusion. Unreadable archive entries stop evaluation so an incomplete scan cannot be presented as complete.

## Score with exact Docker features

On Windows start the **existing rebuilt original-v7 diagnostic image**:

```powershell
.\scripts\start_reviewer_diagnostic.ps1 -Version v7
```

The diagnostic service uses route 0 for all-sample v7 parity checks. Local comparisons retain each model's original route 0.15 and adapter threshold 0.7. The service must expose exact reviewer feature diagnostics, with adapter v2 disabled.

On the VM, after fresh data and the source JSON exist:

```bash
./.venv/bin/python scripts/reviewer_v8_fresh_validation.py evaluate \
  --sources validation-data/v8-fresh-sources.json \
  --service-url http://192.168.1.193:8082/
```

Send `comparison-summary.json` and `comparison-scores.csv` from `validation-data/reviewer-v8-fresh-evaluation`. Model column keys retain helper compatibility: `v8_import_upper` means **expanded calibrated**, and `v8_import_midpoint` means **expanded fixed 0.6397**, not the earlier import-only or midpoint candidate. Human-readable labels are included in the summary. Both expanded policies have identical scores; only thresholds differ. Summary includes per-source results and paired rescues/regressions versus v7.

No final summary is written until every selected SHA is scored, v7 parity passes, and service configuration remains unchanged. Acquisition provenance is user-declared. Do not tune on these results and continue calling them independent evaluation; any later tuning makes the batch development data. Existing output directories are refused; use a fresh `--output` after a failed run. Freeze supports `--training`, `--audit`, `--coverage`, `--reports`, and `--output`; evaluate supports `--bundle`, `--sources`, `--service-url`, `--api-timeout`, and `--output`.
