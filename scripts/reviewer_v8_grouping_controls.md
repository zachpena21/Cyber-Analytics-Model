# Grouping audit and reviewer-only controls

Run on the VM after the previous grouped experiment completed:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_grouping_controls.py
```

No Docker service, network collection, sample execution or feature re-extraction
is needed. The script uses the same complete audit caches, frozen-model hashes
and completed-evaluation provenance checks as the previous experiment. It first
audits the largest mixed component and largest malware-only component, then fits
only the existing 72-feature reviewer configuration in two separate panels.
Deployed v7, frozen v8 and historical reports remain unchanged.

Default output: `validation-data/reviewer-v8-grouping-controls-development/`.
Send these files:

- `grouping-audit-summary.json`
- `control-comparison-summary.json`
- `provenance/control-summary.json`
- `template/control-summary.json`

The two control summaries have the same basename; upload them separately or
rename copies to identify their panel. Detailed component files, split manifests
and held-out score records stay in the output directory for further inspection.
Use `--audit-only` to generate just the component diagnostics. Every invocation
requires an empty output directory; use a new `--output` for repeated runs.

## Component audit

The prior group manifest must exactly match the current pool and reconstructed
old grouping. Previous labels and sources are checked against the cache. The
audit reports cross-cohort coarse-template links, constant/variable structural
features, float64/float32 unique vector counts, representation-alias counts,
zero-section/import/virtual-size counts and unique prior model scores.

An identical representation is not evidence of identical bytes or a malware
family. Zero fields alone do not establish extraction failure. Historical report
names without software/acquisition metadata are reported as unresolved cohorts.
No labels are changed and no suspicious samples are removed.

## Separate holdout panels

| Panel | Groups kept together | What can cross splits |
| --- | --- | --- |
| `provenance` | Identified software/package families across versions, documented acquisitions, plus exact structural/import representations | Coarse build/import templates shared by different provenance groups |
| `template` | Coarse structural/import templates plus exact structural/import representations | Software/acquisition cohorts containing multiple templates |

The previous union of both coarse rules is retained only for auditing. Its scores
remain valid historical development results; the revised controls do not replace
or rewrite them. Both new panels keep exact float32 structural vectors plus
normalized ordinary-import basenames together. This is a representation-based
duplicate safeguard, not verified near-duplicate binary detection. Six fixed
upstream scores are excluded from these representation fingerprints.

Every panel's split manifest reports provenance, template and representation
overlaps between fitting, calibration and held-out pools. Thus software holdouts
and template holdouts can be interpreted separately. Neither proves malware
family independence, and neither is an independent final test.

## Calibration diversity

Five outer folds each hold out one complete group partition. Calibration uses
one of the remaining folds if it passes these predeclared development checks:

- At least 20 reviewer-routed malware samples.
- At least three malware groups and three distinct structural/import representations.
- At most 70% of routed calibration malware in one group.

The fitting pool must meet the same checks. If no single calibration fold works,
two can be combined, leaving the others for fitting. The choice uses counts and
group identities only, never model scores or error status. The script stops if
there is no qualifying plan rather than splitting an alias group. These numerical
checks are development design choices, not statistical guarantees of sufficient
coverage. Acquisition/software metadata can be incomplete in historical data.

Threshold selection retains the previous 1% overall and eligible-source benign
FPR caps and malware-recall objective. A zero-recall calibration policy is now
explicitly marked ineligible even when its FPR constraint is feasible. Results
are still reported, without selecting a replacement threshold from held-out data.
Controls also report the pre-existing fixed threshold .639722991937624.

Each SHA is held out once per panel. Pooled results combine fold-specific
thresholds and are not one deployable model. Exports are development-only generic
tree payloads, checked against sklearn with float32 scoring on the complete pool;
they are not supported by the deployed BoundaryReviewer loader.

Base and adapter remain fixed legacy models with their historical training
overlap unchanged. All recent batches have already become development data.
The root `excluded-sha256.json` records every reused SHA and frozen exclusion
for a future validation freeze. A new untouched final acquisition is required.
No enhanced reviewer or skimmer is trained in this step.

## Verification

```bash
./.venv/bin/python -m unittest discover -s scripts \
  -p 'test_reviewer_v8_grouping_controls.py' -v
```
