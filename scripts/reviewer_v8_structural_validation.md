# Freeze the structural primary and bounded comparison before fresh acquisition

On the VM:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_structural_validation.py freeze
```

Upload `validation-data/reviewer-v8-structural-frozen-validation/freeze-manifest.json`.
The freeze requires a completed bounded-upstream experiment and verifies both
grouping panels, every prior model's held scores/gates, correction exports,
split identity, paired accounting and input/dependency hashes.

The primary is the **existing provenance fold 0 structural-only model**, with its
existing software-calibrated threshold. The comparison is the same fold's bounded
correction with its own existing software-calibrated threshold. Fold zero is a
fixed index, not the best held-performing fold. No fitting, threshold selection,
new fold search, averaging or final refit occurs. Approximately 40% of the prior
pool fitted those trees and 40% calibrated that fold; all fitting, calibration
and inspected held samples are excluded from future untouched evaluation. Pooled
five-fold development metrics are not performance estimates for this one frozen
model. A later full-data refit would require a separate calibration/freeze.

The bundle includes immutable copies of both candidates, their selected split,
threshold policies, original v7/expanded-v8 references, source hashes and exclusions.
Exclusions union the 12,627-sample development pool, old frozen exclusions, all
recorded CSV SHAs, and prior exclusion lists. The command prints the actual count.
The bundle is separate from deployed v7 and the existing frozen expanded v8.
Model exports remain offline-only; this workflow does not deploy them.

Default input selection is the latest completed bounded-upstream run. Use
`--previous` for an explicit directory. Existing nonempty freeze output is refused;
do not overwrite a successful freeze to change its timestamp. Keep the bundle and
scripts unchanged during evaluation. Hashes protect model/exclusion/script identity.

## Acquire new validation data after freezing

Use independently obtained benign installations/software versions and newly
acquired malware with documented dates/origins/labels. Do not reuse the former
fresh batches that were incorporated into development. Changing source names,
repackaging archives, or copying old binaries does not make them independent.
Samples are never executed. SHA disjointness does not prove family/version independence.

Create `validation-data/v8-structural-fresh-sources.json` with actual source paths,
specific provenance and **actual ISO timestamps with timezones** after the manifest's
`frozen_at`. The following is a schema example, not usable acquisition metadata:

```json
[
  {"path":"NEW-BENIGN.zip","label":0,"source_id":"specific-software-version",
   "provenance":"Actual trusted installer origin and version",
   "acquired_at":"REPLACE-WITH-ACTUAL-TIMESTAMP-AFTER-FREEZE"},
  {"path":"NEW-MALWARE-DIRECTORY","label":1,"source_id":"specific-acquisition-batch",
   "provenance":"Actual collection origin, date and label provenance",
   "acquired_at":"REPLACE-WITH-ACTUAL-TIMESTAMP-AFTER-FREEZE"}
]
```

Paths may be relative to the source JSON, absolute files, directories or encrypted
nested archives. Acquisition timestamps are user-declared, not independently proved.
Oversize samples and SHA overlaps are excluded and reported; unreadable entries
and conflicting labels stop evaluation. Both classes must remain, unless explicitly
running a supplemental `--benign-only` cohort. Do not tune using validation outcomes.

## Exact-feature validation

On Windows, use the existing original-v7 diagnostic service:

```powershell
.\scripts\start_reviewer_diagnostic.ps1 -Version v7
```

On the VM, after actual new acquisitions and their source JSON exist:

```bash
./.venv/bin/python scripts/reviewer_v8_structural_validation.py evaluate \
  --sources validation-data/v8-structural-fresh-sources.json \
  --service-url http://192.168.1.193:8082/
```

No new Docker deployment is required. The diagnostic supplies exact feature vectors,
import libraries and upstream scores. Original v7 must reproduce its all-route
service scores, while local comparisons retain the frozen route 0.15 and adapter
threshold 0.7. Structural predictions use the vector without six upstream features,
plus existing import flags; only the bounded comparison reads correction inputs.
Model/exclusion hashes and service configuration are checked again at completion.

Evaluation creates a timestamped directory and prints its path. Upload
`comparison-summary.json` and `comparison-scores.csv`. The summary identifies the
fixed primary and descriptive comparison, plus original v7 and expanded-calibrated
v8 references, overall/source rates and paired changes against the primary.
Comparisons do not authorize swapping the primary after inspecting validation.
Any subsequent tuning makes the reused validation SHAs development data.

```bash
./.venv/bin/python -m unittest discover -s scripts -p 'test_reviewer_v8_structural_validation.py' -v
```
