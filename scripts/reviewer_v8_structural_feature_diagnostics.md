# Structural v8 post-evaluation feature diagnostics

This script collects Docker feature vectors for every sample in a completed
structural frozen evaluation. It does not fit models, search thresholds, change
routing, or modify frozen scripts, dependencies, models, or manifests.

Keep the original-v7 all-route diagnostic service running. From the repository:

```bash
./.venv/bin/python scripts/test_reviewer_v8_structural_feature_diagnostics.py
./.venv/bin/python scripts/reviewer_v8_structural_feature_diagnostics.py \
  --service-url http://192.168.1.193:8082/
```

Defaults:
- bundle: validation-data/reviewer-v8-structural-frozen-validation
- sources: validation-data/reviewer-v8-structural-fresh-acquisition/sources.json
- evaluation: latest completed reviewer-v8-structural-evaluation-* matching the
  exact freeze-manifest and sources hashes
- output: a new reviewer-v8-structural-feature-diagnostics-* timestamped directory

Use --evaluation PATH to identify a specific completed run. Optional --output PATH
must be empty. --api-timeout defaults to 30 seconds. A failed run has incomplete
diagnostic-inputs.json; rerunning creates a new directory.

Before collection, the script validates the frozen artifacts and dependencies,
completed score/SHA/label/source coverage, summary totals, acquisition timestamps,
current archives, and service configuration. Every recollected score and upstream
component must agree within 1e-9, and every decision must agree exactly. Final
reports require full SHA coverage, no archive read warnings, unchanged service
configuration, unchanged input files, and a second frozen-bundle validation.

Outputs:
- feature-diagnostic-summary.json: cohort counts, SHA lists, score distributions,
  feature distributions and the 12 largest median shifts scaled by the correctly
  classified reference population's IQR.
- error-samples.json: individual structural errors with all scores, full feature
  values, ordinary import libraries and descriptive cohort assignments.
- feature-cache.json: complete 72-feature vectors and prior scores for every SHA.
- excluded-sha256.json: separate conservative union of frozen exclusions and this
  batch for future acquisition workflows. The frozen bundle is not changed.
- diagnostic-inputs.json, acquisition-audit.json and archive-read-warnings.json:
  input binding, completion and archive integrity evidence.

Controls are correctly classified samples of the same label. Malware misses are
separated into gate misses, both-reference detections, v7-only detections,
expanded-only detections and shared misses. The expanded reference uses its
already frozen calibrated policy. Exact structural-input groups use float32
model inputs; they are not verified malware families or near-duplicate clusters.

Profiles are associations, not causal feature explanations. Median shifts with
zero reference IQR are not ranked. Small cohorts and repeated software builds
limit interpretation. Reading these reports does not change weights. If findings
are used to develop or tune a model, record this batch as development data and
obtain another untouched validation batch.

The self-tests use synthetic records only. They check gate/reference separation,
score and decision parity rejection, duplicate/invalid SHA rejection,
same-label control selection, exact-input grouping, and completed-run discovery.
