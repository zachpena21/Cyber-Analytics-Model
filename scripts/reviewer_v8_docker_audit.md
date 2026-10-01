# Exact Docker feature audit before v8 retraining

Collect the current Docker runtime's original-v7 feature vectors and component
scores for the full existing reviewer development pool (10,650 unique SHA in the
current reports) and all additional coverage samples (684 in the completed
comparison). Compare the VM training cache with Docker and examine every frozen
v8 import candidate error on coverage. No fitting, calibration, new gates, or
deployment changes occur.

Use the rebuilt original-v7 all-route diagnostic container from the coverage
comparison. It must expose opt-in feature diagnostics, use original v7's saved
threshold, route minimum zero, adapter threshold 0.7, and adapter v2 disabled.
There is no need to rebuild/restart if that container is still running.

From the VM:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_docker_audit.py \
  --service-url http://192.168.1.193:8082/
```

This is a larger run: it submits 11,334 unique PE byte payloads to the existing
Docker scoring service. It reads archives in memory and never executes samples
or extracts them to disk. Progress prints every 25 samples; checkpoints save
every 250 and on caught errors. The default PE search root is `validation-data`.
If original samples are elsewhere, supply repeatable `--location` roots/ZIPs
that together contain both the old pool and additional coverage samples.
Unreadable archive members are logged; every required SHA must still be found.

Defaults:

- Original cache: `validation-data/reviewer-v8-development/feature-cache.json`.
- Coverage manifest: `validation-data/reviewer-v8-coverage-development/coverage-manifest.json`.
- Completed comparison: `validation-data/reviewer-v8-coverage-comparison-docker-features`.
- Output: `validation-data/reviewer-v8-docker-audit`.

Supply `--cache`, `--coverage`, `--comparison`, or `--output` if your successful
runs used different locations. Original files and deployed models are read-only.

Resume after a disconnect or an interrupted run using the same command/options
with `--resume` appended:

```bash
./.venv/bin/python scripts/reviewer_v8_docker_audit.py \
  --service-url http://192.168.1.193:8082/ \
  --resume
```

Resume checks the manifest, original cache, reports, prior comparison, frozen
model hashes, service configuration, SHA set and locations. It also rechecks
checkpoint vectors, components, labels and frozen scores. Changed inputs require
a fresh output directory. A process killed without an exception may lose work
since the most recent 250-sample checkpoint. Scoring is idempotent.

Outputs:

- `docker-audit-summary.json`: feature difference counts, maximum differences,
  isolated score/prediction impact, upstream component differences, all-sample
  v7 service parity, and reproduced coverage metrics.
- `coverage-error-audit.json`: every v8 false positive and false negative, exact
  Docker feature values, largest additive tree contributions with branch paths,
  and nearest correctly classified samples from the original fit split.
- `cache-differences.json`: per-SHA feature differences and model score impact.
- `docker-feature-cache.json`: exact Docker vectors, ordinary import libraries,
  fresh components, labels, original source IDs, frozen model scores and gates.
- `run-inputs.json`, `archive-read-warnings.json`, and failure diagnostics.

Send `docker-audit-summary.json` and `coverage-error-audit.json` first. Keep the
Docker feature cache on the VM for subsequent controlled training. Do not replace
the old cache with it: its schema and provenance differ.

Cache comparisons use exact structural equality and a 1e-12 upstream-component
tolerance. Scores compare both feature versions using the same fresh Docker
components, isolating feature effects. Import-identity changes are checked even
when all shared structural values match. Changed predictions use each frozen
model's original route minimum and threshold. Every Docker reference score must
match v7 within 1e-9, and coverage results must reproduce the completed comparison.

Neighbors use the preserved original fitting split only, no calibration or
coverage rows. Distance excludes component scores and added import flags; shared
structural features are log1p transformed, standardized using fitting-only
median/IQR (std fallback), then compared with clipped mean absolute distance.
They are diagnostic similarities, not evidence of malware-family independence.
Tree contributions describe additive score terms and observed branches; they
are not causal attributions. Labels come from existing reports and the audited
coverage manifest. Malware coverage source IDs use the inventory's original
input location rather than assigning them to the Windows benign acquisition.
These are development diagnostics, not final independent evaluation.

Tests:

```bash
./.venv/bin/python scripts/test_reviewer_v8_docker_audit.py
```
