# Cyber Analytics Malware Defense

A PE malware classifier for the course black-box defense project. The runtime
combines a compact legacy random forest, a modern linear adapter, and an optional
boundary reviewer. Training and diagnostics run separately from inference.

## Current model status — October 5, 2026

| Component | Current state |
|---|---|
| Compact legacy forest | Existing runtime base; benign threshold `0.510001` |
| Modern adapter | Existing coefficients; malware threshold `0.70`; signature-adjusted base verdict is an input |
| Reviewer v7 | Latest tracked runtime reference: `boundary_reviewer_v7_gbdt_candidate`; 66 features, 128 gradient-boosting trees; route `0.15`, threshold `0.6312998096487621` |
| Structural v8 | Current primary research candidate; 66 structural/import features; fixed provenance fold 0 with software calibration; route `0.15`, threshold `0.6882517225516912` |
| Bounded v8 comparison | Same structural trees plus a constrained upstream-score correction; threshold `0.6722878125865038` |
| Original expanded v8 | Preserved 72-feature reference; calibrated threshold `0.3181019231722836`; fixed comparison threshold `0.6397229919376241` |

**Structural v8 is an offline candidate, not a deployed replacement.** Its bundle
lives locally at `validation-data/reviewer-v8-structural-frozen-validation/`.
The original expanded bundle remains at
`validation-data/reviewer-v8-frozen-validation/`. Both are ignored by Git.
The default Docker configuration loads the adapter and leaves the reviewer
disabled; v7 must be explicitly enabled and selected as shown below.

The adapter supplies the routing gate. Routed samples use the reviewer decision;
samples below the route minimum retain the adapter decision. Structural v8 removes
six upstream score/signature features from the reviewer's input, but retains the
adapter routing policy. Its 66 inputs comprise 60 PE structural features and six
driver-import features. It does not introduce a new adapter or a trained skimmer.

## Latest frozen comparison

The October 5 acquisition contains 526 unique benign PEs from 14 Python 3.13
Windows x64 wheels across seven package families, and 92 MalwareBazaar PEs.
Five previously used benign SHAs were excluded during collection; malware
collection reported zero overlaps and stopped at the download budget before
reaching its requested 200 samples. The evaluation scored all 618 retained samples.

| Frozen policy | Benign errors / 526 | FPR | Malware detected / 92 | TPR |
|---|---:|---:|---:|---:|
| v7 reference | 169 | 32.13% | 67 | 72.83% |
| Original expanded v8, calibrated | 163 | 30.99% | 85 | 92.39% |
| **Structural v8 primary** | **2** | **0.38%** | **75** | **81.52%** |
| Bounded comparison | 2 | 0.38% | 75 | 81.52% |

These are observed results on this particular acquisition, not hidden-course
performance. SHA disjointness and post-freeze collection do not establish
software-family/version or malware-family independence. Benign wheels include
familiar package families/versions. The 92 malware samples also limit precision.
The project goals remain FPR at most 1% and TPR at least 95%; structural v8 does
not meet the latter goal on this batch.

Evaluation completed without threshold tuning. v7 service parity error was at
most `3.33e-16`; subsequent recollection reproduced every recorded score exactly.
The bounded comparison made no classification changes from the primary.

All 17 structural malware misses were routed. Four were detected by both older
references, eight only by expanded v8, and five by neither. The two benign errors
were in Pillow 12.3.0 and lxml 6.1.3. Feature diagnostics suggest testing section
measurements, import identities, managed-PE metadata, and broader benign coverage.
These are development hypotheses, not deployed rules or causal explanations.

The acquisition has now been inspected for future feature design. Retain the
original frozen comparison as recorded evidence; if it informs fitting or tuning,
treat these 618 SHAs as development and obtain another untouched validation batch.

## Repository layout

| Path | Purpose |
|---|---|
| `defender/` | Docker build context, inference service, model artifacts and API tests |
| `scripts/` | Collection, training, validation and diagnostic tools; see [workflow index](scripts/README.md) |
| `validation-data/` | Local samples, caches, reports, frozen bundles and diagnostic copies; ignored by Git |
| `docs/history/` | Historical setup and development notes |

Tracked old model artifacts and experiment scripts are retained for reproducibility.
Frozen bundles bind script/dependency hashes, so moving or modifying those scripts
can invalidate existing runs. Reconstructed v4/v5 model JSONs are build products;
their committed chunk files remain authoritative.

## Runtime reference: build and select v7

Stage the verified course forest before the first build:

```bash
python scripts/stage_model.py /path/to/NFS_21_ALL_hash_50000_WITH_MLSEC20.zip
docker build -t blackbox-defense:v7-reference ./defender
```

The build converts the supplied sklearn forest into memory-mapped arrays.
The staged pickle and generated compact arrays are not tracked.

Run the existing v7 cascade locally:

```bash
docker run --rm --name blackbox-defense-v7 \
  -p 8080:8080 --memory=1g --cpus=1 \
  -e DF_MODEL_THRESH=0.510001 \
  -e DF_ENABLE_BOUNDARY_REVIEWER=1 \
  -e DF_REVIEWER_DIR=/opt/defender/defender/models/boundary_reviewer_v7_gbdt_candidate \
  blackbox-defense:v7-reference
```

The request interface is `POST /`, an octet-stream PE body, and JSON
`{"result":0}` for benign or `{"result":1}` for malware.
`GET /healthz` checks readiness and `GET /model` reports configuration.

```bash
curl -sS -X POST --data-binary @sample.exe \
  -H 'Content-Type: application/octet-stream' http://127.0.0.1:8080/
```

Scoring and feature diagnostic endpoints are disabled by default. Keep them
disabled in any final submission.

## Current research workflow

Use the existing VM `.venv` and update with `git pull --ff-only origin main`.
Do not overwrite an existing successful freeze or recreate it merely to change
its acquisition cutoff.

1. [Structural freeze and evaluation](scripts/reviewer_v8_structural_validation.md):
   verifies prior grouped controls and freezes existing provenance fold 0.
   This is not a final full-data refit.
2. [Structural collection](scripts/collect_reviewer_v8_structural.md):
   reads the new frozen exclusions, collects benign wheels and hourly malware
   batches, and writes timestamped `sources.json`. The hourly collector avoids
   the MalwareBazaar API path that previously returned repeated 502 errors.
3. Evaluate the frozen policies using original-v7 Docker features.
4. [Post-evaluation feature diagnostics](scripts/reviewer_v8_structural_feature_diagnostics.md):
   recollects exact features, verifies all prior decisions/scores, and compares
   errors with correctly classified controls of the same label.

For the existing frozen bundle, start the all-route diagnostic service on
Windows PowerShell. This helper makes a separate diagnostic model copy, stops
Docker containers occupying the requested host port, and preserves original weights:

```powershell
.\scripts\start_reviewer_diagnostic.ps1 -Version v7 -Image blackbox-defense:v7-reference
```

Its diagnostic route is zero to expose every score. Offline evaluation still
uses each frozen policy's original route; the all-route service is not the
production policy. The default host port is 8082.

On the VM, after fresh collection:

```bash
./.venv/bin/python scripts/reviewer_v8_structural_validation.py evaluate \
  --sources validation-data/reviewer-v8-structural-fresh-acquisition/sources.json \
  --service-url http://192.168.1.193:8082/
```

Substitute the Windows host IP if different. For diagnostics of a completed run:

```bash
./.venv/bin/python scripts/test_reviewer_v8_structural_feature_diagnostics.py
./.venv/bin/python scripts/reviewer_v8_structural_feature_diagnostics.py \
  --service-url http://192.168.1.193:8082/
```

The diagnostic selects the latest completed evaluation matching the exact
bundle/source hashes; `--evaluation PATH` selects an explicit run. It writes a new
timestamped output directory with `feature-diagnostic-summary.json`,
`error-samples.json`, and a complete `feature-cache.json`.

Keep malware encrypted at rest and read samples in memory in the isolated VM.
Never execute samples or commit samples, acquisition credentials or local reports.
Source labels are inherited from their publishers/providers, not independently
verified ground truth.

## Submission compatibility: work still required

The supplied October 5 instructions require exactly one Dockerfile of at most
100 KiB in the ZIP, with required COPY inputs inside its containing build context.
They describe approved Python 3.11/3.12 slim images, a 300-second build limit,
startup on port 8080 within 25 seconds, non-root execution, a read-only filesystem,
no runtime network, 1 CPU and 1 GiB RAM.

**The current Dockerfile uses Python 3.9 and legacy dependencies. It is not yet
compatible with the advertised submission base-image policy.** Migrating it is a
separate runtime/parity task; changing dependencies without validating extracted
features can change model scores. Exact approved image pins and the full HTTP,
resource and qualification rules must be checked on the platform Rules page when
accessible. Do not assume that a successful ZIP upload is a qualification result.

Before submission: migrate and parity-check the approved runtime, package only
inference inputs, disable diagnostics, and measure clean build time, startup,
memory and latency under the stated restrictions. No platform qualification or
hidden evaluation result has been obtained.

## Historical references

The [archived baseline README](docs/history/baseline-readme.md) preserves the early
adapter/reviewer results and setup notes. Those measurements used earlier
development batches and are not the current model status.

Upstream base:
[2021 Machine Learning Security Evasion Competition](https://github.com/fabriciojoc/2021-Machine-Learning-Security-Evasion-Competition).
