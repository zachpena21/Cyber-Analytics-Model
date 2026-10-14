# Defender development history and current model

Updated October 14, 2026. This records the important iterations leading to the
current whitebox model, including unsuccessful experiments and measured tradeoffs.
The current defense combines the original compact forest, the retained linear
modern adapter, the frozen structural v8 reviewer at threshold **0.60**, and an
agreement rescue. Its standalone whitebox ZIP passed the recorded qualification.

See the [project README](../README.md) and [package instructions](../docs/whitebox-submission-package.md).
This `defender/` directory is still the **legacy research Docker context**.
Building it alone does not select the final whitebox policy. The final ZIP has
its own Python 3.11 Dockerfile, bundled models and `defender.whitebox_main` entrypoint.

## Reading the evidence

- **TPR** is malware detected / malware samples. **FPR** is benign files wrongly
  flagged / benign samples. **pp** means percentage points. Counts accompany rates.
- Calibration data informed model or threshold selection. It is not an independent
  test. Evaluations become development data after they inform later changes.
- Panels changed across versions. A lower calibration FPR on a different panel
  does not establish an improvement over the preceding version. Matched controls
  are identified below; no significance tests or hidden-test guarantees are claimed.
- SHA-disjoint samples can still share software versions or malware families.
  Runtime parity proves consistency, not classification accuracy.
- Adapter versions, reviewer versions, batch numbers and runtime formats are
  separate naming tracks. Early “adapter v4” is not reviewer v4.

## Current configuration and checkpoints

| Component | Current whitebox state |
|---|---|
| Original forest | 100 trees, 250,041 transformed inputs; base benign threshold `0.510001`; original forest weights retained |
| Modern adapter | Linear model, 250,042 inputs, malware threshold `0.70`; signature-adjusted base trigger included |
| Reviewer | 128 gradient-boosting trees from frozen structural v8 provenance fold 0; route minimum `0.15` |
| Reviewer features | 66 active structural/import inputs in a 72-field runtime vector; six upstream score/signature placeholders unused by the trees |
| Reviewer threshold | `0.60`, changed from blackbox `0.6882517225516912`; no whitebox refit |
| Rescue | Adapter >=0.99, base benign <=0.20, reviewer >=0.30, adjusted base trigger still 1, no verified Microsoft override |

Routed samples normally use the reviewer verdict; below the route minimum the
adapter decides. The rescue can change only an otherwise benign verdict to malware.
It never suppresses a detection or changes a raw reviewer score. No sample hashes,
filenames or family labels are used by the rescue at inference. Model scores are
not treated as calibrated confidence probabilities.

| Branch / artifact | Purpose |
|---|---|
| `main` | Current verified whitebox work and package evidence |
| `checkpoint/blackbox-v8-submission` | Exact blackbox checkpoint at `c3d9228` |
| `whitebox-v8-threshold-060` | Threshold-only fallback at `1aaf7bb` |
| `whitebox-v8-phorpiex-rescue` | Retained development history, squash-merged into main |
| [Blackbox ZIP](../submission/reviewer-v8-submission.zip) | Original submission, preserved through Git LFS |
| [Whitebox ZIP](../submission/reviewer-v8-whitebox-submission.zip) | Qualified standalone rescue defense, preserved through Git LFS |

## 1. Supplied forest, threshold and compact runtime — September 21–23

The starting classifier was the supplied 2021 MLSEC
`NFS_21_ALL_hash_50000_WITH_MLSEC20` forest. Its inherited benign-score threshold
was `0.75`; that starting value did not establish compliance with the course's
<=1% FPR and >=95% TPR targets. The forest itself was not retrained.

Development selected **`0.510001`**: the base predicts malware when benign
probability is below that threshold. At score `0.51`, one malware and three
valid Microsoft-signed Windows files collided. A narrow Authenticode check
retained benign verdicts only for the verified Microsoft files. It was not a
blanket signed-file bypass. No reliable matched aggregate before/after report
for this initial threshold adjustment is retained here, so none is invented.

The roughly **2.0 GiB resident sklearn forest** was converted into about
**325 MiB of memory-mapped arrays**. Historical measurements recorded about
105 MiB idle RSS and 317 MiB after inference. A five-row equivalence smoke test
had **0.0 maximum probability difference**. This improved deployability, not
learned detection. The service also added one-time model loading, non-root
execution, a health endpoint, a 16 MiB request cap, octet-stream validation and
fail-closed parser handling. A small benign-PE smoke run took 46–62 ms; it was
not an efficacy evaluation.

Sources: [archived baseline](../docs/history/baseline-readme.md),
[compact runtime](defender/models/compact_model.py),
[baseline commit](https://github.com/zachpena21/Cyber-Analytics-Model/commit/d767608).

## 2. Modern linear adapter and serving correction — September 23

The modern adapter addressed distribution shift from the older forest's data.
It used the existing transformed forest features plus a legacy-verdict feature.
An early additive policy was explored; the retained design lets the adapter
decide using that verdict as an input, rather than permanently OR-ing every
base detection into the output.

Source-aware development used **99 malware and 2,831 benign files**: 1,831 older
benign for fitting, 500 newer benign for calibration and 500 for a within-run
benign holdout; malware split 79/20 between fitting/calibration.

On the **same 500 benign holdout files**, the legacy control had **13 FP (2.6%)**
and the adapter **1 FP (0.2%)**: **12 fewer FP, -2.4 pp FPR**. Calibration gave
20/20 malware detections and 2/500 benign errors (0.4%). The benign-only holdout
contained no malware and therefore supplied no held-out TPR estimate.

A later 1,000-benign / 36-malware audit initially reported **34 FP (3.4%)**,
**36/36 TP**, zero errors, 75 ms mean and 528 ms maximum response time. Serving
was corrected to use the same **signature-adjusted legacy trigger** expected
by the adapter policy, and exact production-score diagnostics were introduced.
The decision threshold was raised from `0.4836661988928846` to **0.70**.
The selected policy on the now-inspected audit recorded **5/1,000 FP (0.5%) and
36/36 TP**: 29 fewer benign errors, -2.9 pp FPR. Serving policy and threshold
both changed, so this is not an isolated threshold-effect estimate. The audit
had become development data; the retained adapter weights were not retrained.

Sources: [adapter metadata](defender/models/modern_adapter/metadata.json),
[historical audit](https://github.com/zachpena21/Cyber-Analytics-Model/commit/f8cd7e0),
[serving correction](https://github.com/zachpena21/Cyber-Analytics-Model/commit/c1b1904).

## 3. Boundary reviewer v1 — September 24

Added a gated second-stage reviewer to suppress adapter false positives while
preserving detections. It was a **128-tree depth-2 random forest**, with 53
upstream/structural/text-summary features. Route minimum was **0.50** and
reviewer threshold `0.6831506122881276`. On its calibration panel it removed
all five adapter false positives while retaining **19/20 malware detections**.
It remained opt-in pending later evaluation.

## 4. Reviewer v2 — September 25

Merged more corpora using SHA deduplication and source/class-aware splits.
The pool grew to **4,999 files (4,831 benign / 168 malware)**. The selected
reviewer had **192 depth-3 trees**, route 0.50 and threshold
`0.3263099058569006`. On its own calibration panel it removed 27 adapter false
positives and recovered one adapter miss. A later v6 acquisition exposed
**8.8% benign FPR**, motivating another distribution update rather than trusting
the strong calibration result.

## 5. Reviewer v3 — September 25

Added the inspected distribution-shift batch. The pool became **6,010 files
(5,831 benign / 179 malware)**. The selected model used **192 depth-5 trees**,
54 realized features, route 0.50 and threshold `0.4852782217812828`. The general
feature recipe remained; realized counts can also change with categorical
vocabularies. Calibration removed 60 adapter false positives while retaining
all 36 malware. However, a later batch missed **2/7 malware** despite zero
benign errors. That batch then became development data for v4.

## 6. Reviewer v4 — September 25

Added the inspected v8 acquisition, reaching **7,017 files (6,831 benign /
186 malware)**. Selected 192 depth-5 trees, minimum leaf size 4, route 0.50 and
threshold `0.4121798812058857`. Calibration reduced adapter benign errors
**80 -> 1**, preserving **37/37 TP**. Compressed/chunked model transport and
build-time reconstruction resolved artifact-transfer problems; those fixes
were not additional accuracy improvements.

## 7. Reviewer v5 — September 28

Jointly calibrated **routing and reviewer threshold**: a reviewer cannot rescue
malware that never reaches it. Selection prioritized malware routing coverage.
The chosen 192-tree depth-2 model used route **0.30**, threshold
`0.4870135287958894` and **8,020 files (7,831 benign / 189 malware)**.
Calibration retained **38/38 TP** and reduced adapter FP **97 -> 11**.
This does not establish universal superiority over v4; the panel had changed.

### Matched adapter controls for reviewers v1–v5

Each row compares the reviewer and frozen adapter on **that row's same
calibration panel**. Adjacent rows are not the same evaluation set.

| Reviewer | Benign / malware | Adapter FP -> reviewer FP | Adapter FPR -> reviewer FPR | Adapter TP -> reviewer TP | Measured benefit |
|---|---:|---:|---:|---:|---|
| v1 | 1,000 / 20 | 5 -> 0 | 0.50% -> 0% | 19 -> 19 | -5 FP; unchanged TPR |
| v2 | 966 / 34 | 27 -> 0 | 2.80% -> 0% | 33 -> 34 | -27 FP; +1 TP |
| v3 | 1,166 / 36 | 61 -> 1 | 5.23% -> 0.086% | 36 -> 36 | -60 FP; unchanged TPR |
| v4 | 1,366 / 37 | 80 -> 1 | 5.86% -> 0.073% | 37 -> 37 | -79 FP; unchanged TPR |
| v5 | 1,566 / 38 | 97 -> 11 | 6.19% -> 0.702% | 38 -> 38 | -86 FP; unchanged TPR |

Sources: [v1 metadata](defender/models/boundary_reviewer/metadata.json),
[v2](defender/models/boundary_reviewer_v2_candidate/metadata.json),
[v3](defender/models/boundary_reviewer_v3_candidate/metadata.json),
[historical v4](https://github.com/zachpena21/Cyber-Analytics-Model/blob/f6a04bbd37c65afcc3394cbe99c92f1e142c4a90/defender/defender/models/boundary_reviewer_v4_candidate/metadata.json),
[v5](defender/models/boundary_reviewer_v5_candidate/metadata.json), and
[compact metric transcription](../docs/history/model-development-metrics.json).

## 8. Adapter v2/v2.1, FN rescue and reviewer v6 — September 28

An always-on nonlinear stacked adapter combined upstream scores with PE
structure. The recorded adapter-v2 ExtraTrees candidate had 256 depth-5 trees,
56 inputs, and calibration **42/42 TP, 9/1,766 FP (0.51%)**. It was an
experimental branch, not the adapter retained in the final defense.
Source-constrained adapter v2.1 and a separate v5 false-negative rescue
experiment followed. Their retained workflows do not establish a comparable
independent gain, so none is claimed. Today's whitebox rescue is a different rule.

Reviewer v6 tested RandomForest/ExtraTrees configurations and routes under
**per-source FPR constraints and leave-one-source-out (LOSO) diagnostics**.
This addressed pooled calibration masking weak new-source performance. Its
trainer and analyses are retained, but a complete selected-result artifact is
not tracked with the current model; a numerical v5-to-v6 gain cannot be verified
from those retained repository artifacts.

Sources: [adapter-v2 metadata commit](https://github.com/zachpena21/Cyber-Analytics-Model/commit/7647128),
[adapter v2.1 trainer](../scripts/train_modern_adapter_v2_1.py),
[FN rescue trainer](../scripts/train_fn_rescue_v1.py),
[v6 trainer](../scripts/train_boundary_reviewer_v6.py).

## 9. Reviewer v6.1: derived features — September 29

Added ten relationships: code/file and virtual/file ratios, imports/exports
per section, section density, export-table indicators, architecture/PE32+
interactions and a modern-linker indicator. The selected **66-feature random
forest** used route **0.20**, threshold `0.6905770973703483`, depth 4 and
minimum leaf size 4. Calibration was **38/42 TP (90.48%), 1/1,766 FP (0.057%)**.
The v10 LOSO result was **16/20 TP (80%) and 1/1,000 FP**: feature engineering
had not solved source generalization.

Source: [v6.1 metadata](defender/models/boundary_reviewer_v6_1_candidate/metadata.json).

## 10. Reviewer v7: gradient boosting — September 29

Changed model family while retaining the 66-feature representation and
source-aware diagnostics. Selected **128 depth-3 boosting trees**, learning
rate 0.1, minimum leaf size 8, route **0.15**, threshold `0.6312998096487621`.
Recorded calibration became **41/42 TP (97.62%), 1/1,766 FP**: three more
detections and +7.14 pp TPR versus v6.1's reported calibration at the same
class counts. The v10 source holdout improved to **18/20 TP (90%), 0/1,000 FP**.
The v9 LOSO run detected 3/3 but flagged 9/1,000 benign files. These separately
selected source-development configurations do not isolate a model-family
effect, and the v10 TPR remained below the 95% goal.

Sources: [v7 metadata](defender/models/boundary_reviewer_v7_gbdt_candidate/metadata.json),
[exporter](../scripts/export_boundary_reviewer_v7_gbdt.py).

## 11. V8 reconstruction, expansion and import features — September 30–October 3

V8 began with a v7 error audit, additional benign/malware coverage and a
runtime-aligned refit control. Archive recovery and required-SHA checks prevented
silent sample loss. Exact runtime vectors exposed LIEF flag spelling, ordinary
versus delay-load import differences, export-name limits and stale text fields.
Explicit **float32 tree inputs** restored sklearn-compatible traversal. These
were measurement/parity fixes, not learned detection gains. Reconstructed
frozen v7 scoring error was about **1.11e-16**.

The runtime-aligned 128-tree refit, route 0.15 and threshold
`0.7250447982089809`, recorded **46/47 calibration TP (97.87%), 0/2,084 FP**.
One source holdout still had **139/589 benign errors (23.60%)**, showing the
limits of pooled calibration.

Six fixed driver-import features were added: presence of `ntoskrnl.exe`,
`hal.dll`, `ndis.sys`, `wdfldr.sys`, `ks.sys`, and their count. The 72-feature
import candidate achieved **47/47 TP and 0/2,084 FP on the shared calibration**:
**+1 TP, +2.13 pp TPR, no new FP**. Its fixed comparison threshold was
`0.639722991937624`. The later expanded-data import candidate had separately
calibrated threshold `0.3181019231722836`; these are different experiment states.

Threshold-interval and linker/symbol/debug/TLS experiments followed; optional
runtime format 9 supported build indicators, but these did not enter final v8.
Provenance/software-template grouping, reviewer-only controls and out-of-fold
upstream inputs were added to examine leakage and source dependence. A skimmer
was explored but is **not** part of the current model. No independent gain is
claimed for these exploratory branches.

Sources: [v8 audit](../scripts/reviewer_v8_workflow.md),
[imports](../scripts/reviewer_v8_import_experiment.md),
[threshold/build follow-up](../scripts/reviewer_v8_followup.md),
[grouped experiments](../scripts/reviewer_v8_grouped_experiment.md),
[historical metric excerpts](../docs/history/model-development-metrics.json).

## 12. Structural-only v8, bounded comparison and frozen evaluation — October 4–5

Upstream-score ablations removed six base/adapter score, trigger and signature
fields from the reviewer trees. The resulting **66 active structural/import
features** differ from v7's 66 inputs, which included upstream fields. A bounded
upstream-logit correction was tested separately but not selected for deployment.

Existing provenance **fold-0** structural trees were frozen by fixed index,
not by choosing the best held fold. There was **no final full-data refit**.
Blackbox route remained **0.15**, threshold **`0.6882517225516912`**.
All policies below scored the same new 526-benign / 92-malware acquisition
before its errors informed richer development.

| Policy on the same 618 files | FP / 526 | FPR | TP / 92 | TPR |
|---|---:|---:|---:|---:|
| Frozen v7 reference | 169 | 32.13% | 67 | 72.83% |
| Expanded v8, calibrated | 163 | 30.99% | 85 | 92.39% |
| Structural v8 selected for blackbox | 2 | 0.38% | 75 | 81.52% |
| Bounded structural comparison | 2 | 0.38% | 75 | 81.52% |

Against v7, structural v8 gave **167 fewer FP and eight more TP**:
**-31.75 pp FPR and +8.70 pp TPR** on this cohort. Against expanded v8, it gave
**161 fewer FP but ten fewer TP**. It was selected for its low-FPR tradeoff,
not because it dominated every alternative or already met 95% detection.
The bounded comparison changed no decisions on this cohort.

Sources: [selection record](../docs/reviewer-v8-final-selection.md),
[structural validation](../scripts/reviewer_v8_structural_validation.md),
[selected metadata](defender/models/boundary_reviewer_v8_final/metadata.json).

## 13. Rich features and coverage experiments, not promoted — October 6–12

Collected **50 additional features** for **13,245 files (12,764 benign /
481 malware)**: 17 section, 24 ordinary-import and nine managed-PE features.
These were new fitted development models, not the final frozen fold-0 model.
Shared template-grouped folds gave:

| Variant | TP / 481 | FP / 12,764 | Delta versus newly fitted structural control |
|---|---:|---:|---|
| Structural control | 220 | 12 | Reference |
| Plus sections | 195 | 23 | -25 TP, +11 FP |
| Plus ordinary imports | 229 | 13 | +9 TP, +1 FP |
| Plus managed-PE features | 222 | 12 | +2 TP, same FP |
| All blocks | 199 | 11 | -21 TP, -1 FP |

Import gains were concentrated in two of five folds. Conservative provenance
links formed a large component that prevented the predeclared diversity rules;
template results did not establish software-family independence.

Calibration audits found that lower thresholds adding malware detections
breached source/software FPR caps, with historical benign files and Windows Kits
recurring as blockers. Targeted Windows coverage, fixed-seed stability,
equal-weight five-seed ensembles and group-balanced weights were investigated.
More data or richer features did not consistently improve malware recall.

In the matched native-coverage imports experiment, the earlier-coverage ensemble
gave **307/481 TP, 24/12,764 FP**, versus **290/481 TP, 14/12,764 FP** after
native-fit coverage: **10 fewer FP but 17 fewer TP**, comprising **20 lost
detections and three rescues**. The 76-sample watch group remained missed.
This was not promoted. These rejected candidates remain research references.

Sources: [rich ablation](../scripts/reviewer_v8_rich_ablation.md),
[targeted coverage](../scripts/reviewer_v8_targeted_coverage_experiment.md),
[seed ensembles](../scripts/reviewer_v8_targeted_seed_ensemble.md),
[group weighting](../scripts/reviewer_v8_group_balanced_weighting.md),
[native audit](../scripts/reviewer_v8_native_coverage_audit.md),
[final dispositions](../docs/reviewer-v8-final-selection.md).

## 14. Freeze, Python 3.11 migration and blackbox packaging — October 13

The chosen structural fold-0 trees were exported into a 72-field runtime vector
by shifting feature indices; the first six upstream fields remained unused.
All **13,245 cached scores reproduced bit-for-bit**, with zero changed decisions.
No refit or seed change was added.

Exported preprocessing parameters replaced loading an old sklearn preprocessing
pickle in Python 3.11. The standalone image retained compact forest arrays and
adapter coefficients. LIEF compatibility restored ordinary-import conventions,
forwarded-export names and the legacy **300-byte export-name limit**. Initial
feature drift was corrected until **16/16 Windows files** and a bounded
**64 benign + 64 malware** cohort passed with zero feature/decision mismatches.
The largest later score difference was about **2.2e-16**. These were parity
results, not 128/128 correct classifications.

The recorded blackbox package build took **50.0 seconds**, restricted startup
**2.39 seconds**, and process peak memory about **553 MiB**. The original ZIP
and exact submission checkpoint were preserved.

Sources: [blackbox package evidence](../submission/package-validation.json),
[runtime regression](../submission/runtime-validation.json),
[finalization](../scripts/finalize_reviewer_v8.md).

## 15. TA feedback and whitebox threshold-only fallback — October 14

The TA's 50-benign / 50-malware evaluation gave **47/50 TP (94%), 0/50 FP,
97% accuracy**. It missed the separate >=95% detection cutoff; at this sample
size at least **48/50** detections were required. Benign files were Microsoft
Sysinternals utilities.

All three misses were **Phorpiex**. Their adapter scores were approximately
**0.99594, 0.99594, 0.99774**, but reviewer scores were **0.33689, 0.60237,
0.60237**. They were routed correctly: the reviewer overruled the strong adapter
scores. Of the 41 Phorpiex files in this set, submitted v8 detected 38.

The first whitebox change preserved weights and route, lowering only the
reviewer threshold to **0.60**. Cached replay and actual Docker scoring gave
**49/50 TP (98%), 0/50 FP, 99% accuracy**: **+2 TP, +4 pp TPR**, with no new
TA benign errors. This artifact/branch remains the threshold-only fallback.

On the **same earlier 618-file cohort**, detection stayed **75/92** while
benign errors rose **2 -> 5 out of 526**: FPR **0.38% -> 0.95% (+0.57 pp)**.
New errors were in scikit-learn, Pillow and lxml files. The threshold change
therefore had a real historical tradeoff and little FPR margin below 1%.

Sources: [t060 workflow](../docs/reviewer-v8-whitebox-t060.md),
[paired comparison](defender/models/boundary_reviewer_v8_whitebox_t060/whitebox-candidate-comparison.json).

## 16. Phorpiex agreement rescue: current inference change — October 14

The last miss's reviewer score was about **0.3369**. Lowering the global
threshold enough to recover it would also flag benign files. A fixed agreement
rule instead requires a routed, otherwise benign t060 verdict, **adapter >=0.99**,
**base benign <=0.20**, adjusted base trigger **1**, no verified Microsoft
override, and **reviewer >=0.30**. The remaining miss met these conditions:
adapter 0.995939, base benign 0.17, reviewer 0.336895.

The rule was manually specified using a disclosed miss, not learned by refitting
the reviewer or adapter. The actual Docker run confirmed **50/50 malware and
50/50 benign correct**, zero scoring errors and **exactly one rescued verdict**
beyond t060. Every feature vector and raw reviewer score was checked against
t060; only the expected verdict changed.

### Matched progress on the same TA set

| Policy | TP / 50 malware | TP / 41 Phorpiex | FP / 50 benign | Accuracy | Change versus prior row |
|---|---:|---:|---:|---:|---|
| Submitted blackbox v8 | 47 (94%) | 38 (92.68%) | 0 | 97% | Baseline |
| Threshold 0.60 | 49 (98%) | 40 (97.56%) | 0 | 99% | +2 TP, +4 pp TPR |
| Threshold 0.60 + rescue | 50 (100%) | 41 (100%) | 0 | 100% | +1 TP, +2 pp TPR |

### Rescue regression checks

| Panel | t060 | t060 + rescue | Change introduced by rescue |
|---|---|---|---|
| TA tuning set | 0/50 FP; 49/50 TP | 0/50 FP; 50/50 TP | 0 new FP; +1 TP |
| Earlier 618-file cohort | 5/526 FP; 75/92 TP | 5/526 FP; 75/92 TP | No changes |
| Full cached development pool | 41/12,764 FP; 339/481 TP | 41/12,764 FP; 339/481 TP | All 13,245 decisions unchanged |

Nine historical reports additionally covered **3,933 unique benign files**;
no benign observation met even the upstream rescue gate. They overlap and are
not an additional independent test. No-new-FP means relative to **t060**, not
the original blackbox threshold: the three historical errors introduced by
lowering to 0.60 remain. The rescue may add FP on unseen data. TA-set 100% is
tuning performance, not a general Phorpiex recall estimate or hidden-test guarantee.

Sources: [rule](defender/reviewer_rescue.py),
[full pool](../docs/evidence/phorpiex-rescue-full-pool.json),
[Docker result](../docs/evidence/whitebox-v8-rescue-runtime-summary.json),
[experiment details](../docs/reviewer-v8-phorpiex-rescue.md).

## 17. Standalone whitebox package and qualification — October 14

Reused the verified blackbox forest, adapter, preprocessing and dependencies.
Bundled the t060 reviewer, rescue rule and a dedicated entrypoint that enables
and verifies this policy. Removed the old blackbox reviewer/entrypoint from this
build context. The ZIP has one root Dockerfile, no malware, no required external
model files, and diagnostics disabled by default. It needs no research repository
for inference.

| Exact-ZIP qualification | Result |
|---|---:|
| Clean build | 32.55 seconds |
| Restricted startup | 1.79 seconds |
| Public malware / benign correct | 50/50 and 50/50 |
| Scoring errors | 0 |
| Maximum public request | 0.42 seconds |
| Process peak memory | 494 MiB |
| Cgroup-reported peak | 369 MiB |
| Restrictions | One CPU, 1 GiB cap, read-only root, no network, non-root, no OOM |

Process and cgroup memory are different accounting measures; both were below
the cap. Different package timing/memory runs do not establish a controlled
model speedup. The PowerShell readiness fix changed qualification tooling only,
not the ZIP or predictions. The TA set had informed tuning before this test.

Qualified ZIP SHA-256:
`c493bf7dbf934f3fd81d1013e60606a6da7372adf2bc4f544cf3ac9023eea05d`.
Its internal manifest records preparation state; the separate report records
the later passed qualification. Exact course base-image pin confirmation remains
unrecorded. Original blackbox and threshold-only checkpoints remain intact.

Sources: [qualification](../submission/whitebox-qualification.json),
[package summary](../submission/whitebox-package.json),
[reproduction instructions](../docs/whitebox-submission-package.md).

## Reproduction and artifact scope

Extract the final whitebox ZIP and build from its root Dockerfile; use the
[qualification workflow](../docs/whitebox-submission-package.md) to repeat the
recorded checks. For **legacy research only**, the old context remains usable:

```bash
python scripts/stage_model.py /path/to/NFS_21_ALL_hash_50000_WITH_MLSEC20.zip
docker build -t blackbox-defense:v7-reference ./defender
```

That research image defaults to the modern adapter with boundary review disabled.
Enable/select a reviewer with `DF_ENABLE_BOUNDARY_REVIEWER=1` and
`DF_REVIEWER_DIR`; it is not the final whitebox entrypoint. Training and analysis
commands are indexed in the [scripts README](../scripts/README.md). Samples,
feature caches and most full development reports remain in ignored
`validation-data/`. Retained metadata, source workflows, historical commits and
compact evidence reports support this history. Missing early measurements are
identified rather than reconstructed from memory.
