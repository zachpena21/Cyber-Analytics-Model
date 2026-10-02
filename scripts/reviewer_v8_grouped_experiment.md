# Grouped reviewer and skimmer experiment

Run on the VM after completing both fresh error audits. This is offline: Docker,
network access and original sample archives are not needed. It reads complete
Docker feature caches and completed evaluations. Samples are never executed.

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_grouped_experiment.py
```

Default inputs:

- `validation-data/reviewer-v8-frozen-validation/`
- `validation-data/reviewer-v8-docker-audit/docker-feature-cache.json`
- `validation-data/reviewer-v8-fresh-error-audit/`
- `validation-data/reviewer-v8-fresh-git-error-audit/`
- Matching `reviewer-v8-fresh-evaluation/` and `reviewer-v8-fresh-git-evaluation/` directories.

Default output: `validation-data/reviewer-v8-grouped-experiment-development/`.
Send `experiment-summary.json` and `group-manifest.json`. The run fits multiple
models and prints progress after cache checks, each inner fold and each outer
fold. A fresh output directory is required. To repeat a run, use a new `--output`.

## What is compared

| Variant | Inputs | Fitting |
| --- | --- | --- |
| `refit_72` | Existing 66 Docker features plus six kernel import indicators | Same 128-tree configuration as v8, refitted on each outer fitting pool |
| `enhanced` | Above plus 14 build/import indicators | Same fitting pool and 128-tree configuration |
| `skimmer` | Enhanced features plus reviewer score and five score-zone indicators | 64 depth-two trees fitted using group-out-of-fold reviewer scores |

The 14 indicators describe linker-2 combinations, symbols/debug/TLS, managed
runtime imports, Cygwin/MSYS imports, CRT imports, C++ runtime imports,
crypto/network imports, distinct ordinary-import library count and sparse imports.
They do not use filenames, source identity, software names from provenance, labels,
or hashes. Ordinary imports only; no sample re-extraction or new extractor.

The skimmer applies to reviewer-routed samples with base/adapter/reviewer
disagreement, linker-major 2, a managed-runtime import, or at most three imports.
Other samples keep the enhanced reviewer's calibrated verdict. This gate is an
error-derived development hypothesis. It is not an allowlist. Zone definitions
use the existing base threshold .510001, adapter .7 and fixed reviewer .639722991937624.
The reviewer middle-zone feature spans .3181019231722836 through .85.

## Isolation and limits

Five outer group folds each use one held-out fold, the next fold for calibration,
and the remaining three for fitting. Each SHA is held out once. Three inner group
folds cross-fit the enhanced reviewer **only inside the outer fitting pool** to
generate skimmer fitting inputs. Outer calibration and held-out rows never fit
either stage. Their first-stage scores come from the outer fitted reviewer.

Connected groups combine entire identified software/package families across
versions, documented malware acquisition batches, and exact structural/import
templates across all labels and sources. Template keys exclude labels, hashes,
names and upstream scores. Transitive links are retained. Historical mixed report
names alone are not treated as documented acquisitions. Grouping does not prove
malware-family independence. `group-overview.json` records group sizes and class
counts. The script stops rather than split a connected group to repair a
single-class fold.

Reviewer and skimmer thresholds use only their outer calibration pool, with a
1% overall benign FPR cap and the existing cap for individual sources containing
at least 100 benign calibration samples. The objective maximizes malware recall,
then minimizes worst source FPR and overall FPR. A policy with no feasible
threshold is explicitly ineligible, and its fallback results are labeled. The
summary also shows reviewer results at the fixed existing .6397 threshold.
Pooled held-out results combine fold-specific thresholds, not a single deployable
model. Per-source/per-group results show uneven performance.

Only the **reviewer** score used for skimmer fitting is cross-fitted. Base and
adapter remain fixed legacy models, whose historical training overlap is not
removed. Do not describe this as fully out-of-fold validation of the entire stack.
Feature/gate hypotheses were informed by previous errors, so these are development
comparisons even when groups are isolated.

Using the two recent evaluation batches here makes all their SHAs development
data. `inputs.json` records that conversion without modifying historical reports.
`excluded-sha256.json` includes the frozen exclusions and every reused SHA; use
these exclusions in the next final-validation freeze. Acquire a new untouched
test batch after selecting and freezing a candidate.

Each fold exports development-only tree JSON for both reviewers and the skimmer.
Every exported tree is checked against sklearn with float32 inputs on fitting,
calibration and held-out vectors. These generic experiment payloads are **not
supported by the deployed BoundaryReviewer loader**. No deployment, runtime schema
change or final refit is performed. Review the experiment before implementing the
selected candidate's runtime and obtaining independent final validation.

## Files to inspect

- `experiment-summary.json`: completion, configurations, calibration feasibility,
  pooled/per-fold/per-source/per-group results and paired changes.
- `group-manifest.json`: SHA group assignments and outer/inner fitting splits.
- `development-scores.json`: one outer held-out prediction per SHA per variant.
- `group-overview.json`: class/source counts for connected groups.
- `fold-*/skimmer-oof-scores.json`: cross-fitted reviewer scores and skimmer gate.
- `inputs.json`, `excluded-sha256.json`: input hashes and future test exclusions.

```bash
./.venv/bin/python -m unittest discover -s scripts \
  -p 'test_reviewer_v8_grouped_experiment.py' -v
```
