# Matched rich-feature v8 ablations

Run after successful rich feature collection on the VM. This fits development
reviewers; it does not retrain the base/adapter, fit a skimmer, overwrite a freeze,
select a final replacement, or deploy a model. All 13,245 included samples are
development data, including the previously inspected 618-sample acquisition.

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only
./.venv/bin/python scripts/test_reviewer_v8_rich_ablation.py
./.venv/bin/python scripts/reviewer_v8_rich_ablation.py --debug
```

Docker and further sample downloads are not needed. The script selects the newest
completed `reviewer-v8-rich-feature-cache-*` directory; pass `--cache PATH` to
choose one explicitly. It reproduces the upstream cached scores, verifies the
collection's bound hashes, baseline/provenance records and extra feature schemas,
then creates a new timestamped `reviewer-v8-rich-ablation-development-*` directory.
Keep the existing `.venv` dependency versions; versions are recorded in the run.

## Five variants

| Variant | Features | Inputs |
|---|---:|---|
| `structural_control` | 66 | Existing 60 structural inputs plus six driver-import flags |
| `plus_sections` | 83 | Control plus 17 section features |
| `plus_imports` | 90 | Control plus 24 fixed ordinary-import indicators |
| `plus_managed` | 75 | Control plus nine CLR/managed-PE features |
| `plus_all` | 116 | Control plus all 50 additional features |

The six upstream score/signature inputs are absent from every reviewer's input.
The adapter still controls routing at `0.15`; below that gate the existing adapter
threshold `0.70` applies. Every variant uses the existing 128-tree GBDT configuration,
balanced class weights and fixed seed. New feature dimensions also affect the
existing `max_features="sqrt"` sampling budget; this is a fixed-configuration
comparison, not proof that any single feature causes a result.

## Matched, conservative splits

Both provenance and template panels run by default. Each has five outer folds;
every SHA appears in held data exactly once. For each held fold, two other folds
are calibration and two are fitting (approximately 40%/40%/20%). Counts, grouping
and software/acquisition provenance select calibration folds; scores and errors
do not influence that assignment. All five variants share the identical plan
within a panel. The two panels have different plans and are separate robustness
checks, not ten independent validations.

Existing entropy-invariant aliases and panel links remain together. Additional
links combine the old coarse build template with section count/flag shapes,
normalized import identities and CLR flags. These links omit timestamps, lengths,
entropies, size ratios and URL densities, so similar build shapes can stay together
despite those differences. Labels and sources are absent from the shape key.
These are conservative splitting assumptions, not verified malware families.

Both panels are checked before any fitting. Fit and calibration must each have
at least 20 routed malware, at least three malware groups/representations, no
malware group above 70%, and at least three identified benign software groups
with 20 samples each. If grouping makes that impossible, the script stops and
leaves `grouping-audit.json` files. Inspect those before revising an assumption;
do not split aliases or search seeds until a desired performance appears.

## Calibration and reporting

Each model chooses its own threshold on its shared calibration rows. Ordinary
calibration maximizes recall subject to at most 1% overall benign FPR and per-source
caps for sources with at least 100 benign samples. Software calibration additionally
caps each identified software group with at least 20 benign samples at 1% FPR.
The old fixed threshold `0.639722991937624` is a diagnostic comparison; matching
that numeric threshold does not mean matching an operating point.

Feasible policies with zero recall are explicitly ineligible. Reports preserve
infeasible/zero-recall outcomes rather than dropping their folds. The 95% malware
recall goal is not assumed to be achieved by this experiment.

Outputs include fold thresholds, sample-weighted rates, equal-weighted malware
and benign group rates, per-source and software-group results, and paired malware
recoveries/benign losses versus the newly fitted structural control. The inspected
618-sample subset is reported separately as development data. Export parity must
be within `1e-10` of sklearn scores for every fold; all exported fold models are
marked development-only and unsupported by the production runtime.

Send `rich-ablation-comparison-summary.json` after completion. Keep the detailed
score files, models, grouping audits and split manifests on the VM. If the script
stops during split planning, send each available panel's `grouping-audit.json`
and the error/traceback. No full-data final refit is performed here.

The richer control is refitted on this expanded pool and new split links, so it
is not expected to reproduce an older model's weights or scores. Prior knowledge
of these errors and historical base/adapter overlap mean this remains development
evidence. Any chosen candidate still needs fresh independent acquisitions,
production export/extractor parity, and submission-runtime compatibility checks.
