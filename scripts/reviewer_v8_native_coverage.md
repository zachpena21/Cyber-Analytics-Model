# Native coverage development comparison

This returns to class-balanced routed reviewer fitting. It compares the previous
coverage (original data plus the earlier targeted files) with that same coverage
plus the newly collected official native files. Both structural control and import
features use all five existing seeds, with equal probability averaging. It reuses
verified previous models and performs 50 new fits. Docker is unnecessary here.

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_native_coverage.py
./.venv/bin/python scripts/reviewer_v8_native_coverage.py
```

Defaults select the latest completed class-balanced ensemble and the latest
completed official-native feature cache matching its original rich cache.
Use `--run PATH` and `--native-cache PATH` to select these explicitly.
For a split audit without training, add `--audit-only`. The printed output
directory contains `native-split-audit-summary.json`. Conflicting representation
links stop before fitting; send that audit if this happens. Old files never move
to resolve a conflict. A clean audit-only output can subsequently be trained with
`--resume PATH`.

Resume an interrupted run using its printed output directory:

```bash
./.venv/bin/python scripts/reviewer_v8_native_coverage.py --resume PATH
```

Completed seeds are hash-checked and reused; an incomplete seed is refitted.
Source inputs, dependency versions, configuration and splits must still match.
The script writes new outputs only and preserves all earlier models and bundles.

Old fit/calibration/held roles stay fixed. Joint representation groups are
recomputed including native files; links crossing old roles or held folds stop
the experiment. Linked new files inherit the existing group's outer fold. Novel
groups receive a deterministic SHA-derived fold, without balancing or searching.
New files assigned to calibration roles are excluded; the exact earlier
calibration SHAs and software constraints remain unchanged. Existing calibration
exclusions for the earlier targeted files also remain excluded.

Send **native-coverage-summary.json** when complete. It contains each seed, the
equal five-seed ensemble, paired sample outcomes, software and historical fixed
thresholds, original/earlier-targeted/native population metrics, and the existing
malware watch groups. Previous model scores and decisions must reproduce on all
old held samples. The original study reference is included separately.

For compatibility with the existing report machinery, `prior_only` means previous
coverage **including the earlier targeted files**, and `targeted_fit_added` means
that coverage plus native files. The report includes this arm mapping explicitly.
Safe within-role group merges can change group metrics relative to historical
reports; both current arms use identical joint groups. The acquired Go versions
represent one software project, not independent software families. These are
inspected development data; this command neither selects a seed nor promotes a
model or changes deployment.
