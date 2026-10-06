# Prespecified training-seed stability study

Run offline on the VM after the completed targeted coverage experiment:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_targeted_seed_stability.py
./.venv/bin/python scripts/reviewer_v8_targeted_seed_stability.py
```

Send `targeted-seed-stability-summary.json` from the printed
`validation-data/reviewer-v8-targeted-seed-stability-*` output directory.
Docker is not required. The completed original experiment, caches, inventory and
source archives must remain available for integrity checks. Override the automatic
choice of the newest completed original experiment with `--run PATH` if needed.

## Fixed design

The training seed list is **8704, 8705, 8706, 8707, 8708**. The list is fixed in code;
there is no seed option, split search, winner selection, or ensemble construction.
This study was designed after inspecting development errors, so it supplies
post-hoc stability evidence rather than independent validation.

The script replays and reuses original seed-8704 results. The other four seeds
require **80 fits**: two feature variants, two coverage arms, and five held folds
per seed. Expect a longer run than the initial 20-fit experiment.

All seeds reuse the original joint template groups and literal fit/calibration/held
SHA assignments. Both coverage arms share the same original calibration and held
samples. New benign files enter only their assigned fit roles in the expanded arm.
Only the fit random seed changes in memory; it is restored afterward, including on
failure. Model configuration, routing and calibration constraints remain fixed.
Existing source files, deployed models and frozen bundles are never changed.

Every newly fitted seed is exported and replayed against saved calibration and held
scores/decisions before it is marked complete. The summary retains all seeds'
primary software-calibrated and fixed diagnostic results, paired coverage/import
changes, thresholds, export parity and targeted false-positive SHAs. Primary
aggregate statistics describe the mean, median, range and population standard
deviation across seeds; they are not confidence intervals from independent data.

The ten largest malware representation groups are monitored by membership count,
without selecting groups by their errors. Each seed reports their detected counts,
score ranges, saved thresholds and score margins for every variant/arm. This includes
the previously observed large group when it is among those ten. The links are not
verified malware families.

## Resume

A completion marker is saved after each seed. If interrupted, rerun with:

```bash
./.venv/bin/python scripts/reviewer_v8_targeted_seed_stability.py \
  --resume validation-data/REPLACE-WITH-PRINTED-STABILITY-DIRECTORY
```

Completed seeds are hash-checked and replayed, then skipped. An unfinished seed
restarts its 20 fits. Resume requires the same source experiment, scripts, caches,
model settings, dependency versions and saved split/exclusion copies. Specify the
same `--run` if automatic source selection has changed.

The top-level summary is `complete: false` until all five seeds finish. Assess the
full paired distribution, including adverse effects, before deciding on further
model work. No model is promoted or selected by this script.
