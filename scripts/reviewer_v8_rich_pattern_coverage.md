# Rich v8 pattern coverage and archive-member names

This read-only audit follows the completed blocker profile. It recovers missing
blocker filenames by matching exact payload SHA-256 inside the already cached
archives, then describes the three observed patterns in each original fit and
calibration split. It changes no labels, features, groups, thresholds or models.
It performs no training, downloads or sample execution and needs no Docker service.

Run from the VM repository root:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_rich_pattern_coverage.py
./.venv/bin/python scripts/reviewer_v8_rich_pattern_coverage.py --debug
```

The default selects the newest completed blocker profile and the `plus_imports`
variant. It creates a fresh timestamped
`validation-data/reviewer-v8-rich-pattern-coverage-*` directory. Send
`rich-pattern-coverage-summary.json` from the printed path.

To choose a profile explicitly:

```bash
./.venv/bin/python scripts/reviewer_v8_rich_pattern_coverage.py \
  --profile validation-data/reviewer-v8-rich-blocker-profile-YOUR-RUN --debug
```

`--variant` may be repeated for variants already present in the chosen profile.
The default archive scan touches only cached locations of blockers with missing
original filenames. If files moved, provide additional files/directories with
`--scan-root PATH`. Reads use the existing `pyzipper` dependency and password
`infected`, handle nested ZIPs, and log unreadable entries. Nested depth is limited
to five and individual ZIP entries to 256 MiB; PE targets are limited to 16 MiB.
No payload bytes are written to disk. Empty archive-member names stay explicitly
unresolved. Hash matches and byte sizes, not names alone, identify the samples.

## Descriptive patterns

These post-hoc, label-independent conditions are for diagnosis, not routing rules:

| Pattern | Condition |
|---|---|
| Tiny managed | Valid CLR metadata; at most 8 KiB; at most three sections; at most one cached DLL import |
| Large native with sparse imports | No valid CLR metadata; 10–20 MiB; 8–10 sections; at most one cached DLL import |
| Managed with no cached imports | Valid CLR metadata; 64–512 KiB; no cached DLL imports |

The report includes fit/calibration sample counts, both class counts, representation
split-group counts, source/software coverage, known resource-DLL paths, reviewer
score ranges, and errors at the already selected threshold. Fit scores are
training diagnostics; they do not estimate generalization. Existing cached import
values and CLR validity indicators are used without changing extraction.

For each calibration blocker representative, it also lists the three nearest
benign and malware samples from the original fit rows. Distances use the import
model inputs and the existing fit-only log/median-IQR normalization. Calibration
samples never become fit references, and held roles are excluded from analysis.

`all_required_names_recovered` distinguishes successful name recovery from a
completed coverage audit. Missing names and archive warnings remain explicit;
coverage analysis can still finish when a name could not be recovered. See
`archive-read-warnings.json` for details. Restoring cached archive locations or
supplying an additional scan root may resolve these gaps.

All dependency/cache and original audit model/manifest hashes are checked. New
`inputs.json` binds the profile, script, original inputs and scanned archive hashes.
Existing outputs remain unchanged; use a new or empty `--output` directory.

Broad pattern coverage does not establish that the precise resource DLL/build
pattern occurred in fitting. Recovered names, Windows paths and inherited labels
are available evidence, not independent authenticity verification. These results
inform a later controlled experiment; they do not approve relabeling, whitelisting,
threshold changes or promotion.
