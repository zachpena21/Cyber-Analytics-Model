# Rich v8 development feature cache

Collect extra features before the next matched, group-disjoint ablations.
This step does not fit a model, call Docker, change thresholds, or modify either
frozen v8 bundle. The inspected 618-sample acquisition becomes development data;
it cannot serve as independent validation for a model informed by these errors.

Run on the Linux VM from the repository root:

```bash
git pull --ff-only
./.venv/bin/python scripts/test_reviewer_v8_rich_features.py
./.venv/bin/python scripts/reviewer_v8_rich_feature_cache.py
```

The script finds the newest completed structural feature diagnostics matching
the structural freeze. It validates the previous development caches, reproduces
the new acquisition's frozen scores and gates, and requires the original pool
to match the structural freeze's excluded SHA set. Defaults cover the previous
12,627 samples plus the newly inspected 618, for an expected total of 13,245.
Counts come from validated manifests, rather than hard-coded acceptance counts.

Sample files are scanned under `validation-data/`. ZIPs, wheels, nested archives,
encrypted archives using the existing `infected` password convention, and raw
MZ files are read using the existing archive reader. Samples are never executed.
Only requested SHA matches are retained. Unreadable archive entries are logged;
missing any required SHA prevents a complete cache. Header parse failures remain
in the pool with explicit validity indicators and a recorded status.

The fixed 50-feature schema contains:

| Block | Count | Measurements |
|---|---:|---|
| Sections | 17 | Header validity, raw bounds and overlaps, executable/writable flags, zero raw sections, virtual/raw mismatch, section entropy statistics |
| Ordinary import identities | 24 | Fixed DLL indicators with Python and VC runtime version normalization, plus CRT API-set indicator; sourced from cached Docker imports |
| Managed PE | 9 | CLR directory/header and metadata signature indicators, metadata size ratio and CLR flags |

The bounded parser follows the [Microsoft PE layout specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
CLR and strong-name flags are header claims; this is not digital signature verification.
The import vocabulary is fixed before fitting. It reflects hypotheses developed
from the inspected errors, so subsequent results remain development evidence.

A new timestamped `validation-data/reviewer-v8-rich-feature-cache-*` directory
contains the original baseline inputs, extra features, input hashes, excluded
SHA union, archive warnings, parser status counts, and summary. Send
`rich-feature-summary.json` after a successful run. Keep the full cache on the VM.

To resume, use the output path printed by the interrupted run:

```bash
./.venv/bin/python scripts/reviewer_v8_rich_feature_cache.py \
  --resume validation-data/reviewer-v8-rich-feature-cache-TIMESTAMP
```

Resume requires identical cached inputs, feature parser, model dependencies,
and scan roots. Collector orchestration fixes may change; the previous input
record is retained and existing feature-parser hashes must still match. Restore
missing archives under the same roots before resuming. To scan other locations,
start a new run and repeat `--scan-root` for every desired root (these replace
the default). Use `--diagnostics PATH` to select a specific completed diagnostic
directory. Do not rerun a freeze or change its dependency files.

Empty ZIP member names are logged and their payloads are read by entry identity,
avoiding `ZipInfo.is_dir()`'s empty-name indexing error. Other archive failures
are recorded while complete required SHA coverage remains mandatory. Use
`--debug` to print a full traceback if the collector stops unexpectedly.

Next: compare structural-only control, each feature block individually, and all
blocks on identical group-disjoint fit/calibration/held splits. The richer features
must also inform conservative template grouping to keep near-duplicate inputs
together. Evaluate malware recovery alongside benign losses and software-group
constraints. A selected candidate will still require fresh independent samples
and runtime/export parity before deployment.
