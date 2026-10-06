# Targeted benign Docker feature collection

This step collects features for the filtered installed-Windows development samples.
It fits no models and changes no thresholds, routes, prior caches, or frozen bundles.
Keep the original rich cache for a matched coverage experiment later.

Start the original v7 all-route diagnostic service on Windows if it is not running:

```powershell
./scripts/start_reviewer_diagnostic.ps1 -Version v7 -Image blackbox-defense:v7-reference
```

On the VM, pull and run the focused integrity/resume tests:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_targeted_feature_cache.py
```

Use the completed inventory directory and original rich cache. Replace
`WINDOWS-HOST` with the Windows host address reachable from the VM:

```bash
./.venv/bin/python scripts/reviewer_v8_targeted_feature_cache.py \
  --inventory validation-data/reviewer-v8-targeted-benign-inventory-20261006-200517 \
  --prior-cache validation-data/reviewer-v8-rich-feature-cache-20261006-050159-967490 \
  --service-url http://WINDOWS-HOST:8082/
```

The default output is a new timestamped `validation-data/reviewer-v8-targeted-feature-cache-*`
directory. Each completed sample is checkpointed. If interrupted, repeat the same
command with `--resume` set to that printed output directory. Resume validates all
saved diagnostic payloads and regenerates their features and frozen decisions;
it does not rescore completed samples. Inputs, parser, scripts, and service model
configuration must match. An HTTP timeout may require increasing `--api-timeout`.

The collector verifies inventory lineage against the original excluded SHA list,
archive hashes, sample SHA/size/labels, schema, upstream components, original v7
service score parity, and offline frozen score/gate replay. The original rich cache
is also validated before collection. Source hashes and service configuration are
checked again before completed outputs are written.

Docker ordinary-import libraries supply all model import features. The Windows
static parser's imports are compared descriptively; differences are reported rather
than silently replacing Docker features. Windows source metadata remains acquisition
evidence and does not verify publishers or benign labels independently.

Outputs:

- `targeted-feature-summary.json`: counts, parser status, parity and import differences;
  send this summary before the matched development experiment.
- `targeted-development-input-cache.json`: baseline Docker vectors, libraries,
  frozen comparison records and per-sample acquisition provenance.
- `targeted-rich-feature-cache.json`: section/import/CLR features using Docker imports.
- `excluded-sha256.json`: conservative union of prior and new development samples.
- `targeted-collection-inputs.json` and `partial-targeted-feature-cache.json`: provenance,
  hash bindings and resumable diagnostic payloads.

These are separate additive caches, not direct inputs to the old rich-ablation CLI.
The next experiment needs an explicit matched comparison with and without the new
coverage, preserving held groups and calibration separation. This batch is development
data and cannot provide untouched validation of a model trained with it.
