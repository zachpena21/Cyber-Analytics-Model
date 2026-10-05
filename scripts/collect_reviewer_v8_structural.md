# Fresh collection for the frozen structural reviewer

Freeze successfully first. Keep that bundle/scripts unchanged; this collector does
not refreeze, tune or deploy. Use a new acquisition output, not previous batches.

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/collect_reviewer_v8_structural.py benign
./.venv/bin/python scripts/collect_reviewer_v8_structural.py malware --count 200
```

The benign command reuses the established PyPI wheel collector with CPython 3.13
Windows x64 builds, two minor versions where available, across its existing package
list. It checks published wheel hashes and excludes frozen development/report SHAs.
It never installs wheels. Availability/sample count is determined by PyPI at run
time. Different ABI builds are not necessarily independent software versions;
retain exact package/version/ABI provenance and do not infer broad benign coverage.
Extra ABIs/packages/versions can be explicitly supplied with `--abis`, `--packages`,
`--versions`. Empty collections stop; inspect their summaries before changing scope.

Malware uses the existing official hourly datalake export collector, avoiding the
MalwareBazaar API that timed out previously. It checks PE/member hashes, excludes
frozen and already selected SHAs, and stores selected payloads encrypted with the
password `infected`. Samples are never executed. The target is 200, not a guarantee.
The batch hour is not an independently verified first-seen date. Labels are retained
from source provenance. Defaults: 48-hour lookback, 1 GiB total download cap and
256 MiB per batch. Exact provenance/failures are recorded. Datalake access can also
fail; progress remains resumable.

If interrupted:

```bash
./.venv/bin/python scripts/collect_reviewer_v8_structural.py malware --count 200 --resume
```

The wrapper loads the **new structural bundle**, leaving the old bundle loader and
frozen validation scripts unchanged. It refuses pre-freeze or mismatched collections,
verifies selected archive hashes, and writes actual recorded acquisition timestamps
required by the structural evaluator. Do not invent dates or relabel old collections.

Outputs under `validation-data/reviewer-v8-structural-fresh-acquisition`:

- `benign/collection-summary.json`
- `malware-batches/collection-summary.json`
- `sources.json`, automatically written after malware collection completes

Upload both collection summaries for coverage review. Collection times plus SHA
disjointness alone do not establish family/version independence. Source diversity
and observed overlap must be described when interpreting the eventual evaluation.
Do not change acquisition scope based on model scores.

After successful collection, start the existing original-v7 diagnostic service on
Windows with `.\scripts\start_reviewer_diagnostic.ps1 -Version v7`, then on the VM:

```bash
./.venv/bin/python scripts/reviewer_v8_structural_validation.py evaluate \
  --sources validation-data/reviewer-v8-structural-fresh-acquisition/sources.json \
  --service-url http://192.168.1.193:8082/
```

Upload comparison-summary.json/comparison-scores.csv from the printed evaluation
directory. No thresholds or model choices may be changed while claiming the same
data are untouched validation.
