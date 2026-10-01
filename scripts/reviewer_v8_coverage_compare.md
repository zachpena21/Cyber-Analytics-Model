# Frozen v8 coverage comparison

Compare the original v7 and both frozen v8 import candidates on **all** unused
samples in the completed development coverage manifest. No training or threshold
selection occurs. The original route minima and saved thresholds determine final
predictions. Scores are also collected below the route minimum for inspection.

Start the existing original-v7 diagnostic service on Windows. This launcher
stops containers occupying port 8082 and starts an all-route diagnostic copy;
the original model artifacts are preserved.

```powershell
cd "C:\Users\zacpe\Documents\CSCE 704 Project\Cyber-Analytics-Model"
git pull --ff-only origin main
docker build -t blackbox-defense:v14-main-v7 .\defender
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_reviewer_diagnostic.ps1 -Version v7
```

After the launcher reports Ready, run from the Linux VM:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_coverage_compare.py \
  --service-url http://192.168.1.193:8082/
```

Dependencies are the existing project environment: numpy, requests, and pyzipper, plus the repository's defender dependencies. The default manifest is
`validation-data/reviewer-v8-coverage-development/coverage-manifest.json`.

The rebuilt service supplies base/adapter/signature-policy components, the exact
original-v7 feature vector, and ordinary-import libraries through the opt-in
`/diagnostics/score?include_features=1` response. The comparison uses Docker
features directly for all 66 shared features, appending the fixed six import
indicators for the v8 candidates. It does not run VM-side PE extraction.
The feature payload must match the submitted SHA and frozen v7 feature schema. Every
sample must reproduce the original v7 Docker reviewer score within 1e-9. The
service must run original-v7's threshold with route minimum 0 and adapter v2
disabled. Candidate hashes must match those frozen in the coverage manifest.
Missing required SHAs, changed candidate files, service errors, parity errors,
or changed service configuration stop the comparison without a final summary.
The manifest's exact SHA set is scored; other archive members are ignored.
Archive read warnings are logged, and required SHA coverage is enforced.
Malware is read and parsed in memory, never executed or extracted to disk.

Outputs in `validation-data/reviewer-v8-coverage-comparison/`:

- `comparison-summary.json`: overall and category error counts, frozen gates and
  thresholds, paired rescues/regressions against v7, and service parity.
- `comparison-scores.csv` and `.json`: scores and gated predictions for every SHA.
- `run-inputs.json`: manifest/model hashes and service configuration.
- `archive-read-warnings.json`: archive diagnostics.
- `partial-scores.json`: periodic checkpoints, never evidence of a complete run.

Send `comparison-summary.json` and `comparison-scores.csv` for review. Category
counts overlap. No thresholds are tuned on this pool. It is a development pool,
not an independent final evaluation, and disjointness does not establish absence
from upstream base training or malware-family independence.

The script refuses a nonempty output directory. After an earlier failed run,
use the rerun command below. Rebuild and restart Docker first to enable the new
opt-in feature diagnostic; normal classification responses stay unchanged. To rerun after correcting a
failure, preserve prior diagnostics and supply a fresh output directory:

```bash
./.venv/bin/python scripts/reviewer_v8_coverage_compare.py \
  --service-url http://192.168.1.193:8082/ \
  --output validation-data/reviewer-v8-coverage-comparison-rerun
```

Tests (synthetic models, mocked service and extractor; no malware execution):

```bash
./.venv/bin/python scripts/test_reviewer_v8_coverage_compare.py
```
