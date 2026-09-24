# Black-Box Malware Defense Baseline

This repository turns the 2021 MLSEC `NeedForSpeedModel` sample into a hardened,
reproducible starting point for the course's first milestone. The original
sklearn forest requires about 2.0 GiB resident memory when loaded, so the build
converts it into memory-mapped inference arrays that preserve its predictions.

## Acceptance targets

| Requirement | Course target | Baseline control |
|---|---:|---|
| False-positive rate | <= 1% | Threshold must be selected on a held-out benign set |
| True-positive rate | >= 95% | Reported with the same frozen threshold |
| Memory | <= 1 GB RAM | Slim single-process image; benchmark with a 1 GB Docker limit |
| Response time | <= 5 seconds/sample | Model loads once; synchronous in-memory inference |
| Interface | HTTP | `POST /`, octet-stream body, JSON integer result |

The inherited `0.75` threshold is only a starting point. It is not evidence
that this model meets the course targets on the hidden evaluation distribution.

## Repository layout

- `defender/`: Docker build context and HTTP service
- `defender/defender/models/`: feature extractor and model class; staged weights are ignored by Git
- `defender/test/`: original evaluator plus API contract tests
- `defender/convert_model.py`: converts the forest during the Docker build
- `scripts/stage_model.py`: verifies and extracts the supplied model archive
- `scripts/select_threshold.py`: selects the best threshold subject to an FPR ceiling

## 1. Stage the supplied model

From the repository root:

```bash
python scripts/stage_model.py /path/to/NFS_21_ALL_hash_50000_WITH_MLSEC20.zip
```

The script verifies both the outer ZIP and inner gzip-pickle SHA-256 hashes
before placing the model in the Docker context. Never load an untrusted pickle.
The multi-stage Docker build converts the verified pickle and excludes the
oversized sklearn forest from the final image.

## 2. Build and run

```bash
docker build -t blackbox-defense ./defender
docker run --rm -p 8080:8080 --memory=1g --cpus=1 blackbox-defense
```

Override the threshold without rebuilding:

```bash
docker run --rm -p 8080:8080 --memory=1g --cpus=1 \
  -e DF_MODEL_THRESH=0.510001 blackbox-defense
```

The measured validation set has a collision at benign probability `0.51`: one
malware sample and three valid Microsoft-signed Windows files share that score.
The service therefore verifies Authenticode only at that exact score and treats
the file as benign only when its embedded signature chains to a trusted root and
the leaf publisher organization is exactly `Microsoft Corporation`. Verification
failures remain malicious. Set `DF_MICROSOFT_OVERRIDE=0` to disable this policy.

## 3. Verify the API

```bash
curl -sS -X POST --data-binary @sample.exe \
  -H 'Content-Type: application/octet-stream' \
  http://127.0.0.1:8080/
```

Expected response:

```json
{"result":1}
```

Run the provided efficacy evaluator against separate malicious and benign
collections without extracting malware archives:

```bash
cd defender
python -m test -m /path/to/malware.zip -b /path/to/benign/files
```

## 4. Calibrate, then freeze, the threshold

`NeedForSpeedModel.predict_threshold` predicts malware when the model's benign
class probability is below `DF_MODEL_THRESH`. Increasing the threshold raises
both TPR and generally FPR.

Export a validation CSV with columns `label,benign_probability`, then run:

```bash
python scripts/select_threshold.py validation_scores.csv --max-fpr 0.01
```

Use a validation set that is disjoint from training and from the final test.
Freeze the selected threshold before reporting FPR/TPR. Because 1% is a tight
constraint, use enough benign samples to make the estimate meaningful; 100
benign samples allow only one false positive and provide a very noisy estimate.

## MalwareBazaar validation workflow

MalwareBazaar contains live malware. Obtain instructor/institutional approval
and use a disposable VM with shared folders and clipboard disabled. Never run
this workflow on a normal workstation, execute a sample, extract samples to a
shared location, or commit validation data to Git. The project ignores the
entire `validation-data/` directory.

1. Obtain a free Auth-Key from <https://auth.abuse.ch/> and review the
   [MalwareBazaar API and fair-use terms](https://bazaar.abuse.ch/api/).
2. In the isolated VM, install the updated evaluator dependencies:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r .\defender\requirements.txt
   ```

3. Put the key only in the current process environment without writing it into
   source code or PowerShell history:

   ```powershell
   $secureKey = Read-Host "MalwareBazaar Auth-Key" -AsSecureString
   $env:MALWAREBAZAAR_AUTH_KEY = [Net.NetworkCredential]::new('', $secureKey).Password
   ```

4. Start with 100 encrypted PE archives:

   ```powershell
   .\.venv\Scripts\python.exe .\scripts\download_malwarebazaar.py --count 100 --acknowledge-live-malware
   ```

   The downloader requests `file_type=exe`, records collection metadata and
   hashes in `manifest.json`, and never extracts a sample. Downloads remain in
   their AES-encrypted ZIPs. MalwareBazaar uses the password `infected`.

5. With the defense container running, evaluate the encrypted archive directory
   directly in memory:

   ```powershell
   cd defender
   ..\.venv\Scripts\python.exe -m test -m ..\validation-data\malwarebazaar -b C:\Windows\System32 --max 16777216 --stopafter 5000
   ```

6. Remove the Auth-Key from the process when finished:

   ```powershell
   Remove-Item Env:MALWAREBAZAAR_AUTH_KEY
   ```

Use the first collection only for pipeline testing and provisional threshold
selection. Collect a separate later set for final reporting so that threshold
selection and evaluation do not reuse the same malware samples. MalwareBazaar
is an external stress test and may not match the hidden course distribution.

## MalShare fallback workflow

If MalwareBazaar is unavailable, MalShare can provide a provisional pipeline
test. MalShare states that not every hosted file is necessarily malicious, so
do not treat this collection as the final ground-truth TPR set. Keep the same
disposable-VM isolation used above.

The downloader validates the returned hash and PE signature in memory, then
writes the sample directly into an AES-256 encrypted ZIP. It never writes a
plaintext executable.

```bash
cd "$HOME/Cyber-Analytics-Model"
source .venv/bin/activate
read -rsp "MalShare API key: " MALSHARE_API_KEY
echo
export MALSHARE_API_KEY
python scripts/download_malshare.py --count 25 --acknowledge-live-malware
unset MALSHARE_API_KEY
```

Encrypted archives and their manifest are saved under
`validation-data/malshare/`. Evaluate that directory with the same in-memory
archive reader used for MalwareBazaar, but label the resulting recall as
provisional MalShare validation rather than final test performance.

## Hardening already applied

- Pins the legacy dependency versions needed to deserialize the provided model.
- Replaces the ~2.0 GiB in-memory sklearn forest with 325 MiB of memory-mapped
  arrays; measured idle RSS was ~105 MiB and RSS after inference was ~317 MiB.
- Preserves reference probabilities in a five-row equivalence smoke test
  (maximum observed absolute difference: 0.0).
- Loads the model once at process startup.
- Rejects wrong content types and empty bodies.
- Fails closed on malformed PE/parser failures, preventing parser-crash bypasses.
- Enforces a configurable 16 MiB request ceiling to bound memory use.
- Runs as an unprivileged container user and includes a health endpoint.
- Omits the large model pickle from Git history.

## Next measurement gate

Before changing the classifier, collect three baselines under the exact Docker
limits: held-out FPR/TPR, p95/max latency, and peak container memory. If FPR is
above 1% at the threshold required for 95% TPR, threshold tuning alone cannot
meet both constraints; the next iteration should add robust PE features or a
second-stage detector rather than merely moving the cutoff.

Local smoke measurements on a 108 KB benign PE were 46-62 ms per inference.
These timings are implementation checks, not efficacy evidence. A small set of
modern Python/Node Windows launcher executables also produced many false
positives at `0.75`, reinforcing that the threshold must be calibrated on a
representative held-out corpus before submission.

Upstream reference:
[2021 Machine Learning Security Evasion Competition](https://github.com/fabriciojoc/2021-Machine-Learning-Security-Evasion-Competition)

## Modern-sample adapter

The compact legacy forest is augmented with a small linear detector trained on
recent samples. The adapter uses the existing 250,041 PE features plus the
legacy model's binary verdict as feature 250,042. The adapter is the final
decision layer, so it can both recover modern-malware false negatives and
correct legacy false positives.

At startup, `defender/defender/__main__.py` loads the adapter whenever
`defender/defender/models/modern_adapter/metadata.json` is present. The
service verifies that `DF_MODEL_THRESH` matches the base threshold recorded
during training. The current deployment uses:

- base benign threshold: `0.510001`
- adapter threshold: `0.70`
- decision policy: `adapter_with_signature_adjusted_legacy_verdict_feature`

### Development-data collection

On Windows, collect validly signed benign PE files:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_benign.ps1
```

For later disjoint collections, use `collect_benign_final.ps1` with an
exclusion directory containing all previously used benign files. The collector
deduplicates by SHA-256 and writes a ZIP under `validation-data/`, which is
ignored by Git.

MalwareBazaar samples must remain inside an approved disposable VM. The
downloader stores each sample as an encrypted archive and supports repeated
`--exclude-manifest` arguments so development and final-test malware remain
disjoint. The trainer and evaluator read archive members directly into memory;
they do not extract live malware to disk.

### Source-aware training

Run training from the repository root in the VM:

```bash
bash scripts/train_modern_adapter.sh \
  validation-data/malwarebazaar-final-20260922 \
  validation-data/benign-retrain \
  http://BASELINE_HOST:8081/ \
  validation-data/benign-validation.zip
```

The third argument must point to the frozen legacy service calibrated at
`0.510001`, not to an already adapted service.

When an explicit validation-benign corpus is supplied, the trainer uses a
source-aware split:

- 80% of development malware for adapter fitting
- 20% of development malware for calibration
- all older benign development samples for fitting
- half of the newer benign corpus for calibration
- half of the newer benign corpus for an untouched within-run benign check

The adapter's regularization and threshold are chosen on the calibration split
subject to a maximum 1% calibration FPR. The trainer records model parameters,
sample counts, split strategy, metrics, and SHA-256 split assignments under
`defender/defender/models/modern_adapter/`.

The newest corpus becomes development data after it influences model or
threshold selection. A later disjoint collection is still required for honest
external evaluation.

### Current measured status

The v3 adapter was trained from 99 development malware samples and 2,831
signed benign samples. Its source-aware development measurements were:

- calibration: 100% TPR on 20 malware and 0.4% FPR on 500 benign files
- within-run benign check: 0.2% FPR on 500 benign files

The initial external service run detected 36/36 malware but flagged 34/1,000
fresh signed benign files. A continuous-score audit of the same samples
reproduced only 9/1,000 adapter false positives at the deployed threshold. This
difference exposed training/serving skew in feature 250,042: training and
offline scoring used the signature-adjusted legacy verdict, while production
used the raw forest verdict.

The v4 inference path now applies the Microsoft signature policy to the legacy
verdict feature before adapter scoring. The adapter remains the final decision,
and a signature cannot directly override an adapter malware verdict. The
threshold was raised to `0.70`. The rebuilt production service measured:

- 36/36 malware detected: 100% observed TPR
- 10/1,000 benign files flagged: 1.0% observed FPR
- zero errors
- 76 ms average response time and 538 ms maximum response time

The VM-side feature pipeline predicted five false positives at this threshold,
while the production container produced ten with only four hashes in common.
Threshold and cascade development must therefore use scores emitted by the
production runtime rather than scores reconstructed under the VM's newer
sklearn compatibility layer.

Because the audit batch selected this threshold, it is now development data.
These figures are not final unbiased performance. Rebuild the service and
verify the implementation on this batch, then collect new disjoint benign and
malware samples for the final report.

### Capture exact production scores

The service has a diagnostic endpoint that is disabled by default. Enable it
only in the isolated development environment; never expose it in the final
submission:

```powershell
docker run --rm --name blackbox-defense-score-audit `
  -p 8080:8080 `
  --memory=1g `
  --cpus=1 `
  -e DF_MODEL_THRESH=0.510001 `
  -e DF_ENABLE_SCORE_ENDPOINT=1 `
  blackbox-defense:v4
```

Then capture exact Docker probabilities from the repository root in the VM:

```bash
git pull origin main
./.venv/bin/python scripts/analyze_adapter_scores.py \
  --malicious validation-data/malwarebazaar-unseen-v1 \
  --benign validation-data/benign-final-3.zip \
  --service-url http://192.168.1.193:8080/ \
  --output-prefix validation-data/adapter-score-production-v4
```

If the actual malware directory has a different name, substitute that path.
The command reads encrypted malware archives in memory and does not extract
them. It creates:

- `adapter-score-production-v4.csv`: SHA-256, label, exact legacy and adapter
  probabilities, raw and adjusted base verdicts, signature status, and verdict
- `adapter-score-production-v4.json`: current rates, boundary density, class
  score quantiles, service metadata, and diagnostic threshold choices

The first diagnostic maximizes TPR while keeping observed FPR at or below 1%.
The second finds the strictest cutoff that still keeps observed TPR at or above
95%. If no cutoff meets both constraints, threshold tuning alone is
insufficient and the adapter needs a feature or classifier change. Boundary
density must be calculated from this production report before selecting the
routing band for a second-stage reviewer.

These diagnostic thresholds are selected using the audit batch. The v4
adjustment therefore makes this batch development data. Do not report its
resulting rates as final unbiased performance. Collect new, disjoint benign
and malware samples and freeze the model before the final test.
