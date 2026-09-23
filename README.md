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

The legacy forest can be augmented with a small linear detector trained on a
recent, local collection. The trainer deduplicates by SHA-256, reads encrypted
malware ZIPs only in memory, and makes deterministic 60/20/20
train/calibration/holdout splits. Model and adapter hyperparameters are chosen
without consulting the holdout split. The existing forest remains active, so
the adapter can add detections but cannot suppress a legacy detection.

On Windows, collect a new benign development corpus containing only files with
a valid Authenticode or catalog signature:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_benign.ps1
```

The collector also creates `validation-data/benign-modern.zip`. Copy only that
benign archive into the disposable VM; do not move malware out of the VM. From
the repository root in the VM, train with one command:

```bash
./scripts/train_modern_adapter.sh \
  validation-data/malwarebazaar-final-20260922 \
  validation-data/benign-modern.zip
```

The command writes the deployment files and an audit report to
`defender/defender/models/modern_adapter/`. Review `metadata.json`; if its
untouched `holdout_test.fpr` is above 1%, do not deploy the adapter. A Docker
build automatically includes the adapter when that directory is present.

The 99 recent MalwareBazaar files used here become development data after this
step. They must not be reported as final external-test performance. Download a
separate later batch, keep it untouched, and use it only after the image and
thresholds are frozen.
