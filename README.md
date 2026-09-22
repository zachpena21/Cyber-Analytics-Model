# Black-Box Malware Defense Baseline

This branch turns the 2021 MLSEC `NeedForSpeedModel` sample into a hardened,
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
  -e DF_MODEL_THRESH=0.75 blackbox-defense
```

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
