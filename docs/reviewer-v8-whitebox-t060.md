# v8 whitebox threshold candidate

This is the first candidate after the instructor disclosed the submission test
samples. It lowers the reviewer threshold from `0.6882517225516912` to `0.60`.
The model payload changes only `reviewer_threshold`: every tree, feature,
adapter coefficient, base-model setting, and the `0.15` route remain fixed.
The submitted v8 model and submission ZIP remain the blackbox baseline.

## Saved-score replay

| Cohort | Submitted v8 | Threshold 0.60 |
|---|---:|---:|
| TA malware detected | 47/50 (94%) | 49/50 (98%) |
| TA benign false positives | 0/50 | 0/50 |
| TA overall accuracy | 97% | 99% |
| Historical malware detected | 75/92 (81.52%) | 75/92 (81.52%) |
| Historical benign false positives | 2/526 (0.38%) | 5/526 (0.95%) |

The rescued Phorpiex SHAs begin `db0424208bbb` and `f116c0400a9c`;
both reviewer scores are approximately `0.6023738215`. The `2a6ebbf39012`
Phorpiex remains missed. New historical benign errors are from scikit-learn,
Pillow, and lxml. See the full paired changes and input hashes in
[`whitebox-candidate-comparison.json`](../defender/defender/models/boundary_reviewer_v8_whitebox_t060/whitebox-candidate-comparison.json).

The TA set informed this threshold and is now a tuning set. The historical
cohort is development evidence with zero SHA overlap with the TA set. Neither
result establishes independent generalization; the historical FPR has little
margin below 1%. The full 13,245-row development pool has not been replayed
here; other reviewers' OOF/ensemble scores must not be substituted for scores
from this fixed model. No retraining or threshold sweep was performed.

## Verify in Windows Command Prompt

From the repository folder, with Docker Desktop running and the TA ZIP in
Downloads, run:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\start_reviewer_v8_whitebox.ps1"
```

If the filename contains `(1)` or the ZIP lives elsewhere, pass its actual path:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\start_reviewer_v8_whitebox.ps1" -Archive "%USERPROFILE%\Downloads\csce704-blackbox-validation-100-samples-20261014(1).zip"
```

This launches a separate candidate on port 8084 using the already-built
`blackbox-defense:v8-final` image; no rebuild or v7 reference is needed. It
checks that the image contains the original frozen model, accepts only the
threshold-only candidate, and uses the image's tested parser and preprocessing.
Existing services on 8082/8083 are untouched. A port conflict stops the script;
use `-Port 8085` if needed.

The scorer reads password-protected ZIP entries in memory without extracting
or executing samples. It checks sample hashes, local tree-score parity,
public-vs-diagnostic decisions, and all 100 labels. The script expects 49 malware
detections and all 50 benign files correct, and stops on a different result.
The container has a read-only root filesystem, 1 CPU, and a 1 GiB memory limit.
Only its report directory is mounted writable. Parsing untrusted samples still
carries residual risk; this workflow does not execute them.

Send `validation-data/whitebox-v8-t060-<timestamp>/whitebox-v8-t060.json`.
The candidate remains running for further diagnostics; the printed `docker stop`
command stops it. This workflow does not create a new submission ZIP or measure
clean-build time, independent accuracy, or peak memory.

## Reproduce offline preparation

Requires standard-library Python only. The source frozen model hash, all TA
vectors and recorded decisions are checked before writing a fresh output folder.

```bash
python scripts/prepare_reviewer_v8_whitebox.py \
  --baseline-report validation-data/whitebox-v8-baseline.json \
  --regression-csv validation-data/reviewer-v8-structural-evaluation-20261005-215505-199557/comparison-scores.csv \
  --output validation-data/whitebox-t060-replay
python -m unittest discover -s scripts -p test_reviewer_v8_whitebox.py -v
```

Additional matched historical CSVs may be supplied with repeated
`--regression-csv` options. They must contain `structural_primary_score` and
`structural_primary_prediction` from the same frozen reviewer. Cohorts are
reported separately, with their TA overlap counts; no pooled accuracy is claimed.
