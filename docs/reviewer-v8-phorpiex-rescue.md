# Agreement rescue experiment

This research experiment tries to recover the last disclosed Phorpiex miss
without adding false positives relative to the passing threshold-0.60 candidate.
That fallback remains unchanged. The rescue is now implemented as an optional
Docker experiment; its raw-file runtime verification passed on all 100 TA files.

## Full development-pool result and Docker verification

The uploaded full-pool reports were byte-identical and bind to the expected
cache hash. They record zero changed decisions across 13,245 files:

| Full development pool | t060 | Rescue hypothesis |
|---|---:|---:|
| Benign errors / 12,764 | 41 (0.321%) | 41 (0.321%) |
| Malware detected / 481 | 339 (70.48%) | 339 (70.48%) |
| New benign errors | — | 0 |

See [the preserved report](evidence/phorpiex-rescue-full-pool.json).
These inspected development results establish no new false positives on this
pool; they are not an independent estimate of detection accuracy. The full-pool
report did not include the TA archive. The subsequent raw-file Docker run
confirmed 50/50 malware detections and zero benign errors, zero scoring errors,
exactly one rescue, and a maximum recorded request time of 0.50 seconds. The
model hash, all feature vectors, and the rescue policy were checked against
t060; no other verdict changed. See the
[runtime summary](evidence/whitebox-v8-rescue-runtime-summary.json).

To reproduce the Docker check on Windows, update main and run from Command Prompt:

```cmd
git fetch origin
git switch main
git pull --ff-only origin main
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\start_reviewer_v8_whitebox.ps1" -AgreementRescue -Port 8085
```

Use `-Archive "C:\path\to\actual-archive.zip"` when the TA ZIP is not at the
default Downloads filename. Existing services are left running.

The new container uses the existing final v8 image, overlays only the optional
cascade code and shared rescue policy, and retains the fixed t060 model.
Startup requires the exact passing full-pool proof. The rule remains disabled
unless the rescue-specific entrypoint option is passed. Raw reviewer scores are
preserved; the diagnostic response separately records when a verdict is rescued.
The scorer independently checks the rule, fixed tree scores, public decisions,
all labels and sample hashes. Expected result: 50/50 malware, 50/50 benign and
exactly one rescue. Root filesystem and code/sample mounts are read-only; only
the report directory is writable. Samples are read in memory, not executed.

Send `whitebox-v8-rescue.json` from the printed output folder. This verifies the
candidate runtime, not a standalone packaged ZIP or a new clean build.

## Fixed hypothesis

Preserve any malware decision from t060. Change a benign decision to malware
only when all conditions hold:

- The sample is routed to the reviewer (adapter at least 0.15).
- Adapter score is at least 0.99.
- Base-model benign score is at most 0.20.
- The signature-adjusted base trigger is still 1.
- A Microsoft signature has not been verified by the existing signature policy.
- Reviewer score is at least 0.30 (and below the existing 0.60 threshold).

The adapter and base-model scores are model outputs, not calibrated confidence
guarantees. This manually specified rule was informed by a disclosed miss.
It uses no filenames, sample hashes, family labels, timestamps, or exact byte
sizes for inference. Hashes bind evaluation inputs only. The thresholds were
not swept over the development pool. No reviewer or adapter has been retrained.

## Local saved-score results

| Cohort | t060 | Rescue hypothesis |
|---|---:|---:|
| TA malware detected | 49/50 | 50/50 |
| TA benign errors | 0/50 | 0/50 |
| Earlier cohort malware detected | 75/92 | 75/92 |
| Earlier cohort benign errors | 5/526 | 5/526 |

The rescued Phorpiex starts `2a6ebbf39012`: adapter 0.995939, base benign
0.17, reviewer 0.336895. All other TA decisions are unchanged. Scores were
replayed from the verified Docker t060 report using the fixed v8 trees.

Nine historical score reports contain 6,823 observations of 4,205 unique files:
3,933 benign and 272 malware. No benign observation satisfies the upstream
agreement gate, so the rescue cannot introduce an extra positive on those
observations, even without their final reviewer scores. Duplicate SHA
observations are all screened rather than selecting a favorable observation.
These overlapping historical reports are not independent test cohorts. Only
the 618-row report contains matched fixed structural-primary scores; it is
reported separately without pooling accuracy.

The initial [preview evidence](evidence/phorpiex-rescue-preview.json) records
input hashes and exact paired changes. It predates the full-pool check; its
null pool fields are superseded by the preserved passing report above. The hypothesis has not
been tested on untouched Phorpiex variants. There is no population-level
false-positive guarantee, and t060's inherited 5/526 historical errors remain.

## Reproduce the completed full-pool check on the VM

The VM holds the full final-export feature cache. From its repository:

```bash
git fetch origin
git switch --track origin/whitebox-v8-phorpiex-rescue
./.venv/bin/python scripts/evaluate_reviewer_v8_rescue.py
```

The script automatically locates the exact cache bound to the final v8 export.
It verifies SHA-256
`a264e6da9633346eddda084814242608d513ea343bd294c64cb67b5b12f57471`,
the 66 cached fields plus six reconstructed driver-import fields, upstream
record/vector agreement, and the expected 12,764 benign / 481 malware counts.
It recomputes all 13,245 scores with the frozen trees at threshold 0.60,
then reports every rescued malware and every newly flagged benign file.
No samples or services are required, and no PE is parsed or executed.

If automatic lookup fails, pass the cache directory explicitly:

```bash
./.venv/bin/python scripts/evaluate_reviewer_v8_rescue.py \
  --cache validation-data/reviewer-v8-rich-feature-cache-20261006-050159-967490
```

Send `validation-data/phorpiex-rescue-experiment.json`. Existing output is not
overwritten; use another `--output` path for a repeat. The script exits with
`REJECTED` if there are any new benign flags. A clean full-pool result permits
the next Docker implementation experiment; it does not promote or package a model.

Optional `--ta-report <path>` replays the t060 TA report when it is available
on the VM. Optional repeated `--csv <path>` screens additional historical score
reports. No raw malware transfer is needed for this cached-vector experiment.
