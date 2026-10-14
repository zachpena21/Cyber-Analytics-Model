# Agreement rescue experiment

This research experiment tries to recover the last disclosed Phorpiex miss
without adding false positives relative to the passing threshold-0.60 candidate.
That fallback remains unchanged. No new inference policy has been deployed.

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

The [preview evidence](evidence/phorpiex-rescue-preview.json) records input
hashes and exact paired changes. Its full development-pool fields are null;
it is explicitly not ready for runtime testing yet. The hypothesis has not
been tested on untouched Phorpiex variants. There is no population-level
false-positive guarantee, and t060's inherited 5/526 historical errors remain.

## Required next check on the VM

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
