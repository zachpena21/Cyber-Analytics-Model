# Resume a native coverage run

This companion leaves all hash-bound experiment scripts unchanged. It selects
the existing run with the most completed seed markers, breaking ties by newest
inputs. It verifies original input hashes and completed seed artifacts before
resuming, and uses the saved baseline and native cache paths rather than selecting
newer inputs. An already-complete run is left intact. Use `--resume PATH` to
select a run explicitly. No new experiment directory is created.

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_recover_reviewer_v8_native_coverage.py
set -o pipefail
./.venv/bin/python -u scripts/recover_reviewer_v8_native_coverage.py 2>&1 | tee validation-data/native-coverage-recovery.log
```

The array scorer avoids building a large Python list of feature floats and
traversing each row in Python. Features are converted to float32, then widened
to float64 for comparison with the model's double thresholds. Trees accumulate
in the original order. Every scoring call compares up to 32 evenly spaced rows
bit-for-bit against the original scorer; saved control replay, decisions and
new-model full export parity checks remain enforced. Tests compare full vectors
with the original scorer and sklearn, including float32 boundary cases.

Recovery method and code hashes are recorded in a separate timestamped JSON
inside the existing run. Completed seed fits are reused; their summaries and
held scores are reproduced as required by the original resume workflow. An
incomplete seed can still require refitting. Splits, seeds, class weights,
calibration rules and thresholds selected by those rules are unchanged.

Send `native-coverage-summary.json` after the script prints `Complete`. If the
process crashes, send the final lines of `native-coverage-recovery.log` or the
terminal error. A partial summary cannot identify the crash cause. If Linux
terminates it with `Killed`, inspect the kernel log for an out-of-memory message
before attributing the failure to memory pressure. Do not launch this runner
while another process is writing to the same run directory.
