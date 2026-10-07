# Five-seed ensemble calibration audit

This read-only audit explains software-calibrated thresholds in the completed
five-seed ensemble comparison. It replays all saved seeds, regenerates the saved
ensemble summary and held scores, and stops on changed or inconsistent inputs.
It trains no models and chooses no new policy.

Run from the repository root on the VM:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_seed_ensemble_calibration_audit.py
./.venv/bin/python scripts/reviewer_v8_seed_ensemble_calibration_audit.py
```

The default uses the newest completed `reviewer-v8-targeted-seed-ensemble-*`
directory. Add `--run validation-data/<ensemble-directory>` to choose explicitly.
Original caches, acquisition archives, seed study, and frozen dependencies must
remain available. Docker is unnecessary. Outputs go into a new timestamped
`reviewer-v8-seed-ensemble-calibration-audit-*` directory.

Send `seed-ensemble-calibration-audit-summary.json` from the printed directory.
For every arm and fold it reproduces the exact chosen calibration threshold,
reports the feasible same-recall range and tie-breaks, and identifies constraints
violated at the next lower calibration threshold that increases malware recall.
The corresponding benign SHA details are complete, rather than truncated.

Paired prior-only / targeted-added reports show constrained benign cohort score
ranges and individual calibration blocker score changes, feature vectors, and
available provenance. Software cohorts and representation groups are descriptive;
metadata does not verify publisher authenticity, and score changes do not establish
which added training file caused a decision.

The existing held watch-group results are copied for context. Alternative
thresholds are evaluated only on calibration samples, never on held samples.
This is an audit of inspected development data, not independent validation or
runtime promotion. Deployed v7 and frozen v8 artifacts remain unchanged.
