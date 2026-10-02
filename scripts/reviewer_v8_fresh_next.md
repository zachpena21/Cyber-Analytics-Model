# Frozen v8 error audit and additional Git validation

Keep the 72-feature candidate and both thresholds unchanged. No command here trains, recalibrates, changes routing, or deploys a model. The original-v7 all-route Docker diagnostic service must remain running.

## Audit the first fresh evaluation

On the VM:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_fresh_error_audit.py \
  --service-url http://192.168.1.193:8082/
```

Defaults use the completed `reviewer-v8-fresh-evaluation`, its `batch-sources.json`, frozen bundle, Docker training cache and preserved training split. The script:

- Rechecks all 662 fresh samples with exact Docker vectors and all three frozen policies, requiring reproduction of completed evaluation scores/decisions and unchanged service configuration.
- Saves exact vectors for all samples, with checkpoints and `--resume` support. Input hashes, cache SHA/label/source and model scores are checked on resume.
- Examines errors under expanded v8 at 0.639722991937624 (expected 18 benign + 28 malware on this batch).
- Records original wheel member paths and available batch provenance, selected structural features, ordinary imports, and strongest positive/negative tree paths.
- Finds nearby correctly classified fitting samples from the frozen expanded model's original+new training split. Calibration samples are excluded. Correct fresh-evaluation neighbors are separately labeled descriptive references.
- Groups repeated build/import templates. These are structural similarities, not malware-family assignments or causal explanations.

Outputs: `validation-data/reviewer-v8-fresh-error-audit/audit-summary.json` and `error-audit.json`. Send both. If interrupted, repeat the command with `--resume`. Controls include `--bundle`, `--comparison`, `--sources`, `--training-cache`, `--training-split`, `--api-timeout`, and `--output`.

## Collect fresh Git/GNU validation examples

Git's official Windows download page links its portable distribution:
https://git-scm.com/install/windows
Publisher release metadata: https://api.github.com/repos/git-for-windows/git/releases

On the Linux VM install the trusted archive reader, then collect:

```bash
sudo apt-get update
sudo apt-get install -y p7zip-full
./.venv/bin/python scripts/collect_reviewer_v8_git.py
```

The collector chooses up to two distinct stable minor release lines of x64 PortableGit from the official Git for Windows repository. It requires and verifies the publisher asset SHA-256 digest. It uses the system `7z`/`7zz` to list/read members, never executes the downloaded portable EXE or its members, never installs Git from it, and writes only valid PE members of at most 16 MiB into selected ZIPs. It excludes all development SHAs plus all SHAs in the first fresh evaluation. It records release, asset and original member provenance. Identical GNU utilities shared between release lines are deduplicated.

A missing publisher digest stops collection; it does not silently accept unverified downloads. Old installations/release lines can still be related despite SHA disjointness. Available release assets and their overlap determine the actual sample count. Outputs are under `validation-data/reviewer-v8-fresh-git`; send `collection-summary.json` to inspect coverage. Existing nonempty output is refused; use a fresh `--output` after a failure. Options: `--bundle`, `--previous`, `--output`, `--releases`.

## Evaluate the new benign cohort

```bash
./.venv/bin/python scripts/reviewer_v8_fresh_validation.py evaluate \
  --benign-only \
  --sources validation-data/reviewer-v8-fresh-git/sources.json \
  --service-url http://192.168.1.193:8082/ \
  --output validation-data/reviewer-v8-fresh-git-evaluation
```

This new explicit mode requires a nonempty benign-only source pool. It reports false-positive results; malware count is zero and detection rate is unavailable. It does not re-use the earlier 134 malware examples to claim another independent malware evaluation. Ordinary two-class evaluation remains the default. Send `comparison-summary.json` and `comparison-scores.csv` from the Git evaluation directory.

This extends validation to Git/GNU. Fresh Cura/KiCad and other trusted Windows application/driver sources remain additional coverage to acquire separately; collecting the same installed versions again does not establish independence. If error findings are later used for fitting/tuning, mark the first fresh batch as development and obtain new independent evaluation data.
