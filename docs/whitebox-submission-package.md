# Whitebox submission ZIP

`reviewer-v8-whitebox-submission.zip` is a standalone Docker build context for
the frozen threshold-0.60 reviewer plus agreement rescue. It has one root
Dockerfile and bundles inference code, preprocessing, compact forest arrays,
adapter coefficients and the selected reviewer. It contains no malware samples,
training caches, old reviewer or legacy pickle. No repository or mounted model
files are needed for inference. Diagnostics are disabled by default.

The original blackbox ZIP and checkpoint remain unchanged. Source forest,
adapter, preprocessing and dependency bytes are retained from that verified
package. Only the whitebox cascade, reviewer, entrypoint and instructions differ.
The whitebox entrypoint verifies the selected model and rescue policy at startup.
The original blackbox entrypoint has been removed from this ZIP.

The [package identity](../submission/whitebox-package.json) records the exact
ZIP SHA-256 and validation results. Creation checks verified ZIP integrity,
all 30 manifest file hashes, one root Dockerfile, and Python compilation.
The actual overlay runtime previously achieved 50/50 malware detections and
zero benign errors. That is tuning-set evidence; a standalone qualification
report for this exact ZIP has now passed. See the
[recorded qualification](../submission/whitebox-qualification.json):

| Check | Measured result |
|---|---:|
| Clean build | 32.55 seconds |
| Restricted startup | 1.79 seconds |
| TA malware / benign correct | 50/50 and 50/50 |
| Scoring errors | 0 |
| Maximum public request | 0.42 seconds |
| Process peak memory | 494 MiB |
| Cgroup-reported peak | 369 MiB |

Both reported memory measures are below the 1 GiB cap; process and cgroup
accounting are different measures. Runtime used one CPU, no network, read-only
root filesystem and disabled diagnostics. No OOM was reported. The qualified
ZIP hash is `c493bf7dbf934f3fd81d1013e60606a6da7372adf2bc4f544cf3ac9023eea05d`.
The archive was not modified after this test. Its internal manifest records
the build-context preparation state; this separate report records subsequent
runtime qualification. Exact course base-pin confirmation remains unrecorded.

## Reproduce qualification on Windows

Save the whitebox ZIP and the TA archive in Downloads, start Docker Desktop,
then run from the repository in Command Prompt:

```cmd
git switch main
git pull --ff-only origin main
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\qualify_reviewer_v8_whitebox.ps1"
```

Pass `-Zip "C:\path\reviewer-v8-whitebox-submission.zip"` or
`-Archive "C:\path\actual-ta-archive.zip"` when filenames or locations differ.
The default TA filename is `csce704-blackbox-validation-100-samples-20261014.zip`;
if yours includes `(1)`, pass that actual path.

The script verifies the ZIP hash, extracts only the submission build context,
and performs a clean build using `--pull --no-cache`. It uses a new image tag,
`blackbox-defense:v8-whitebox-rescue`. Existing diagnostic containers are not
stopped. The qualification container has a read-only root filesystem, no network,
one CPU and a 1 GiB memory limit. Its only test mounts are the checker scripts
and TA archive, both read-only; all inference code/models come from the image.
The checker reads sample bytes in memory without extracting or executing PEs.

Required checks are clean build at most 300 seconds, startup at most 25 seconds,
all 100 public classifications correct, no scoring errors, requests at most
5 seconds, disabled diagnostics, non-root inference, no OOM, and measured memory
below the 1 GiB cap. Measurements include the in-container checker as well as
the service. The candidate uses the same `python:3.11-slim` family as the
verified blackbox ZIP; exact course base-pin confirmation remains unrecorded.

Send `whitebox-submission-qualification.json` from the printed
`validation-data/whitebox-submission-<timestamp>/` folder. Failure logs and the
public per-sample report are retained there. The checker container is stopped
afterward. No external submission is performed by this workflow.

## Reproduce package creation

With the verified original blackbox ZIP available:

```bash
python scripts/package_reviewer_v8_whitebox.py \
  --source submission/reviewer-v8-submission.zip \
  --output validation-data/new-whitebox-package/reviewer-v8-whitebox-submission.zip
```

Source ZIP hash verification rejects Git LFS pointers and modified archives.
Existing output ZIPs are never overwritten. The generated companion summary
records preparation checks; clean-build/runtime qualification remains separate.
