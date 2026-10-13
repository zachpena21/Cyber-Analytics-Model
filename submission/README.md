# Final v8 container preparation

The uploaded Windows preflight passed on October 13: clean build 67.79 seconds,
restricted startup 3.47 seconds, and exact raw-PE parity for all 16 System32
smoke samples (maximum error zero). After restoring the legacy 300-byte named
export limit, the uploaded bounded check passed on all 64 benign and 64 malware
samples with no changed features or decisions (maximum score error 2.22e-16).
Sanitized evidence is in `runtime-validation.json`. These checks verify the
supplied cohorts only; final package and base-image review remain pending.

The final reviewer weights are tracked at
`defender/defender/models/boundary_reviewer_v8_final/`. All previous candidates
remain in the repository. Its exported scores/decisions reproduced all 13,245
cached vectors exactly. This directory contains a **Python-3.11 build template**,
not a complete build context: prepare inference arrays from the existing image.

On Windows PowerShell, from the repository root:

```powershell
git pull --ff-only origin main
.\scripts\start_reviewer_diagnostic.ps1 -Version v7 -Image blackbox-defense:v7-reference
.\scripts\build_reviewer_v8_submission.ps1
```

The workflow copies the existing compact forest and adapter, exports only the
old preprocessing parameters inside the original image, and verifies their sparse
vectors on synthetic rows including unknown categories. No model is refitted.
The new runtime reads JSON/scaling parameters and unchanged mmap tree arrays;
it never loads the cross-version sklearn pipeline pickle. It uses pinned binary
dependencies supporting Python 3.11, including LIEF 0.13.2. Original runtime and
hash-bound experiment modules remain unchanged.

It stages a new `validation-data/submission-v8-*/context/` containing exactly one
Dockerfile and inference inputs only. A clean build must take at most 300 seconds.
The restricted container must start on port 8080 within 25 seconds with no network,
read-only filesystem, a non-root user, one CPU and 1 GiB RAM. Diagnostics are
disabled in the final entrypoint; only the separate diagnostic instance enables
them for score comparisons.

The initial raw-PE check uses existing Windows System32 files, comparing upstream
probabilities, signature decisions, complete reviewer vectors and final cascade
decisions against the original-v7 diagnostic reference. Failures stop the script
and report changed fields. No samples are executed or packaged. The diagnostic
container stays available on host port 8083 (use `-DiagnosticPort` if occupied).

Send `submission-preflight-summary.json` and `runtime-parity-summary.json` from
the printed directory. These smoke tests do not establish broad malware parity,
accuracy, latency or peak memory on large files. Further benign/malware checks
are required before making the final submission ZIP. The exact platform-approved
Python image pin is not present in the supplied screenshot; the template uses
`python:3.11-slim`, and this must be confirmed against the current course rules.
The Canvas update accepts the same defense content via a hosted ZIP, grader-accessible
repository, or Docker Hub; no external submission has been made by this workflow.
Do not submit the whole research repository as a ZIP/build context: it contains
multiple historical/template Dockerfiles and does not track the large base
forest arrays. Submit only the completed generated context after qualification.

Dependency compatibility was checked against the published release files:
[LIEF 0.13.2](https://pypi.org/project/lief/0.13.2/) and
[scikit-learn 1.2.2](https://pypi.org/project/scikit-learn/1.2.2/).

For additional raw files from the VM, the stdlib checker can use the Windows host
address for both services and local benign/malware files via `--files`:

```bash
./.venv/bin/python scripts/check_reviewer_v8_runtime_parity.py \
  --reference http://WINDOWS_HOST:8082 --candidate http://WINDOWS_HOST:8083 \
  --model defender/defender/models/boundary_reviewer_v8_final/model.json \
  --files /path/to/benign.exe /path/to/malware.exe \
  --output validation-data/v8-runtime-parity-additional.json
```
# Parser compatibility

The submission-only extractor restores two LIEF 0.11.5 text conventions on
the pinned LIEF 0.13.2 parser: delay imports are excluded from imported-library
and function text, named forwarded exports use the export-name table, and
named exports exceeding the old 300-byte limit are excluded by ordinal.
This follows the upstream `src/PE/Binary.cpp` and `src/PE/Parser.cpp` at those
release tags. The frozen reference extractor and all model weights remain
unchanged. Raw-PE parity still must pass; this compatibility layer does not
establish equivalence on every malformed PE.

## Bounded VM archive regression

Keep both diagnostic services running on the Windows host. From the VM repo root:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/check_reviewer_v8_batch_runtime.py \
  --reference http://WINDOWS_HOST:8082 --candidate http://WINDOWS_HOST:8083
```

Replace `WINDOWS_HOST` with the reachable host address. Defaults select 64 unique
eligible PEs from `validation-data/benign-final-6.zip` and across sorted existing
`validation-data/malwarebazaar*-final-*` batches; override `--benign` or pass one
or more paths with `--malware` if needed. SHAs are deduplicated across batches.
Existing pyzipper handles the encrypted archives. Members stay in
memory and are never executed or extracted. Each scored sample is checkpointed
to `validation-data/v8-batch-runtime-parity-summary.json`; archive warnings and
insufficient eligible coverage are reported rather than counted as a pass.
This is runtime regression evidence on reused data, not a new accuracy estimate.
The HTTP timings include network and diagnostic overhead.

## Create the submission ZIP

From the Windows repository directory, this command works in Command Prompt
or PowerShell:

```text
git pull --ff-only origin main
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\package_reviewer_v8_submission.ps1"
```

Keep the tested v8 diagnostic instance on port 8083 running. The command uses
the latest completed preflight directory, verifies its image identity and all
context hashes, rejects stale inference code, records process/cgroup peak memory,
and creates `reviewer-v8-submission.zip` with one root Dockerfile. Use `-Work`
with a specific preflight directory if needed. It includes inference assets
only and preserves earlier candidates, contexts and reports. It neither refits
nor uploads anything. Send `submission-package-summary.json` for final review.
The summary still marks base-image course verification pending; if an exact
approved pin is required, update it and repeat the preflight before submission.

