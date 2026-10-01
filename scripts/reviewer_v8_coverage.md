# Collect unused reviewer category coverage

The next step is an inventory, not retraining. We need additional independently
sourced benign driver/build examples and correctly labeled malware with kernel
imports. Already recorded SHA pools are excluded. Current candidates remain frozen.

## Windows benign collection

From PowerShell in the Windows repository:

```powershell
cd "C:\Users\zacpe\Documents\CSCE 704 Project\Cyber-Analytics-Model"
git pull --ff-only origin main
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_reviewer_v8_benign.ps1
```

The collector reads Windows driver folders and installed Program Files roots,
checks MZ headers, deduplicates exact bytes, and writes
`validation-data\benign-v8-coverage.zip`. It runs no collected binary and changes
no source file. The archive includes original paths, hashes, source ID and role.
Labels come from user-selected trusted installed-software roots, not signatures.
Only include software you know is legitimate. Collection limits default to 5,000
files, 16 MiB per file and 1 GiB total uncompressed bytes. The file order is
shuffled with seed 704. Access/read failures are logged; limits mean this is a
sample of those roots, not an exhaustive Windows inventory.

Existing output is never overwritten. To collect from specific known benign
software, pass `-Roots` and a new output/source ID directly from PowerShell:

```powershell
.\scripts\collect_reviewer_v8_benign.ps1 `
  -Roots "C:\Program Files\Git", "C:\Windows\System32\drivers" `
  -SourceId "windows-extra-dev" `
  -Output "validation-data\benign-v8-extra.zip"
```

Use the same source ID and role when auditing that ZIP. A source ID records the
actual acquisition source; changing its text does not create independence.

## VM category inventory

Copy `benign-v8-coverage.zip` from Windows into the VM repository's
`validation-data/` folder. Then run:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/reviewer_v8_coverage.py \
  --benign validation-data/benign-v8-coverage.zip \
  --malicious validation-data/malwarebazaar-* \
  --source-id zach-windows-coverage-dev
```

The malicious inputs are existing MalwareBazaar folders: this scans for unused
samples rather than downloading malware. You can instead name one or more new,
correctly labeled malware roots or ZIPs after `--malicious`. A kernel import or a
known vulnerable driver alone does not establish that a file is malware.
If no new malicious kernel-import examples appear, further independent collection
is needed before claims about that category are justified.

The VM audit reads nested/encrypted ZIPs in memory with password `infected`, hashes
PE candidates, and excludes the original reviewer pools and all other recorded
CSV SHA pools under `validation-data`. Conflicting labels stop the audit. It then
parses unused candidates and reports:

- kernel/driver imports among the fixed five libraries;
- linker version 2 with symbols;
- linker version 2 with symbols, no debug directory and TLS;
- other PE samples.

Outputs go to `validation-data/reviewer-v8-coverage-development/`:

- `coverage-summary.json`: counts, overlap exclusions, category coverage,
  collection provenance and frozen comparison model hashes. Send this file.
- `coverage-manifest.json`: every accepted unused PE, label, source ID, attributes,
  origin root/archive, SHA and development/evaluation role.

For development, matching categories are flagged for possible future addition;
other unused files remain recorded. No files are automatically relabeled, scored,
trained, or copied out of malware archives. Parser/archive failures set
`complete: false` and exit code 2; this is not a complete clean pool. Collection
read/access errors are separately recorded and describe the initial sampling
coverage, rather than archive integrity. Exact SHA exclusion does not establish
malware-family independence or absence from upstream legacy/base-model training.

The baseline/import/follow-up model files must exist so the audit can record v7,
v8 import-upper and v8 import-midpoint model hashes. No Docker service is needed.
Use a new `--output` directory for another collection; manifests are not overwritten.

## Reserve an independent evaluation collection

Obtain another collection from an independent acquisition source, keeping it
separate from development. For a Windows benign ZIP, collect on that source with
`-Role evaluation -SourceId independent-windows-eval -Output <new-zip-path>`.
Then, on the VM:

```bash
./.venv/bin/python scripts/reviewer_v8_coverage.py \
  --benign validation-data/benign-v8-independent-eval.zip \
  --malicious validation-data/malware-v8-independent-eval \
  --source-id independent-windows-eval \
  --role evaluation \
  --exclude-manifest validation-data/reviewer-v8-coverage-development/coverage-manifest.json \
  --output validation-data/reviewer-v8-coverage-evaluation
```

The evaluation audit requires the development exclusion manifest, blocks reusing
its acquisition-source ID, and excludes every SHA from it. It reserves all unused
PE categories rather than filtering evaluation down to the categories targeted
for development. Independent software/family coverage still requires provenance
review; different source IDs alone are insufficient. This step inventories and
reserves data; it does not evaluate model performance. Freeze the model choices
before scoring that batch, and do not use it to tune a replacement afterward.

Tests:

```bash
./.venv/bin/python scripts/test_reviewer_v8_coverage.py
```

The Python tests cover SHA exclusions, duplicate handling, input/known class
conflicts, archive/parser incompleteness, acquisition-source separation, collection
role consistency and all-category evaluation reservation. The Windows collector
must be run on Windows; it was not executed in the Linux development environment.
