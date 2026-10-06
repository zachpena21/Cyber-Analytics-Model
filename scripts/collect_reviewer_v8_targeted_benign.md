# Targeted benign development collection and blocker identity metadata

The pattern audit found no tiny-managed fit examples in folds 2/3 and only zero or
one large-native benign fit example per fold. This workflow stages additional
installed Windows PEs and statically reads version/import metadata from old
blockers. It does not train, deploy, change thresholds or relabel existing files.

## 1. Inspect the existing blockers on the VM

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/test_reviewer_v8_targeted_benign.py
./.venv/bin/python scripts/reviewer_v8_blocker_metadata.py --debug
```

The inspector selects the newest completed pattern-coverage run and reads the
already cached archives. It matches exact SHA-256, then reports available
CompanyName, ProductName, OriginalFilename, FileDescription and version strings.
Send `blocker-metadata-summary.json` from the printed output directory. Missing
version resources are explicit; strings and certificate-directory presence are
unverified claims. No samples are extracted to disk or executed.

## 2. Stage additional installed Windows candidates

Run in Windows PowerShell from the Windows repository:

```powershell
Set-Location 'C:\Users\zacpe\Documents\CSCE 704 Project\Cyber-Analytics-Model'
git pull --ff-only origin main
py scripts/collect_reviewer_v8_targeted_benign.py collect --output validation-data/reviewer-v8-targeted-benign-windows-20261006
```

This command requires Python 3.9+ but no new Python packages. If the launcher is
not installed, replace `py` with the existing `python` command. Default roots are
Program Files and Program Files (x86). Use explicit installed application roots
with repeated `--scan-root` if needed. It never downloads or installs applications.
Do not point this benign collector at Downloads or sample-storage directories.

Selection uses static PE structure and ordinary imports:

- Tiny managed: valid CLR metadata, <=8 KiB, <=3 sections, <=1 DLL import.
- Large native: no valid CLR metadata, 10–16 MiB, 8–10 sections, <=1 DLL import.
- Managed without imports: valid CLR metadata, 64–512 KiB, no DLL imports.
- Controls: other valid installed PEs with a complete static import parse.

Defaults cap each product directory at ten files per target pattern plus three
controls. Round-robin product selection caps the collection at 400 files and
500 MiB of uncompressed PE bytes. Individual PEs remain <=16 MiB, matching prior
workflow limits. Products with no matching files contribute no target examples.
Counts and warnings are written to `collection-summary.json`; empty or sparse
coverage is reported rather than presumed sufficient.

Each product directory receives a separate ZIP containing PE bytes plus
`collection-manifest.json`. Original paths, category, raw SHA, bounded static
imports, version metadata, collection time and product-directory provenance are
preserved. Reparse/junction directories and symlink files are skipped. Selection
uses no model scores. Historical overlaps are not checked until the VM step.
Installed-root provenance supplies candidate benign labels; it is not independent
verification. The workflow does not treat a filename, product string, CLR flag,
resource-DLL name or certificate-directory presence as proof of trust.

## 3. Remove known SHAs on the VM

Copy the entire generated Windows directory into the VM's `validation-data/`,
preserving its name and contents. Then run:

```bash
./.venv/bin/python scripts/collect_reviewer_v8_targeted_benign.py inventory \
  --collection validation-data/reviewer-v8-targeted-benign-windows-20261006 \
  --exclude validation-data/reviewer-v8-rich-feature-cache-20261006-050159-967490/excluded-sha256.json
```

The exclusion file is the 13,245-SHA rich development cache, not only the older
frozen bundle's exclusions. If using a newer development cache, pass its complete
exclusion list. The inventory validates archive SHA, manifest identity, each
payload SHA/size/label and its static target category, removes historical overlaps
and duplicates, and writes new filtered product ZIPs plus `sources.json`.

Send `targeted-benign-inventory-summary.json` from its printed output directory.
Its new-sample counts and product counts determine whether coverage has improved;
product directories are not automatically independent build/software families.
These are development acquisitions. Do not use them as untouched validation or
rebuild the existing frozen bundles. Before training, new SHAs still need original
Docker feature extraction, rich feature collection, grouping and parity checks.
Static diagnostic imports are not presumed equivalent to the Docker LIEF extractor.

Both steps require a new or empty output directory. An interrupted collection may
leave partial ZIPs without a completed summary; rerun into a new directory after
resolving the failure. All generated files remain local under ignored
`validation-data/`; commit only these scripts/docs, not samples or local reports.

## Static parser scope

`reviewer_v8_pe_metadata.py` reads PE32/PE32+ section mappings, bounded ordinary
import descriptors, CLR metadata validity, and the version-resource string tree.
It does not extract delayed imports or verify signatures. Malformed import tables
prevent targeting; version-resource errors are reported. This is an acquisition
metadata parser, not a replacement runtime feature extractor.

Layout references: [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
and [VERSIONINFO resource](https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource).
