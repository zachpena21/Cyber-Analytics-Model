# Fresh acquisitions for frozen expanded v8

Run on the Linux VM, after the freeze succeeded. Nothing is installed from downloaded wheels or executed from malware archives. This collects an evaluation batch; leave deployed v7 unchanged.

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python -m pip install requests pyzipper packaging
./.venv/bin/python scripts/collect_reviewer_v8_fresh.py benign
./.venv/bin/python scripts/collect_reviewer_v8_fresh.py malware --count 200
./.venv/bin/python scripts/collect_reviewer_v8_fresh.py sources
```

The malware command uses `MALWAREBAZAAR_AUTH_KEY`, `MALWAREBAZAAR_API_KEY`, or `MB_API_KEY`, if present. Otherwise it asks for an Auth-Key with hidden input. Obtain a key through https://auth.abuse.ch/ if needed. Do not paste it into chat, commit it, or pass it as a command-line argument. The collector never writes the key.

## Benign source

The collector uses the official PyPI JSON API and download host, checks the published wheel SHA-256, and reads Windows x64 CPython 3.12 wheels **without installing them**. Defaults: SciPy, NumPy, scikit-learn, pandas, Matplotlib, Pillow, lxml and psutil. Up to two stable versions per package, preferring distinct minor versions. It excludes yanked/prerelease releases and Linux wheels. Some packages use different ABI tags, so unavailable matching wheels are reported, not counted as successful acquisitions.

It saves verified PE members only (`.pyd`, `.dll`, `.exe`, `.sys`) in per-wheel ZIPs, excluding all frozen SHAs. It records package/version/ABI, original member path, wheel URL/digest/upload date and each PE digest. PyPI publisher provenance supports the benign label; it is not independent sample vetting. Default wheel download budget: 1 GiB; per-PE cap: 16 MiB. Sample count depends on available versions and overlap. Different builds of the same library may remain related.

Use another output root for additional batches, for example:

```bash
./.venv/bin/python scripts/collect_reviewer_v8_fresh.py benign \
  --abis cp311 cp313 --output validation-data/reviewer-v8-fresh-acquisition-extra
```

This **targets the scientific-library failures**. It does not replace fresh Git/GNU, Cura/KiCad, Windows drivers or ordinary benign software coverage. Those should be collected from separately obtained official builds/independent trusted installations with the existing Windows collector and explicit evaluation role; do not recopy old installations and call them independent. Add those verified paths/provenance to a separate source file when available.

## Malware source

The collector queries MalwareBazaar's recent EXE and DLL metadata (up to 1,000 records per type), keeps samples first seen within seven days and at most 16 MiB, excludes frozen SHAs, and downloads in a predetermined SHA-based order. Target: 200 verified PE payloads, not a guaranteed number. It uses no reviewer scores for selection. All query parameters, first/last seen, reported signature/tags and other returned metadata are retained. Family counts are reported; **new SHA or first-seen date does not establish malware-family independence**. Labels come from MalwareBazaar and remain subject to provenance review.

Downloads remain in their original encrypted ZIPs. The collector reads them in memory using `pyzipper`/password `infected`, checks the requested payload SHA and PE header, and rejects additional unexpected PE payloads. It does not extract or execute malware. Keep this collection on the VM. It pauses one second per download, stops on HTTP errors and records failures. Some samples can be unavailable; it reports `target_met=false` with the actual count rather than claiming 200 samples.

If interrupted:

```bash
./.venv/bin/python scripts/collect_reviewer_v8_fresh.py malware --count 200 --resume
```

Resume checks the same frozen bundle/target and all saved archive hashes, retains the original query pool/date window and skips completed downloads. Do not use resume with benign collection. After a benign download failure, use a new `--output` root and the same root for all subsequent commands. With no eligible malware, acquire later or use an explicitly wider `--days` window in a new root.

Official API documentation: https://bazaar.abuse.ch/api/ . PyPI JSON API: https://docs.pypi.org/api/json/ . Current MalwareBazaar requests require `Auth-Key`; downloads are AES-encrypted ZIPs.

## Sources and evaluation

Default outputs are under `validation-data/reviewer-v8-fresh-acquisition`:

- `benign/collection-summary.json`: actual package/member counts, overlap and unavailable choices.
- `malware/collection-summary.json`: actual downloaded count, target flag, signature distribution, per-sample metadata and failures.
- `sources.json`: ready-to-use input for frozen comparison; produced only after both collections complete against the same frozen bundle. Archive hashes are checked when generating it.

Send both collection summaries first so batch size/source diversity can be assessed. Then start the rebuilt v7 Docker diagnostic service on Windows:

```powershell
.\scripts\start_reviewer_diagnostic.ps1 -Version v7
```

And run on the VM:

```bash
./.venv/bin/python scripts/reviewer_v8_fresh_validation.py evaluate \
  --sources validation-data/reviewer-v8-fresh-acquisition/sources.json \
  --service-url http://192.168.1.193:8082/
```

The frozen comparison rejects development overlap again and checks original v7 Docker parity before writing complete results. Treat source-specific outcomes separately; a scientific-library-heavy benign pool is not representative of all benign Windows programs. Do not tune thresholds from this evaluation and continue calling it independent validation.
