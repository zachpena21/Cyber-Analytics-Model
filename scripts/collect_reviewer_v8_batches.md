# MalwareBazaar hourly export fallback

Use this when `mb-api.abuse.ch` returns repeated 502 errors. MalwareBazaar documents hourly exports on the separate official datalake host:
https://datalake.abuse.ch/malware-bazaar/hourly/
https://bazaar.abuse.ch/api/

This script makes **no MalwareBazaar API calls** and reuses the completed benign wheel collection. It requests the public hourly listing and recent available ZIP files on `datalake.abuse.ch`. Availability from the VM is not guaranteed; if this host fails too, retain the error for network diagnosis.

On the VM:

```bash
cd ~/Cyber-Analytics-Model
git pull --ff-only origin main
./.venv/bin/python scripts/collect_reviewer_v8_batches.py --count 200
```

It selects available batches within the last 48 UTC hours, newest first; uses predetermined SHA-based member ordering within each batch; filters to valid PE payloads at most 16 MiB; excludes all frozen development/report SHAs and previously collected API SHAs. Hash filenames, when present, must match payload hashes. No reviewer output influences selection. The label comes from the official malware export and is not independently vetted. Batch hour is **not** a verified sample first-seen date. No API-derived malware signature/family metadata is available.

Downloads are limited to 1 GiB total, 256 MiB per batch by default. Oversize/unavailable batches are logged/skipped; the target of 200 is not guaranteed. Existing selected downloads are preserved; fresh batch downloads are cached separately. Selected malware is kept in AES-encrypted per-SHA ZIPs with password `infected`, using `pyzipper`. Members are read in memory, never executed or extracted as loose executables. Downloaded batch digests and original members are recorded as provenance.

Default output root is `validation-data/reviewer-v8-fresh-acquisition`:

- `malware-batches/collection-summary.json`: actual count/target flag, batches, per-SHA provenance and failures.
- `batch-downloads/`: original hourly ZIPs cached outside the evaluation sample directory.
- `batch-sources.json`: automatically combines the existing completed benign sources with the selected batch malware. It does not overwrite `sources.json` or the partial API collection.

If interrupted, use:

```bash
./.venv/bin/python scripts/collect_reviewer_v8_batches.py --count 200 --resume
```

Resume checks the frozen bundle/target and saved selected archive hashes, preserves the planned batch list, skips processed batches and reuses cached downloads. It does not rely on the API. The collector retries transient network failures and reports if the datalake connection also fails. Controls: `--hours`, `--max-download-mb`, `--max-batch-mb`, `--connect-timeout`, `--read-timeout`, `--attempts`, `--bundle`, `--output`.

Send `malware-batches/collection-summary.json` and the prior `benign/collection-summary.json` for source/size review. For frozen evaluation use this new source file:

```bash
./.venv/bin/python scripts/reviewer_v8_fresh_validation.py evaluate \
  --sources validation-data/reviewer-v8-fresh-acquisition/batch-sources.json \
  --service-url http://192.168.1.193:8082/
```

The existing original-v7 Docker diagnostic service must be running. Keep expanded v8 thresholds frozen. SHA disjointness does not prove family independence; retain that limitation when interpreting this batch.
