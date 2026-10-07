# Official-release large-native development collection

This VM-side collector seeks unused benign Windows AMD64 binaries from official
release archives, with no installation or program execution. It keeps the existing
16 MiB PE limit. Selection uses static shape, provenance and SHA overlap only;
no model scores or predictions are requested.

From the repository root:

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_collect_reviewer_v8_official_native.py
./.venv/bin/python scripts/collect_reviewer_v8_official_native.py
```

Docker is unnecessary. The collector uses Python's standard library and the
existing static PE parser. The test also checks compatibility with the existing
feature-cache inventory reader in the project environment.

The initial bounded catalog comprises:

- Official Go Windows archives: the highest published patch release within each
  of Go 1.20–1.25, selected from the official download JSON catalog.
- GitHub CLI: v1.14.0, v2.0.0 and v2.14.0.
- containerd: v1.7.13 and v1.7.28.
- BuildKit: v0.13.2 and v0.16.0.

These historical versions provide version diversity; they are acquisition
candidates, not installation recommendations. Missing assets or absent published
SHA-256 values are reported and skipped. The resolved catalog and checksum
metadata are frozen in the output directory. Sources:
[Go](https://go.dev/dl/), [GitHub CLI](https://github.com/cli/cli/releases),
[containerd](https://github.com/containerd/containerd/releases),
[BuildKit](https://github.com/moby/buildkit/releases).

Every archive must match its published SHA-256 before inspection. Release hashes
verify transfer integrity; this is not signature verification or an independently
confirmed benign label. Original project identity, release version, asset URL,
archive SHA, member name and raw sample SHA are preserved. Multiple versions of
one project retain one software identity and are not independent families.

Default limits: 1 GiB declared download budget, 256 MiB per archive, eight unique
samples per asset, 16 MiB per PE. Exact targets are native AMD64 PEs of 10–16 MiB,
8–10 sections, and at most one imported DLL. Separately reported adjacent targets
are native PEs of 8–16 MiB, 6–12 sections and at most four DLLs. Both require a
complete import parse and no valid CLR metadata. A release can yield zero matches.

By default, the collector unions all `excluded-sha256.json` lists under
`validation-data/`, excluding known samples before quotas. Each exclusion file is
hash-bound. To narrow the source lists deliberately, pass one or more explicit
`--exclude <path>` arguments. Defaults preserve exclusions across the prior
13245-sample cache and the newer targeted samples. Previous bundles are not edited.

A timestamped output directory is printed immediately. Network retries are bounded;
successful archive downloads remain available if another asset fails. Resume with:

```bash
./.venv/bin/python scripts/collect_reviewer_v8_official_native.py \
  --resume validation-data/<printed-collection-directory>
```

Resume reuses downloaded metadata and checksum-verified archives. A partial archive
restarts its download. Completed collections are verified without network access.
Exclusions, collector/parser code and collection limits must match the initial run;
changed inputs or completed outputs cause an error. When overriding limits on the
initial run, provide the same options on resume.

Send **`official-native-collection-summary.json`**. It reports exact/adjacent counts,
known overlaps, distinct projects, asset-level outcomes and failures. The directory
also contains source ZIPs, `sources.json`, and an inventory compatible with the
existing feature collector. Wait for this coverage review before feature collection
or training. Failed assets leave the inventory incomplete until resumed successfully.
Zero matches are a coverage result, not permission to change selection limits.

This is targeted development acquisition informed by earlier misses, not independent
validation, model promotion, or a change to the frozen models.
