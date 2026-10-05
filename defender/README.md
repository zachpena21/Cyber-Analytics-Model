# Defender Docker context

See the [repository README](../README.md) for current model status and commands.
This directory contains the existing inference runtime and tracked reviewer
references. Structural v8 remains an offline candidate in a local frozen bundle.

From the repository root, stage the supplied verified course model and build:

```bash
python scripts/stage_model.py /path/to/NFS_21_ALL_hash_50000_WITH_MLSEC20.zip
docker build -t blackbox-defense:v7-reference ./defender
```

The default runtime uses the modern adapter and leaves boundary review disabled.
Enable v7 with `DF_ENABLE_BOUNDARY_REVIEWER=1` and set
`DF_REVIEWER_DIR=/opt/defender/defender/models/boundary_reviewer_v7_gbdt_candidate`.
The base threshold remains `0.510001`; the adapter threshold is `0.70`.

The builder converts the forest into memory-mapped arrays and reconstructs v4/v5
JSON artifacts from committed chunks. Those generated files are ignored by Git.

The Dockerfile still uses Python 3.9 with legacy dependencies. It requires a
separate migration and feature/score parity check for the advertised submission
Python 3.11/3.12 policy. This cleanup does not change runtime behavior.
