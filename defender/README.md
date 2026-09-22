# Defender Docker Context

See the repository-level [`README.md`](../README.md) for setup, validation,
threshold calibration, and benchmark instructions.

The course model must first be staged from the supplied ZIP:

```bash
python scripts/stage_model.py /path/to/NFS_21_ALL_hash_50000_WITH_MLSEC20.zip
```

Then build this directory from the repository root:

```bash
docker build -t blackbox-defense ./defender
```

The builder converts the sklearn random forest to memory-mapped arrays and
removes the original high-memory pickle from the final image.
