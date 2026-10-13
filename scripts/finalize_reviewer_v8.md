# Final reviewer v8 weights

Deadline selection: keep the existing **frozen structural primary**, fixed
provenance fold zero, route 0.15 and threshold 0.6882517225516912. It had 2 benign
errors among 526 and detected 75 of 92 malware in the recorded acquisition.
The richer, targeted, native and group-weighted experiments remain preserved;
native coverage reduced benign errors but regressed malware detections. No
additional refit, threshold search or compiler exception is selected.

```bash
git pull --ff-only origin main
./.venv/bin/python scripts/test_finalize_reviewer_v8.py
./.venv/bin/python scripts/finalize_reviewer_v8.py
```

The immutable frozen model hash must match the previously evaluated structural
primary. Every cached vector and cascade decision must reproduce bit-for-bit.
The script checks a completed rich feature cache, preserves all existing files,
and writes a new timestamped export with a candidate inventory.

The runtime accepts the existing format 8. The export pads the feature schema
with the six legacy upstream fields and shifts structural split indices by six;
those upstream fields are never used by any tree. All tree values, thresholds,
float32 branch semantics, adapter routing and the frozen decision threshold stay
unchanged. There are 66 structural inputs in a 72-field runtime vector.

Send **reviewer-v8-final-model.zip** and **reviewer-v8-finalization-summary.json**.
The model ZIP contains model weights and metadata only. It is not the final Docker
submission ZIP. After uploading it, the final model can be committed alongside
all prior candidates and incorporated into the inference package.

The remaining task is runtime qualification: the current reference Dockerfile
uses Python 3.9, while the supplied instructions list Python 3.11/3.12 slim images.
Cached-vector export parity does not prove parity after a Python/LIEF migration.
That migration needs actual container extraction/score checks and build/startup,
memory and read-only runtime tests before submitting through Canvas. The recorded
81.52% malware detection does not meet the project's stated 95% goal; none of
these measurements establishes hidden-course performance.
