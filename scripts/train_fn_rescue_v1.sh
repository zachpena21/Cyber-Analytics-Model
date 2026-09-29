#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
OUTPUT="${ROOT}/defender/defender/models/fn_rescue_v1_candidate"
REVIEWER_DIR="${ROOT}/defender/defender/models/boundary_reviewer_v5_candidate"
REVIEWER_MODEL="${REVIEWER_DIR}/model.json"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

# Reviewer v5 is stored in the repository as deterministic gzip/base64 chunks.
# Reconstruct the exact frozen model locally when model.json is absent, matching
# the Docker build path and verifying its known SHA-256 before use.
if [[ ! -f "${REVIEWER_MODEL}" ]]; then
  echo "Reconstructing frozen reviewer-v5 model.json from payload parts..." >&2
  "${PYTHON}" - "${REVIEWER_DIR}" <<'PY'
import base64
import gzip
import hashlib
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
parts = sorted(p.glob("model.json.gz.b64.part-*"))
if len(parts) != 2:
    raise SystemExit(f"expected 2 reviewer-v5 payload parts, found {len(parts)}")
raw = gzip.decompress(base64.b64decode("".join(x.read_text() for x in parts)))
expected = "3decc3b4fd372d1812888ac53686ef1f2f3fc271ffae4d33f06db22710ff8ac3"
actual = hashlib.sha256(raw).hexdigest()
if actual != expected:
    raise SystemExit(f"reviewer-v5 model checksum mismatch: {actual}")
obj = json.loads(raw)
if len(obj.get("estimators", [])) != 192:
    raise SystemExit("unexpected reviewer-v5 tree count")
if len(obj.get("feature_names", [])) != 54:
    raise SystemExit("unexpected reviewer-v5 feature count")
if abs(float(obj.get("route_min")) - 0.3) >= 1e-12:
    raise SystemExit("unexpected reviewer-v5 route_min")
if abs(float(obj.get("reviewer_threshold")) - 0.4870135287958894) >= 1e-12:
    raise SystemExit("unexpected reviewer-v5 threshold")
(p / "model.json").write_bytes(raw)
print(f"Reconstructed {p / 'model.json'}")
PY
fi

exec "${PYTHON}" "${ROOT}/scripts/train_fn_rescue_v1.py" \
  --reviewer-model "${REVIEWER_MODEL}" \
  --report "${ROOT}/validation-data/reviewer-core-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-benign-final-2-v4.csv" \
  --report "${ROOT}/validation-data/adapter-score-production-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-v5-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v2-v6-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v3-v8-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v4-v9-dev.csv" \
  --report "${ROOT}/validation-data/reviewer-v5-v10-diagnostic.csv" \
  --location "${ROOT}/validation-data/malwarebazaar-final-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-unseen-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-v5-final-20260925" \
  --location "${ROOT}/validation-data/malwarebazaar-v6-final-20260925" \
  --location "${ROOT}/validation-data/malwarebazaar-v8-final-20260926" \
  --location "${ROOT}/validation-data/malwarebazaar-v9-final-20260926" \
  --location "${ROOT}/validation-data/malwarebazaar-v10-final-eligible-20260928" \
  --location "${ROOT}/validation-data/benign-modern.zip" \
  --location "${ROOT}/validation-data/benign-final.zip" \
  --location "${ROOT}/validation-data/benign-final-2.zip" \
  --location "${ROOT}/validation-data/benign-final-3.zip" \
  --location "${ROOT}/validation-data/benign-final-4.zip" \
  --location "${ROOT}/validation-data/benign-final-5.zip" \
  --location "${ROOT}/validation-data/benign-final-7.zip" \
  --location "${ROOT}/validation-data/benign-final-8.zip" \
  --location "${ROOT}/validation-data/benign-final-9-eligible.zip" \
  --holdout-source reviewer-v4-v9-dev \
  --holdout-source reviewer-v5-v10-diagnostic \
  --output "${OUTPUT}" \
  "$@"
