#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
OUTPUT="${ROOT}/defender/defender/models/modern_adapter_v2_candidate"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

# All reports below have already been inspected and are development data.
# v10 is explicitly included after the frozen reviewer-v5 final-style check
# missed 3/20 malware.  Adapter v2 must be frozen before any later disjoint
# evaluation is inspected.
exec "${PYTHON}" "${ROOT}/scripts/train_modern_adapter_v2.py" \
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
  --output "${OUTPUT}" \
  "$@"
