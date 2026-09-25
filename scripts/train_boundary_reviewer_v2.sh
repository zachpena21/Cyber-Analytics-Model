#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

exec "${PYTHON}" "${ROOT}/scripts/train_boundary_reviewer_v2.py" \
  --report "${ROOT}/validation-data/reviewer-core-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-benign-final-2-v4.csv" \
  --report "${ROOT}/validation-data/adapter-score-production-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-v5-new-batch.csv" \
  --location "${ROOT}/validation-data/malwarebazaar-final-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-unseen-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-v5-final-20260925" \
  --location "${ROOT}/validation-data/benign-modern.zip" \
  --location "${ROOT}/validation-data/benign-final.zip" \
  --location "${ROOT}/validation-data/benign-final-2.zip" \
  --location "${ROOT}/validation-data/benign-final-3.zip" \
  --location "${ROOT}/validation-data/benign-final-4.zip" \
  "$@"
