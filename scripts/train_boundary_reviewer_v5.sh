#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
OUTPUT="${ROOT}/defender/defender/models/boundary_reviewer_v5_candidate"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

# Reviewer v5 keeps the legacy model and modern adapter frozen and jointly
# calibrates only the reviewer routing gate + reviewer model/threshold.
# v8 and v9 have already been inspected, so they are development data here.
# A later disjoint malware/benign corpus is required for final evaluation.
exec "${PYTHON}" "${ROOT}/scripts/train_boundary_reviewer_v5.py" \
  --report "${ROOT}/validation-data/reviewer-core-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-benign-final-2-v4.csv" \
  --report "${ROOT}/validation-data/adapter-score-production-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-v5-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v2-v6-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v3-v8-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v4-v9-dev.csv" \
  --location "${ROOT}/validation-data/malwarebazaar-final-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-unseen-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-v5-final-20260925" \
  --location "${ROOT}/validation-data/malwarebazaar-v6-final-20260925" \
  --location "${ROOT}/validation-data/malwarebazaar-v8-final-20260926" \
  --location "${ROOT}/validation-data/malwarebazaar-v9-final-20260926" \
  --location "${ROOT}/validation-data/benign-modern.zip" \
  --location "${ROOT}/validation-data/benign-final.zip" \
  --location "${ROOT}/validation-data/benign-final-2.zip" \
  --location "${ROOT}/validation-data/benign-final-3.zip" \
  --location "${ROOT}/validation-data/benign-final-4.zip" \
  --location "${ROOT}/validation-data/benign-final-5.zip" \
  --location "${ROOT}/validation-data/benign-final-7.zip" \
  --location "${ROOT}/validation-data/benign-final-8.zip" \
  --output "${OUTPUT}" \
  "$@"
