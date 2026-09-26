#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"
OUTPUT="${ROOT}/defender/defender/models/boundary_reviewer_v4_candidate"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

# Reviewer v4 treats every inspected v4/v5/v6/v7/v8 corpus as development
# data. The v8 score audit is included because the frozen v3 reviewer missed
# 2/7 malware on the new distribution while producing 0 false positives.
# A later disjoint corpus must still be used for final evaluation.
exec "${PYTHON}" "${ROOT}/scripts/train_boundary_reviewer_v2.py" \
  --report "${ROOT}/validation-data/reviewer-core-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-benign-final-2-v4.csv" \
  --report "${ROOT}/validation-data/adapter-score-production-v4.csv" \
  --report "${ROOT}/validation-data/reviewer-v5-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v2-v6-new-batch.csv" \
  --report "${ROOT}/validation-data/reviewer-v3-v8-new-batch.csv" \
  --location "${ROOT}/validation-data/malwarebazaar-final-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-unseen-20260922" \
  --location "${ROOT}/validation-data/malwarebazaar-v5-final-20260925" \
  --location "${ROOT}/validation-data/malwarebazaar-v6-final-20260925" \
  --location "${ROOT}/validation-data/malwarebazaar-v8-final-20260926" \
  --location "${ROOT}/validation-data/benign-modern.zip" \
  --location "${ROOT}/validation-data/benign-final.zip" \
  --location "${ROOT}/validation-data/benign-final-2.zip" \
  --location "${ROOT}/validation-data/benign-final-3.zip" \
  --location "${ROOT}/validation-data/benign-final-4.zip" \
  --location "${ROOT}/validation-data/benign-final-5.zip" \
  --location "${ROOT}/validation-data/benign-final-7.zip" \
  --output "${OUTPUT}" \
  "$@"
