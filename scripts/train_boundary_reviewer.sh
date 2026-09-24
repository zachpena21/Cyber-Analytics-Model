#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

exec "${PYTHON}" "${ROOT}/scripts/train_boundary_reviewer.py" \
  --training-report "${ROOT}/validation-data/reviewer-core-v4.csv" \
  --calibration-report "${ROOT}/validation-data/reviewer-benign-final-2-v4.csv" \
  --malicious "${ROOT}/validation-data/malwarebazaar-final-20260922" \
  --training-benign "${ROOT}/validation-data/benign-modern.zip" \
  --training-benign "${ROOT}/validation-data/benign-final.zip" \
  --calibration-benign "${ROOT}/validation-data/benign-final-2.zip" \
  "$@"
