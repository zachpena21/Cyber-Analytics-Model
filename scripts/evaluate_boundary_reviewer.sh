#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "${PYTHON}" ]]; then
  echo "Virtual-environment Python not found at ${PYTHON}" >&2
  exit 1
fi

exec "${PYTHON}" "${ROOT}/scripts/evaluate_boundary_reviewer.py" \
  --report "${ROOT}/validation-data/adapter-score-production-v4.csv" \
  --malicious "${ROOT}/validation-data/malwarebazaar-unseen-20260922" \
  --benign "${ROOT}/validation-data/benign-final-3.zip" \
  --model "${ROOT}/defender/defender/models/boundary_reviewer_candidate/model.json" \
  --output-prefix "${ROOT}/validation-data/boundary-reviewer-evaluation-v1" \
  "$@"
