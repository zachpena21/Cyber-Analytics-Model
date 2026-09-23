#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "Usage: $0 MALWARE_DIRECTORY BENIGN_DIRECTORY [BASE_API_URL] [VALIDATION_BENIGN]" >&2
  exit 2
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$repo_dir/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  python_bin=python3
fi

args=(
  "$repo_dir/scripts/train_modern_adapter.py"
  --malicious "$1"
  --benign "$2"
  --base-benign-threshold 0.510001
  --max-fpr 0.01
)

if [[ $# -eq 3 ]]; then
  args+=(--base-url "$3")
fi

if [[ $# -eq 4 ]]; then
  args+=(--base-url "$3" --validation-benign "$4")
fi

exec "$python_bin" "${args[@]}"
