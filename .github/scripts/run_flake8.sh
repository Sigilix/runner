#!/usr/bin/env bash
set -euo pipefail

: "${FLAKE8_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/flake8.txt"
out="$SARIF_DIR/flake8.sarif"
flake8_venv="$RUNNER_TEMP/flake8-${FLAKE8_VERSION}"
flake8_python="$flake8_venv/bin/python"
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/flake8-files.XXXXXX")"

cleanup_flake8() {
  rm -rf "$flake8_venv"
  if [ -n "$files_list" ]; then rm -f "$files_list"; fi
}
trap cleanup_flake8 EXIT

emit_empty_raw() {
  : > "$raw"
}

discover_python_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name '.venv' \
    -o -name 'vendor' -o -name '__pycache__' -o -name '.tox' -o -name '.mypy_cache' \
    -o -name '.pytest_cache' -o -name '.terraform' \) -prune \) -o \
    \( -type f -name '*.py' -print0 \)
}

find_flake8_marker() {
  if [ -f .flake8 ]; then
    printf '%s\n' .flake8
  fi
}

cd "$SOURCE_DIR"
flake8_marker="$(find_flake8_marker)"
if [ -z "$flake8_marker" ]; then
  echo "::notice::No .flake8 marker found - emitting empty Flake8 SARIF run."
  emit_empty_raw
elif ! discover_python_files > "$files_list"; then
  echo "::warning::Flake8 file discovery failed - emitting empty Flake8 SARIF run."
  emit_empty_raw
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    emit_empty_raw
  elif [[ ! "$FLAKE8_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::Flake8 version must be a pinned x.y.z version - emitting empty Flake8 SARIF run."
    emit_empty_raw
  elif ! python3 -m venv "$flake8_venv"; then
    echo "::warning::Flake8 venv creation failed - emitting empty Flake8 SARIF run."
    emit_empty_raw
  elif ! "$flake8_python" -m pip install --quiet --disable-pip-version-check "flake8==${FLAKE8_VERSION}"; then
    echo "::warning::Flake8 install failed - emitting empty Flake8 SARIF run."
    emit_empty_raw
  elif ! flake8_version="$("$flake8_python" -m flake8 --version 2>/dev/null | awk '{print $1}' | head -n 1)"; then
    echo "::warning::Flake8 version check failed - emitting empty Flake8 SARIF run."
    emit_empty_raw
  elif [ "$flake8_version" != "$FLAKE8_VERSION" ]; then
    echo "::warning::Flake8 installed version mismatch - emitting empty Flake8 SARIF run."
    emit_empty_raw
  else
    "$flake8_python" -m flake8 \
      --isolated \
      --select=E9,F63,F7,F82 \
      "--format=%(path)s:%(row)d:%(col)d: %(code)s %(text)s" \
      -- \
      "${files[@]}" > "$raw" || true
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/flake8_to_sarif.py" "$raw" "$out" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
