#!/usr/bin/env bash
set -euo pipefail

: "${PYLINT_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

json="$SARIF_DIR/pylint.json"
out="$SARIF_DIR/pylint.sarif"
pylint_venv="$RUNNER_TEMP/pylint-${PYLINT_VERSION}"
pylint_python="$pylint_venv/bin/python"
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/pylint-files.XXXXXX")"

cleanup_pylint() {
  rm -rf "$pylint_venv"
  if [ -n "$files_list" ]; then rm -f "$files_list"; fi
}
trap cleanup_pylint EXIT

emit_empty_json() {
  printf '[]' > "$json"
}

discover_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name '.venv' \
    -o -name 'vendor' -o -name '__pycache__' -o -name '.tox' -o -name '.mypy_cache' \
    -o -name '.pytest_cache' -o -name '.terraform' \) -prune \) -o \
    \( -type f -name '*.py' -print0 \)
}

cd "$SOURCE_DIR"
if ! discover_files > "$files_list"; then
  echo "::warning::Pylint file discovery failed - emitting empty Pylint SARIF run."
  emit_empty_json
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    emit_empty_json
  elif [[ ! "$PYLINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::Pylint version must be a pinned x.y.z version - emitting empty Pylint SARIF run."
    emit_empty_json
  elif ! python3 -m venv "$pylint_venv"; then
    echo "::warning::Pylint venv creation failed - emitting empty Pylint SARIF run."
    emit_empty_json
  elif ! "$pylint_python" -m pip install --quiet --disable-pip-version-check "pylint==${PYLINT_VERSION}"; then
    echo "::warning::Pylint install failed - emitting empty Pylint SARIF run."
    emit_empty_json
  else
    if ! installed_version="$("$pylint_python" -m pylint --version 2>/dev/null | sed -n '1s/^pylint //p')"; then
      echo "::warning::Pylint version check failed - emitting empty Pylint SARIF run."
      emit_empty_json
    elif [ "$installed_version" != "$PYLINT_VERSION" ]; then
      echo "::warning::Pylint installed version mismatch - emitting empty Pylint SARIF run."
      emit_empty_json
    elif ! "$pylint_python" -m pylint \
      --rcfile=/dev/null \
      --output-format=json \
      --disable=all \
      --enable=E,F \
      --disable=import-error,no-member \
      --exit-zero \
      --persistent=n \
      --score=n \
      --reports=n \
      --ignore-paths='^\./(.*/)?(\.git|node_modules|dist|build|coverage|\.next|out|\.venv|vendor|__pycache__|\.tox|\.mypy_cache|\.pytest_cache|\.terraform)(/|$)' \
      -- \
      "${files[@]}" > "$json"; then
      if [ ! -s "$json" ]; then
        echo "::warning::Pylint scan failed and produced no JSON output - emitting empty Pylint SARIF run."
        emit_empty_json
      fi
    fi
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/pylint_to_sarif.py" "$json" "$out" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
