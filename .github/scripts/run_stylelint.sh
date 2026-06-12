#!/usr/bin/env bash
set -euo pipefail

: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${STYLELINT_NPM_INTEGRITY:?}"
: "${STYLELINT_VERSION:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

json="$SARIF_DIR/stylelint.json"
out="$SARIF_DIR/stylelint.sarif"
stylelint_config="$RUNNER_DIR/.github/config/stylelint-sigilix.json"
stylelint_install_dir=""
stylelint_bin=""
stylelint_package=""
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/stylelint-files.XXXXXX")"

cleanup_stylelint() {
  rm -f "$files_list"
  if [ -n "$stylelint_install_dir" ]; then rm -rf "$stylelint_install_dir"; fi
}
trap cleanup_stylelint EXIT

emit_empty_json() {
  printf '[]' > "$json"
}

verify_package_integrity() {
  local actual
  actual="sha512-$(openssl dgst -sha512 -binary "$1" | openssl base64 -A)"
  [ "$actual" = "$STYLELINT_NPM_INTEGRITY" ]
}

discover_stylesheet_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name 'vendor' \) -prune \) -o \
    \( -type f -name '*.css' -print0 \)
}

cd "$SOURCE_DIR"
if [ ! -f "$stylelint_config" ]; then
  echo "::warning::Stylelint Sigilix config missing at $stylelint_config - emitting empty Stylelint SARIF run."
  emit_empty_json
elif ! discover_stylesheet_files > "$files_list"; then
  echo "::warning::Stylelint file discovery failed - emitting empty Stylelint SARIF run."
  emit_empty_json
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    emit_empty_json
  elif [[ ! "$STYLELINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::Stylelint version must be a pinned x.y.z version - emitting empty Stylelint SARIF run."
    emit_empty_json
  elif [[ ! "$STYLELINT_NPM_INTEGRITY" =~ ^sha512-[A-Za-z0-9+/]+={0,2}$ ]]; then
    echo "::warning::Stylelint package integrity must be a pinned sha512 value - emitting empty Stylelint SARIF run."
    emit_empty_json
  else
    stylelint_can_scan=true
    stylelint_install_dir="$(mktemp -d "$RUNNER_TEMP/stylelint-${STYLELINT_VERSION}.XXXXXX")"
    stylelint_bin="$stylelint_install_dir/node_modules/.bin/stylelint"
    if ! stylelint_package_json="$(npm pack --json --silent --pack-destination "$stylelint_install_dir" \
      --registry=https://registry.npmjs.org \
      "stylelint@${STYLELINT_VERSION}")"; then
      echo "::warning::Stylelint package download failed - emitting empty Stylelint SARIF run."
      stylelint_can_scan=false
    elif ! stylelint_package="$(PACK_JSON="$stylelint_package_json" python3 - <<'PY'
import json
import os
import sys

try:
    data = json.loads(os.environ["PACK_JSON"])
    if not isinstance(data, list) or len(data) != 1:
        raise ValueError("expected one packed package")
    filename = data[0].get("filename")
    if not isinstance(filename, str) or not filename:
        raise ValueError("missing packed filename")
    print(filename)
except Exception:
    sys.exit(1)
PY
)"; then
      echo "::warning::Stylelint package download returned invalid metadata - emitting empty Stylelint SARIF run."
      stylelint_can_scan=false
    else
      package_name="${stylelint_package##*/}"
      if [[ ! "$package_name" =~ ^stylelint-[0-9]+[.][0-9]+[.][0-9]+[.]tgz$ ]]; then
        echo "::warning::Stylelint package download returned an unexpected filename - emitting empty Stylelint SARIF run."
        stylelint_can_scan=false
      else
        stylelint_package="$stylelint_install_dir/$package_name"
      fi
    fi

    if [ "$stylelint_can_scan" = true ] && [ ! -f "$stylelint_package" ]; then
      echo "::warning::Stylelint package tarball missing after download - emitting empty Stylelint SARIF run."
      stylelint_can_scan=false
    elif [ "$stylelint_can_scan" = true ] && ! verify_package_integrity "$stylelint_package"; then
      echo "::warning::Stylelint package integrity mismatch - emitting empty Stylelint SARIF run."
      rm -f "$stylelint_package"
      stylelint_can_scan=false
    elif [ "$stylelint_can_scan" = true ] && ! npm install --silent --prefix "$stylelint_install_dir" --ignore-scripts --omit=optional \
      --registry=https://registry.npmjs.org --no-audit --no-fund \
      "$stylelint_package" >/dev/null; then
      echo "::warning::Stylelint package install failed - emitting empty Stylelint SARIF run."
      stylelint_can_scan=false
    elif [ "$stylelint_can_scan" = true ] && [ ! -x "$stylelint_bin" ]; then
      echo "::warning::Stylelint binary missing after install - emitting empty Stylelint SARIF run."
      stylelint_can_scan=false
    fi

    if [ "$stylelint_can_scan" = false ]; then
      emit_empty_json
    else
      "$stylelint_bin" \
        "${files[@]}" \
        --config "$stylelint_config" \
        --formatter json \
        --output-file "$json" \
        --allow-empty-input \
        --no-color || true
      if [ ! -s "$json" ]; then
        echo "::warning::Stylelint scan produced no JSON output - emitting empty Stylelint SARIF run."
        emit_empty_json
      fi
    fi
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/stylelint_to_sarif.py" "$json" "$out" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
