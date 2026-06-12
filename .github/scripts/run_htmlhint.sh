#!/usr/bin/env bash
set -euo pipefail

: "${HTMLHINT_VERSION:?}"
: "${HTMLHINT_NPM_INTEGRITY:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/htmlhint.raw.sarif"
out="$SARIF_DIR/htmlhint.sarif"
htmlhint_config="$RUNNER_DIR/.github/config/htmlhint-sigilix.json"
htmlhint_install_dir=""
htmlhint_bin=""
htmlhint_package=""
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/htmlhint-files.XXXXXX")"

cleanup_htmlhint() {
  rm -f "$files_list"
  if [ -n "$htmlhint_install_dir" ]; then rm -rf "$htmlhint_install_dir"; fi
}
trap cleanup_htmlhint EXIT

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

verify_package_integrity() {
  local actual
  actual="sha512-$(openssl dgst -sha512 -binary "$1" | openssl base64 -A)"
  [ "$actual" = "$HTMLHINT_NPM_INTEGRITY" ]
}

discover_html_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name 'vendor' \) -prune \) -o \
    \( -type f \( -name '*.html' -o -name '*.htm' -o -name '*.xhtml' \) -print0 \)
}

cd "$SOURCE_DIR"
if [ ! -f "$htmlhint_config" ]; then
  echo "::warning::HTMLHint Sigilix config missing at $htmlhint_config - emitting empty HTMLHint SARIF run."
  emit_empty_sarif
elif ! discover_html_files > "$files_list"; then
  echo "::warning::HTMLHint file discovery failed - emitting empty HTMLHint SARIF run."
  emit_empty_sarif
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    emit_empty_sarif
  elif [[ ! "$HTMLHINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::HTMLHint version must be a pinned x.y.z version - emitting empty HTMLHint SARIF run."
    emit_empty_sarif
  elif [[ ! "$HTMLHINT_NPM_INTEGRITY" =~ ^sha512-[A-Za-z0-9+/]+={0,2}$ ]]; then
    echo "::warning::HTMLHint package integrity must be a pinned sha512 value - emitting empty HTMLHint SARIF run."
    emit_empty_sarif
  else
    htmlhint_can_scan=true
    htmlhint_install_dir="$(mktemp -d "$RUNNER_TEMP/htmlhint-${HTMLHINT_VERSION}.XXXXXX")"
    htmlhint_bin="$htmlhint_install_dir/node_modules/.bin/htmlhint"
    if ! htmlhint_package_json="$(npm pack --json --silent --pack-destination "$htmlhint_install_dir" \
      --registry=https://registry.npmjs.org \
      "htmlhint@${HTMLHINT_VERSION}")"; then
      echo "::warning::HTMLHint package download failed - emitting empty HTMLHint SARIF run."
      htmlhint_can_scan=false
    elif ! htmlhint_package="$(PACK_JSON="$htmlhint_package_json" python3 - <<'PY'
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
      echo "::warning::HTMLHint package download returned invalid metadata - emitting empty HTMLHint SARIF run."
      htmlhint_can_scan=false
    else
      package_name="${htmlhint_package##*/}"
      if [[ ! "$package_name" =~ ^htmlhint-[0-9]+[.][0-9]+[.][0-9]+[.]tgz$ ]]; then
        echo "::warning::HTMLHint package download returned an unexpected filename - emitting empty HTMLHint SARIF run."
        htmlhint_can_scan=false
      else
        htmlhint_package="$htmlhint_install_dir/$package_name"
      fi
    fi

    if [ "$htmlhint_can_scan" = true ] && [ ! -f "$htmlhint_package" ]; then
      echo "::warning::HTMLHint package tarball missing after download - emitting empty HTMLHint SARIF run."
      htmlhint_can_scan=false
    elif [ "$htmlhint_can_scan" = true ] && ! verify_package_integrity "$htmlhint_package"; then
      echo "::warning::HTMLHint package integrity mismatch - emitting empty HTMLHint SARIF run."
      rm -f "$htmlhint_package"
      htmlhint_can_scan=false
    elif [ "$htmlhint_can_scan" = true ] && ! npm install --silent --prefix "$htmlhint_install_dir" --ignore-scripts --omit=optional \
      --registry=https://registry.npmjs.org --no-audit --no-fund \
      "$htmlhint_package" >/dev/null; then
      echo "::warning::HTMLHint package install failed - emitting empty HTMLHint SARIF run."
      htmlhint_can_scan=false
    elif [ "$htmlhint_can_scan" = true ] && [ ! -x "$htmlhint_bin" ]; then
      echo "::warning::HTMLHint binary missing after install - emitting empty HTMLHint SARIF run."
      htmlhint_can_scan=false
    fi

    if [ "$htmlhint_can_scan" = false ]; then
      emit_empty_sarif
    else
      "$htmlhint_bin" \
        --config "$htmlhint_config" \
        --format sarif \
        "${files[@]}" > "$raw" || true
      if [ ! -s "$raw" ]; then
        echo "::warning::HTMLHint scan produced no SARIF output - emitting empty HTMLHint SARIF run."
        emit_empty_sarif
      fi
    fi
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
  htmlhint "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
