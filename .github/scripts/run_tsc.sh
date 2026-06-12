#!/usr/bin/env bash
set -euo pipefail

: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${TYPESCRIPT_NPM_INTEGRITY:?}"
: "${TYPESCRIPT_VERSION:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/tsc.txt"
out="$SARIF_DIR/tsc.sarif"
tsc_install_dir=""
tsc_bin=""
tsc_package=""
tsc_version=""
configs_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
configs_list="$(mktemp "$RUNNER_TEMP/tsc-configs.XXXXXX")"

cleanup_tsc() {
  rm -f "$configs_list"
  if [ -n "$tsc_install_dir" ]; then rm -rf "$tsc_install_dir"; fi
}
trap cleanup_tsc EXIT

emit_empty_raw() {
  : > "$raw"
}

verify_package_integrity() {
  local actual
  actual="sha512-$(openssl dgst -sha512 -binary "$1" | openssl base64 -A)"
  [ "$actual" = "$TYPESCRIPT_NPM_INTEGRITY" ]
}

discover_tsconfigs() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name '.venv' \
    -o -name 'vendor' -o -name '__pycache__' -o -name '.tox' -o -name '.mypy_cache' \
    -o -name '.pytest_cache' -o -name '.terraform' \) -prune \) -o \
    \( -type f \( -name 'tsconfig.json' -o -name 'tsconfig.*.json' \) -print0 \)
}

cd "$SOURCE_DIR"
if ! discover_tsconfigs > "$configs_list"; then
  echo "::warning::TypeScript config discovery failed - emitting empty TypeScript SARIF run."
  emit_empty_raw
elif [[ ! "$TYPESCRIPT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::TypeScript version must be a pinned x.y.z version - emitting empty TypeScript SARIF run."
  emit_empty_raw
elif [[ ! "$TYPESCRIPT_NPM_INTEGRITY" =~ ^sha512-[A-Za-z0-9+/]+={0,2}$ ]]; then
  echo "::warning::TypeScript package integrity must be a pinned sha512 value - emitting empty TypeScript SARIF run."
  emit_empty_raw
else
  configs=()
  while IFS= read -r -d '' config; do
    configs+=("$config")
  done < "$configs_list"

  if [ "${#configs[@]}" -eq 0 ]; then
    emit_empty_raw
  else
    tsc_can_scan=true
    tsc_install_dir="$(mktemp -d "$RUNNER_TEMP/tsc-${TYPESCRIPT_VERSION}.XXXXXX")"
    tsc_bin="$tsc_install_dir/node_modules/.bin/tsc"
    if ! tsc_package="$(npm pack --silent --pack-destination "$tsc_install_dir" \
      --registry=https://registry.npmjs.org \
      "typescript@${TYPESCRIPT_VERSION}" | tail -n 1)"; then
      echo "::warning::TypeScript package download failed - emitting empty TypeScript SARIF run."
      tsc_can_scan=false
    else
      tsc_package="$tsc_install_dir/${tsc_package##*/}"
    fi

    if [ "$tsc_can_scan" = true ] && [ ! -f "$tsc_package" ]; then
      echo "::warning::TypeScript package tarball missing after download - emitting empty TypeScript SARIF run."
      tsc_can_scan=false
    elif [ "$tsc_can_scan" = true ] && ! verify_package_integrity "$tsc_package"; then
      echo "::warning::TypeScript package integrity mismatch - emitting empty TypeScript SARIF run."
      tsc_can_scan=false
    elif [ "$tsc_can_scan" = true ] && ! npm install --silent --prefix "$tsc_install_dir" --ignore-scripts --omit=optional \
      --registry=https://registry.npmjs.org --no-audit --no-fund \
      "$tsc_package" >/dev/null; then
      echo "::warning::TypeScript package install failed - emitting empty TypeScript SARIF run."
      tsc_can_scan=false
    elif [ "$tsc_can_scan" = true ] && [ ! -x "$tsc_bin" ]; then
      echo "::warning::TypeScript compiler binary missing after install - emitting empty TypeScript SARIF run."
      tsc_can_scan=false
    elif [ "$tsc_can_scan" = true ] && ! tsc_version="$("$tsc_bin" --version 2>/dev/null)"; then
      tsc_can_scan=false
    elif [ "$tsc_can_scan" = true ]; then
      tsc_version="$(printf '%s\n' "$tsc_version" | grep -Eo '^(Version|v)[[:space:]]*[0-9]+[.][0-9]+[.][0-9]+' | grep -Eo '[0-9]+[.][0-9]+[.][0-9]+' | head -n 1 || true)"
      if [ "$tsc_version" != "$TYPESCRIPT_VERSION" ]; then
        tsc_can_scan=false
      fi
    fi

    if [ "$tsc_can_scan" = false ]; then
      echo "::warning::TypeScript version mismatch or unavailable: expected ${TYPESCRIPT_VERSION}, got '${tsc_version:-unavailable}' - emitting empty TypeScript SARIF run."
      emit_empty_raw
    else
      : > "$raw"
      for config in "${configs[@]}"; do
        tsc_exit=0
        "$tsc_bin" --project "$config" --noEmit --pretty false --skipLibCheck --noErrorTruncation >> "$raw" 2>&1 || tsc_exit=$?
        if [ "$tsc_exit" -gt 2 ]; then
          echo "::warning::TypeScript exited with code $tsc_exit for $config - results may be incomplete."
        fi
        printf '\n' >> "$raw"
      done
    fi
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/tsc_to_sarif.py" "$raw" "$out" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
