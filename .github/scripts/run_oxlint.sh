#!/usr/bin/env bash
set -euo pipefail

: "${OXLINT_LINUX_X64_GNU_INTEGRITY:?}"
: "${OXLINT_NPM_INTEGRITY:?}"
: "${OXLINT_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/oxlint.raw.sarif"
out="$SARIF_DIR/oxlint.sarif"
oxlint_config="$RUNNER_DIR/.github/config/oxlint-sigilix.oxlintrc.jsonc"
oxlint_pack_dir="$RUNNER_TEMP/oxlint-pack"
oxlint_install_dir="$RUNNER_TEMP/oxlint-${OXLINT_VERSION}"
oxlint_package="$oxlint_pack_dir/oxlint-${OXLINT_VERSION}.tgz"
oxlint_binding_package="$oxlint_pack_dir/oxlint-binding-linux-x64-gnu-${OXLINT_VERSION}.tgz"
oxlint_bin="$oxlint_install_dir/node_modules/.bin/oxlint"
files_list="$RUNNER_TEMP/oxlint-files"

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"

sri_sha512() { printf 'sha512-%s' "$(openssl dgst -sha512 -binary "$1" | openssl base64 -A)"; }

tarball_size() {
  if [ ! -r "$1" ]; then
    printf '0'
    return
  fi
  wc -c < "$1" | tr -d '[:space:]'
}

cd "$SOURCE_DIR"
if ! find -P . \
  \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
  -o -name 'coverage' -o -name '.next' -o -name 'out' \) -prune \) -o \
  \( -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' \
  -o -name '*.ts' -o -name '*.tsx' \) -print0 \) > "$files_list"; then
  echo "::warning::oxlint file discovery failed - manifest will record missing output."
else
  mapfile -d '' files < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    printf '{"version":"2.1.0","runs":[]}' > "$raw"
  elif [ ! -f "$oxlint_config" ]; then
    echo "::warning::oxlint Sigilix config missing at $oxlint_config - manifest will record missing output."
  else
    oxlint_can_scan=true
    mkdir -p "$oxlint_pack_dir" "$oxlint_install_dir"
    if ! npm pack --silent --pack-destination "$oxlint_pack_dir" \
      --registry=https://registry.npmjs.org \
      "oxlint@${OXLINT_VERSION}" "@oxlint/binding-linux-x64-gnu@${OXLINT_VERSION}" >/dev/null; then
      echo "::warning::oxlint package download failed - manifest will record missing output."
      oxlint_can_scan=false
    elif [ ! -s "$oxlint_package" ] || [ ! -s "$oxlint_binding_package" ]; then
      echo "::warning::oxlint package tarball missing after download - manifest will record missing output."
      oxlint_can_scan=false
    elif [ "$(tarball_size "$oxlint_package")" -le 1024 ] \
      || [ "$(tarball_size "$oxlint_binding_package")" -le 1024 ]; then
      echo "::warning::oxlint package tarball at or below 1024 bytes after download - manifest will record missing output."
      oxlint_can_scan=false
    elif [ "$(sri_sha512 "$oxlint_package")" != "$OXLINT_NPM_INTEGRITY" ]; then
      echo "::warning::oxlint package integrity mismatch - manifest will record missing output."
      oxlint_can_scan=false
    elif [ "$(sri_sha512 "$oxlint_binding_package")" != "$OXLINT_LINUX_X64_GNU_INTEGRITY" ]; then
      echo "::warning::oxlint linux binding integrity mismatch - manifest will record missing output."
      oxlint_can_scan=false
    elif ! npm install --silent --prefix "$oxlint_install_dir" --ignore-scripts --omit=optional \
      --registry=https://registry.npmjs.org --no-audit --no-fund \
      "$oxlint_package" "$oxlint_binding_package"; then
      echo "::warning::oxlint verified package install failed - manifest will record missing output."
      oxlint_can_scan=false
    elif [ ! -x "$oxlint_bin" ]; then
      echo "::warning::oxlint binary missing after verified install - manifest will record missing output."
      oxlint_can_scan=false
    elif ! oxlint_version="$("$oxlint_bin" --version 2>/dev/null)"; then
      oxlint_version=""
      oxlint_can_scan=false
    else
      oxlint_detected_version="$(printf '%s\n' "$oxlint_version" | sed -nE 's/.*([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n 1)"
      if [ "$oxlint_detected_version" != "$OXLINT_VERSION" ]; then
        oxlint_can_scan=false
      fi
    fi
    if [ "$oxlint_can_scan" = false ]; then
      echo "::warning::oxlint version mismatch or unavailable: expected ${OXLINT_VERSION}, got '${oxlint_version:-unavailable}' - manifest will record missing output."
    fi
    if [ "$oxlint_can_scan" = true ]; then
      if ! "$oxlint_bin" \
        --config "$oxlint_config" \
        --disable-nested-config \
        --no-ignore \
        -A all -D correctness \
        --format sarif \
        --no-error-on-unmatched-pattern \
        -- \
        "${files[@]}" > "$raw"; then
        if [ ! -s "$raw" ]; then
          echo "::warning::oxlint scan failed and produced no SARIF output - manifest will record missing output."
        fi
      fi
    fi
  fi
  if [ -s "$raw" ]; then
    python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
      oxlint "$raw" "$out" --cap "$RESULT_CAP" --ensure-run \
      || echo "::warning::oxlint SARIF normalization failed - manifest will record missing output."
  fi
fi
