#!/usr/bin/env bash
set -euo pipefail

: "${REGAL_LINUX_X86_64_SHA256:?}"
: "${REGAL_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/regal.raw.sarif"
out="$SARIF_DIR/regal.sarif"
regal_config="$RUNNER_DIR/.github/config/regal-sigilix.yaml"
regal_bin="$RUNNER_TEMP/regal"
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/regal-files.XXXXXX")"

cleanup_regal() {
  rm -f "$files_list" "$regal_bin"
}
trap cleanup_regal EXIT

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

discover_rego_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name 'vendor' -o -name '.terraform' \) -prune \) -o \
    \( -type f -name '*.rego' -print0 \)
}

cd "$SOURCE_DIR"
if [ ! -f "$regal_config" ]; then
  echo "::warning::Regal Sigilix config missing at $regal_config - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! discover_rego_files > "$files_list"; then
  echo "::warning::Regal file discovery failed - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! grep -qz . "$files_list"; then
  echo "::notice::No Rego files found - emitting empty Regal SARIF run."
  emit_empty_sarif
elif [[ ! "$REGAL_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::Regal version must be a pinned x.y.z version - emitting empty Regal SARIF run."
  emit_empty_sarif
elif [[ ! "$REGAL_LINUX_X86_64_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::warning::Regal checksum must be a pinned SHA256 value - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! curl -fsSL -o "$regal_bin" \
  "https://github.com/open-policy-agent/regal/releases/download/v${REGAL_VERSION}/regal_Linux_x86_64"; then
  echo "::warning::Regal download failed - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! printf '%s  %s\n' "$REGAL_LINUX_X86_64_SHA256" "$regal_bin" | sha256sum -c --strict -; then
  echo "::warning::Regal checksum mismatch - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! chmod +x "$regal_bin"; then
  echo "::warning::Regal chmod failed - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! regal_version="$("$regal_bin" version 2>/dev/null)"; then
  echo "::warning::Regal version check failed - emitting empty Regal SARIF run."
  emit_empty_sarif
elif ! printf '%s\n' "$regal_version" | grep -q "^Version:[[:space:]]*${REGAL_VERSION}$"; then
  echo "::warning::Regal installed version mismatch - emitting empty Regal SARIF run."
  emit_empty_sarif
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  "$regal_bin" lint \
    --config-file "$regal_config" \
    --disable-category idiomatic \
    --disable-category style \
    --disable-category performance \
    --disable-category testing \
    --disable-category custom \
    --format sarif \
    --output-file "$raw" \
    -- \
    "${files[@]}" || true
  if [ ! -s "$raw" ]; then
    echo "::warning::Regal scan produced no SARIF output - emitting empty Regal SARIF run."
    emit_empty_sarif
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
  regal "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
