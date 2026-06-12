#!/usr/bin/env bash
set -euo pipefail

: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${TFLINT_LINUX_AMD64_SHA256:?}"
: "${TFLINT_VERSION:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/tflint.raw.sarif"
out="$SARIF_DIR/tflint.sarif"
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/tflint-files.XXXXXX")"

cleanup_tflint() {
  rm -f "$files_list" "$RUNNER_TEMP/tflint.zip" "$RUNNER_TEMP/tflint"
}
trap cleanup_tflint EXIT

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

discover_terraform_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name '.terraform' \) -prune \) -o \
    \( -type f -name '*.tf' -print0 \)
}

cd "$SOURCE_DIR"
if ! discover_terraform_files > "$files_list"; then
  echo "::warning::TFLint file discovery failed - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif ! grep -qz . "$files_list"; then
  echo "::notice::No Terraform files found - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif [[ ! "$TFLINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::TFLint version must be a pinned x.y.z version - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif [[ ! "$TFLINT_LINUX_AMD64_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::warning::TFLint checksum must be a pinned SHA256 value - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif ! curl -fsSL -o "$RUNNER_TEMP/tflint.zip" \
  "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_amd64.zip"; then
  echo "::warning::TFLint download failed - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif ! printf '%s  %s\n' "$TFLINT_LINUX_AMD64_SHA256" "$RUNNER_TEMP/tflint.zip" | sha256sum -c --strict -; then
  echo "::warning::TFLint checksum mismatch - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif ! unzip -q -o "$RUNNER_TEMP/tflint.zip" -d "$RUNNER_TEMP"; then
  echo "::warning::TFLint unzip failed - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif [ ! -x "$RUNNER_TEMP/tflint" ]; then
  echo "::warning::TFLint binary missing or not executable after extract - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif ! tflint_version="$("$RUNNER_TEMP/tflint" --version 2>/dev/null)"; then
  echo "::warning::TFLint version check failed - emitting empty TFLint SARIF run."
  emit_empty_sarif
elif ! printf '%s\n' "$tflint_version" | grep -q "^TFLint version ${TFLINT_VERSION}\\b"; then
  echo "::warning::TFLint installed version mismatch - emitting empty TFLint SARIF run."
  emit_empty_sarif
else
  "$RUNNER_TEMP/tflint" --recursive --format sarif > "$raw" || true
  if [ ! -s "$raw" ]; then
    echo "::warning::TFLint scan produced no SARIF output - emitting empty TFLint SARIF run."
    emit_empty_sarif
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
  tflint "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
