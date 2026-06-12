#!/usr/bin/env bash
set -euo pipefail

: "${HADOLINT_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/hadolint.raw.sarif"
out="$SARIF_DIR/hadolint.sarif"
files_list="$RUNNER_TEMP/hadolint-files"

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

cd "$SOURCE_DIR"
if ! curl -fsSL -o "$RUNNER_TEMP/hadolint" \
  "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64"; then
  echo "::warning::hadolint download failed - manifest will record missing output."
elif ! chmod +x "$RUNNER_TEMP/hadolint"; then
  echo "::warning::hadolint chmod failed - manifest will record missing output."
elif ! find . -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' \) \
  -not -path './.git/*' -not -path './node_modules/*' -print0 > "$files_list"; then
  echo "::warning::hadolint file discovery failed - manifest will record missing output."
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    emit_empty_sarif
  else
    "$RUNNER_TEMP/hadolint" --no-fail --format sarif "${files[@]}" > "$raw" || true
    if [ ! -s "$raw" ]; then emit_empty_sarif; fi
  fi
  python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
    hadolint "$raw" "$out" --cap "$RESULT_CAP" --ensure-run \
    || echo "::warning::hadolint SARIF normalization failed - manifest will record missing output."
fi
