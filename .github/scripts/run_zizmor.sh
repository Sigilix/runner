#!/usr/bin/env bash
set -euo pipefail

: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${ZIZMOR_VERSION:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/zizmor.raw.sarif"
out="$SARIF_DIR/zizmor.sarif"

mkdir -p "$SARIF_DIR"

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

cd "$SOURCE_DIR"
if [ ! -d .github/workflows ]; then
  emit_empty_sarif
elif ! python3 -m pip install --quiet "zizmor==${ZIZMOR_VERSION}"; then
  echo "::warning::zizmor install failed - manifest will record missing output."
else
  zizmor --format sarif . > "$raw" || true
  if [ ! -s "$raw" ]; then emit_empty_sarif; fi
fi

if [ -s "$raw" ]; then
  python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
    zizmor "$raw" "$out" --cap "$RESULT_CAP" --ensure-run \
    || echo "::warning::zizmor SARIF normalization failed - manifest will record missing output."
fi
