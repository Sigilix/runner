#!/usr/bin/env bash
set -euo pipefail

: "${KNIP_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

json="$SARIF_DIR/knip.json"
out="$SARIF_DIR/knip.sarif"
knip_config="$RUNNER_DIR/.github/config/knip-sigilix.json"
knip_install_dir="$RUNNER_TEMP/knip-${KNIP_VERSION}-$$"
knip_bin="$knip_install_dir/node_modules/.bin/knip"
knip_version=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"

emit_empty_json() {
  printf '{"issues":[]}' > "$json"
}

cd "$SOURCE_DIR"
if [ ! -f package.json ]; then
  emit_empty_json
elif [[ ! "$KNIP_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::Knip version must be a pinned x.y.z version - emitting empty Knip SARIF run."
  emit_empty_json
elif [ ! -f "$knip_config" ]; then
  echo "::warning::Knip Sigilix config missing at $knip_config - emitting empty Knip SARIF run."
  emit_empty_json
else
  knip_can_scan=true
  mkdir -p "$knip_install_dir"
  if ! (
    cd "$RUNNER_TEMP"
    npm install --silent --prefix "$knip_install_dir" --ignore-scripts \
      --registry=https://registry.npmjs.org --no-audit --no-fund \
      "knip@${KNIP_VERSION}" >/dev/null
  ); then
    echo "::warning::Knip package install failed - emitting empty Knip SARIF run."
    knip_can_scan=false
  elif [ ! -x "$knip_bin" ]; then
    echo "::warning::Knip binary missing after install - emitting empty Knip SARIF run."
    knip_can_scan=false
  elif ! knip_version="$("$knip_bin" --version 2>/dev/null)"; then
    echo "::warning::Knip version check failed - emitting empty Knip SARIF run."
    knip_can_scan=false
  elif [ "$knip_version" != "$KNIP_VERSION" ]; then
    echo "::warning::Knip installed version mismatch - emitting empty Knip SARIF run."
    knip_can_scan=false
  fi

  if [ "$knip_can_scan" = false ]; then
    emit_empty_json
  elif ! "$knip_bin" \
    --config "$knip_config" \
    --include unresolved,unlisted,binaries \
    --reporter json \
    --no-exit-code \
    --no-progress \
    --no-config-hints \
    --no-tag-hints \
    --no-gitignore > "$json"; then
    echo "::warning::Knip scan failed - emitting empty Knip SARIF run."
    emit_empty_json
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/knip_to_sarif.py" "$json" "$out" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
