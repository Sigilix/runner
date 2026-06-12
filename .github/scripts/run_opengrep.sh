#!/usr/bin/env bash
set -euo pipefail

: "${OPENGREP_MANYLINUX_AARCH64_SHA256:?}"
: "${OPENGREP_MANYLINUX_X86_SHA256:?}"
: "${OPENGREP_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${OPENGREP_CONFIG:=p/security-audit,p/owasp-top-ten}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/opengrep.raw.sarif"
out="$SARIF_DIR/opengrep.sarif"
opengrep_bin="$RUNNER_TEMP/opengrep"
asset=""
checksum=""
config_args=()

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"

cleanup_opengrep() {
  rm -f "$opengrep_bin"
}
trap cleanup_opengrep EXIT

parse_opengrep_configs() {
  local item
  local trimmed
  IFS=',' read -r -a config_items <<< "$OPENGREP_CONFIG"
  for item in "${config_items[@]}"; do
    trimmed="${item#"${item%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [ -z "$trimmed" ]; then
      echo "::warning::OpenGrep config contains an empty ruleset - manifest will record missing output."
      return 1
    fi
    if [[ "$trimmed" == -* ]]; then
      echo "::warning::OpenGrep config '$trimmed' must not start with '-' - manifest will record missing output."
      return 1
    fi
    if [[ ! "$trimmed" =~ ^[A-Za-z0-9._/@-]+$ ]]; then
      echo "::warning::OpenGrep config '$trimmed' contains unsupported characters - manifest will record missing output."
      return 1
    fi
    config_args+=(--config "$trimmed")
  done
  if [ "${#config_args[@]}" -eq 0 ]; then
    echo "::warning::OpenGrep config is empty - manifest will record missing output."
    return 1
  fi
}

case "$(uname -m)" in
  x86_64|amd64)
    asset="opengrep_manylinux_x86"
    checksum="$OPENGREP_MANYLINUX_X86_SHA256"
    ;;
  aarch64|arm64)
    asset="opengrep_manylinux_aarch64"
    checksum="$OPENGREP_MANYLINUX_AARCH64_SHA256"
    ;;
  *)
    echo "::warning::OpenGrep unsupported runner architecture $(uname -m) - manifest will record missing output."
    ;;
esac

cd "$SOURCE_DIR"
if [ -z "$asset" ]; then
  :
elif [[ ! "$OPENGREP_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::OpenGrep version must be a pinned x.y.z version - manifest will record missing output."
elif [[ ! "$checksum" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::warning::OpenGrep checksum must be a pinned SHA256 value - manifest will record missing output."
elif ! parse_opengrep_configs; then
  :
elif ! curl -fsSL -o "$opengrep_bin" \
  "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}"; then
  echo "::warning::OpenGrep download failed - manifest will record missing output."
elif ! printf '%s  %s\n' "$checksum" "$opengrep_bin" | sha256sum -c --strict -; then
  echo "::warning::OpenGrep checksum mismatch - manifest will record missing output."
elif ! chmod +x "$opengrep_bin"; then
  echo "::warning::OpenGrep chmod failed - manifest will record missing output."
elif ! opengrep_version="$("$opengrep_bin" --version 2>/dev/null)"; then
  echo "::warning::OpenGrep version check failed - manifest will record missing output."
elif ! printf '%s\n' "$opengrep_version" | grep -Eq "(^|[^0-9.])${OPENGREP_VERSION}([^0-9.]|$)"; then
  echo "::warning::OpenGrep installed version mismatch - manifest will record missing output."
else
  "$opengrep_bin" scan \
    "${config_args[@]}" \
    --exclude=node_modules \
    --exclude=dist \
    --exclude=build \
    --exclude=coverage \
    --exclude=.next \
    --exclude=out \
    --exclude=.venv \
    --exclude=vendor \
    --exclude=.tox \
    --exclude=.terraform \
    --sarif-output="$raw" \
    . || true
  if [ ! -s "$raw" ]; then
    echo "::warning::OpenGrep scan produced no SARIF output - manifest will record missing output."
  fi
fi

if [ -s "$raw" ]; then
  python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
    opengrep "$raw" "$out" --cap "$RESULT_CAP" --ensure-run \
    || echo "::warning::OpenGrep SARIF normalization failed - manifest will record missing output."
fi
