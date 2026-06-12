#!/usr/bin/env bash
set -euo pipefail

: "${GOLANGCI_LINT_VERSION:?}"
: "${GOLANGCI_LINT_LINUX_AMD64_SHA256:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/golangci-lint.raw.sarif"
out="$SARIF_DIR/golangci-lint.sarif"
archive="$RUNNER_TEMP/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64.tar.gz"
golangci_dir="$RUNNER_TEMP/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64"
golangci_bin="$golangci_dir/golangci-lint"
files_list=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/golangci-lint-files.XXXXXX")"

cleanup_golangci_lint() {
  rm -f "$files_list" "$archive"
  rm -rf "$golangci_dir"
}
trap cleanup_golangci_lint EXIT

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

discover_go_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name 'vendor' \
    -o -name '.terraform' \) -prune \) -o \
    \( -type f \( -name '*.go' -o -name 'go.mod' \) -print0 \)
}

cd "$SOURCE_DIR"
if ! discover_go_files > "$files_list"; then
  echo "::warning::golangci-lint file discovery failed - emitting empty golangci-lint SARIF run."
  emit_empty_sarif
else
  if ! grep -qz . "$files_list"; then
    echo "::notice::No Go files found - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif [ ! -f go.mod ]; then
    echo "::notice::No root go.mod found - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif [[ ! "$GOLANGCI_LINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::golangci-lint version must be a pinned x.y.z version - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif [[ ! "$GOLANGCI_LINT_LINUX_AMD64_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::warning::golangci-lint checksum must be a pinned SHA256 value - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif ! curl -fsSL -o "$archive" \
    "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64.tar.gz"; then
    echo "::warning::golangci-lint download failed - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif ! printf '%s  %s\n' "$GOLANGCI_LINT_LINUX_AMD64_SHA256" "$archive" | sha256sum -c --strict -; then
    echo "::warning::golangci-lint checksum mismatch - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif ! tar -xzf "$archive" -C "$RUNNER_TEMP"; then
    echo "::warning::golangci-lint extract failed - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif [ ! -x "$golangci_bin" ]; then
    echo "::warning::golangci-lint binary missing after extract - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif ! golangci_version="$("$golangci_bin" --version 2>/dev/null)"; then
    echo "::warning::golangci-lint version check failed - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  elif ! printf '%s\n' "$golangci_version" | grep -q "version ${GOLANGCI_LINT_VERSION}\\b"; then
    echo "::warning::golangci-lint installed version mismatch - emitting empty golangci-lint SARIF run."
    emit_empty_sarif
  else
    "$golangci_bin" run \
      --no-config \
      --default=standard \
      --timeout=5m \
      --issues-exit-code=0 \
      --output.sarif.path="$raw" \
      ./... || true
    if [ ! -s "$raw" ]; then
      echo "::warning::golangci-lint scan produced no SARIF output - emitting empty golangci-lint SARIF run."
      emit_empty_sarif
    fi
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
  golangci-lint "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
