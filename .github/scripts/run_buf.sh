#!/usr/bin/env bash
set -euo pipefail

: "${BUF_LINUX_X86_64_SHA256:?}"
: "${BUF_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

json="$SARIF_DIR/buf.jsonl"
raw="$SARIF_DIR/buf.raw.sarif"
out="$SARIF_DIR/buf.sarif"
buf_bin="$RUNNER_TEMP/buf-${BUF_VERSION}"
files_list=""
buf_config=""
buf_config_dir=""
buf_path_args=()

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/buf-files.XXXXXX")"

cleanup_buf() {
  rm -f "$files_list" "$buf_bin" "$json" "$raw" 2>/dev/null || true
  if [ -n "$buf_config_dir" ]; then rm -rf "$buf_config_dir" 2>/dev/null || true; fi
}
trap cleanup_buf EXIT

emit_empty_json() {
  : > "$json"
}

discover_proto_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name 'vendor' \
    -o -name '.terraform' \) -prune \) -o \
    \( -type f -name '*.proto' -print0 \)
}

write_default_buf_config() {
  buf_config_dir="$(mktemp -d "$RUNNER_TEMP/buf-config.XXXXXX")"
  buf_config="$buf_config_dir/buf.yaml"
  cat > "$buf_config" <<'EOF'
version: v2
lint:
  use:
    - MINIMAL
EOF
}

install_buf() {
  if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo "::error::Buf unsupported runner platform: expected Linux x86_64."
    return 64
  fi
  if [[ ! "$BUF_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::error::Buf version must be a pinned x.y.z version."
    return 64
  fi
  if [[ ! "$BUF_LINUX_X86_64_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::Buf checksum must be a pinned SHA256 value."
    return 64
  fi
  if ! curl -fsSL -o "$buf_bin" \
    "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-x86_64"; then
    echo "::error::Buf download failed."
    return 64
  fi
  if ! printf '%s  %s\n' "$BUF_LINUX_X86_64_SHA256" "$buf_bin" | sha256sum -c --strict -; then
    echo "::error::Buf checksum mismatch."
    return 64
  fi
  chmod +x "$buf_bin"
  if ! detected_version="$("$buf_bin" --version 2>/dev/null)"; then
    echo "::error::Buf version check failed."
    return 64
  fi
  if [ "$detected_version" != "$BUF_VERSION" ]; then
    echo "::error::Buf installed version mismatch: expected ${BUF_VERSION}, got '${detected_version:-unavailable}'."
    return 64
  fi
}

cd "$SOURCE_DIR"
if ! discover_proto_files > "$files_list"; then
  echo "::error::Buf file discovery failed."
  exit 64
elif ! grep -qz . "$files_list"; then
  echo "::notice::No Protobuf files found - emitting empty Buf SARIF run."
  emit_empty_json
else
  echo "::notice::Using runner-owned Buf v2 MINIMAL config."
  write_default_buf_config
  while IFS= read -r -d '' file; do
    buf_path_args+=(--path "$file")
  done < "$files_list"

  install_buf
  set +e
  "$buf_bin" lint --config "$buf_config" --error-format=json "${buf_path_args[@]}" > "$json"
  buf_status=$?
  set -e
  if [ "$buf_status" -ne 0 ] && [ "$buf_status" -ne 100 ]; then
    echo "::error::Buf lint failed with exit code ${buf_status}."
    exit 64
  fi
  if [ "$buf_status" -eq 100 ] && [ ! -s "$json" ]; then
    echo "::warning::Buf exited with lint findings but produced no JSON output - emitting empty Buf SARIF run."
    emit_empty_json
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/buf_to_sarif.py" "$json" "$raw" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
  buf "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
