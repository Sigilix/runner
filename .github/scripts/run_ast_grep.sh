#!/usr/bin/env bash
set -euo pipefail

: "${AST_GREP_LINUX_X64_GNU_INTEGRITY:?}"
: "${AST_GREP_NPM_INTEGRITY:?}"
: "${AST_GREP_VERSION:?}"
: "${DETECT_LIBC_NPM_INTEGRITY:?}"
: "${DETECT_LIBC_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"

raw="$SARIF_DIR/ast-grep.raw.sarif"
out="$SARIF_DIR/ast-grep.sarif"
ast_grep_config="$RUNNER_DIR/.github/config/ast-grep-sigilix/sgconfig.yml"
ast_grep_pack_dir="$RUNNER_TEMP/ast-grep-pack"
ast_grep_install_dir="$RUNNER_TEMP/ast-grep-${AST_GREP_VERSION}"
ast_grep_package="$ast_grep_pack_dir/ast-grep-cli-${AST_GREP_VERSION}.tgz"
ast_grep_binding_package="$ast_grep_pack_dir/ast-grep-cli-linux-x64-gnu-${AST_GREP_VERSION}.tgz"
detect_libc_package="$ast_grep_pack_dir/detect-libc-${DETECT_LIBC_VERSION}.tgz"
ast_grep_bin="$ast_grep_install_dir/node_modules/.bin/ast-grep"
ast_grep_version=""
ast_grep_can_scan=true

mkdir -p "$SARIF_DIR"

sri_sha512() {
  python3 - "$1" <<'PY'
import base64
import hashlib
import sys

with open(sys.argv[1], "rb") as handle:
    print("sha512-" + base64.b64encode(hashlib.sha512(handle.read()).digest()).decode("ascii"), end="")
PY
}

tarball_size() {
  if [ ! -r "$1" ]; then
    printf '0'
    return
  fi
  wc -c < "$1" | tr -d '[:space:]'
}

emit_empty_raw() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

if [[ ! "$AST_GREP_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || [[ ! "$DETECT_LIBC_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::ast-grep version inputs must be pinned x.y.z versions - emitting empty ast-grep SARIF run."
  emit_empty_raw
elif [ ! -f "$ast_grep_config" ]; then
  echo "::warning::ast-grep Sigilix config missing at $ast_grep_config - emitting empty ast-grep SARIF run."
  emit_empty_raw
else
  mkdir -p "$ast_grep_pack_dir" "$ast_grep_install_dir"
  if ! npm pack --silent --pack-destination "$ast_grep_pack_dir" \
    --registry=https://registry.npmjs.org \
    "@ast-grep/cli@${AST_GREP_VERSION}" \
    "@ast-grep/cli-linux-x64-gnu@${AST_GREP_VERSION}" \
    "detect-libc@${DETECT_LIBC_VERSION}" >/dev/null; then
    echo "::warning::ast-grep package download failed - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif [ ! -s "$ast_grep_package" ] || [ ! -s "$ast_grep_binding_package" ] || [ ! -s "$detect_libc_package" ]; then
    echo "::warning::ast-grep package tarball missing after download - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif [ "$(tarball_size "$ast_grep_package")" -le 1024 ] \
    || [ "$(tarball_size "$ast_grep_binding_package")" -le 1024 ] \
    || [ "$(tarball_size "$detect_libc_package")" -le 1024 ]; then
    echo "::warning::ast-grep package tarball at or below 1024 bytes after download - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif [ "$(sri_sha512 "$ast_grep_package")" != "$AST_GREP_NPM_INTEGRITY" ]; then
    echo "::warning::ast-grep package integrity mismatch - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif [ "$(sri_sha512 "$ast_grep_binding_package")" != "$AST_GREP_LINUX_X64_GNU_INTEGRITY" ]; then
    echo "::warning::ast-grep linux binding integrity mismatch - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif [ "$(sri_sha512 "$detect_libc_package")" != "$DETECT_LIBC_NPM_INTEGRITY" ]; then
    echo "::warning::detect-libc package integrity mismatch - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif ! npm install --silent --prefix "$ast_grep_install_dir" --ignore-scripts --omit=optional \
    --registry=https://registry.npmjs.org --no-audit --no-fund \
    "$detect_libc_package" "$ast_grep_package" "$ast_grep_binding_package"; then
    echo "::warning::ast-grep verified package install failed - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif [ ! -x "$ast_grep_bin" ]; then
    echo "::warning::ast-grep binary missing after verified install - emitting empty ast-grep SARIF run."
    ast_grep_can_scan=false
  elif ! ast_grep_version="$("$ast_grep_bin" --version 2>/dev/null)"; then
    ast_grep_can_scan=false
  else
    ast_grep_detected_version="$(printf '%s\n' "$ast_grep_version" | sed -nE 's/^ast-grep[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' | head -n 1)"
    if [ "$ast_grep_detected_version" != "$AST_GREP_VERSION" ]; then
      ast_grep_can_scan=false
    fi
  fi
  if [ "$ast_grep_can_scan" = false ]; then
    echo "::warning::ast-grep version mismatch or unavailable: expected ${AST_GREP_VERSION}, got '${ast_grep_version:-unavailable}' - emitting empty ast-grep SARIF run."
    emit_empty_raw
  # ast-grep exits 1 for error-level findings; keep non-empty SARIF in that case.
  # Caller ignore files can hide review-relevant source; generated/vendor globs below are the exclusion contract.
  elif "$ast_grep_bin" scan \
      --config "$ast_grep_config" \
      --format sarif \
      --no-ignore hidden --no-ignore vcs --no-ignore parent --no-ignore exclude --no-ignore global --no-ignore dot \
      --globs '*.js' --globs '*.jsx' --globs '*.mjs' --globs '*.cjs' \
      --globs '*.ts' --globs '*.tsx' --globs '*.mts' --globs '*.cts' \
      --globs '!**/.git/**' --globs '!**/node_modules/**' --globs '!**/dist/**' \
      --globs '!**/build/**' --globs '!**/coverage/**' --globs '!**/.next/**' \
      --globs '!**/out/**' --globs '!**/.venv/**' --globs '!**/vendor/**' \
      --globs '!**/__pycache__/**' --globs '!**/.tox/**' --globs '!**/.mypy_cache/**' \
      --globs '!**/.pytest_cache/**' --globs '!**/.terraform/**' \
      . > "$raw"; then
    :
  elif [ -s "$raw" ]; then
    :
  else
    echo "::warning::ast-grep scan failed and produced no SARIF output - emitting empty ast-grep SARIF run."
  fi
fi

if [ ! -s "$raw" ]; then emit_empty_raw; fi
python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
  ast-grep "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
