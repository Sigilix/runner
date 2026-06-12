#!/usr/bin/env bash
set -euo pipefail

: "${ESLINT_MODE:=safe}"
: "${ESLINT_PLUGIN_SECURITY_VERSION:?}"
: "${ESLINT_PLUGIN_UNICORN_VERSION:?}"
: "${ESLINT_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${TYPESCRIPT_ESLINT_VERSION:?}"
: "${TYPESCRIPT_VERSION:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

json="$SARIF_DIR/eslint.json"
out="$SARIF_DIR/eslint.sarif"
eslint_config="$RUNNER_DIR/.github/config/eslint-sigilix.config.mjs"
eslint_install_dir="$RUNNER_TEMP/eslint-${ESLINT_VERSION}"
runtime_eslint_config="$eslint_install_dir/eslint-sigilix.config.mjs"
eslint_bin="$eslint_install_dir/node_modules/.bin/eslint"
sigilix_tsconfig="$SOURCE_DIR/.sigilix-eslint-tsconfig.json"
files_list=""
eslint_version=""

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
files_list="$(mktemp "$RUNNER_TEMP/eslint-files.XXXXXX")"

cleanup_eslint() {
  rm -f "$sigilix_tsconfig"
  if [ -n "$files_list" ]; then rm -f "$files_list"; fi
}
trap cleanup_eslint EXIT

emit_empty_json() {
  printf '[]' > "$json"
}

discover_files() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name '.venv' \
    -o -name 'vendor' -o -name '__pycache__' -o -name '.tox' -o -name '.mypy_cache' \
    -o -name '.pytest_cache' -o -name '.terraform' \) -prune \) -o \
    \( -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' \
    -o -name '*.ts' -o -name '*.tsx' -o -name '*.mts' -o -name '*.cts' \) -print0 \)
}

has_typescript_file() {
  local file
  for file in "$@"; do
    case "$file" in
      *.ts|*.tsx|*.mts|*.cts) return 0 ;;
    esac
  done
  return 1
}

has_tsconfig() {
  local found
  found="$(find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name '.venv' \
    -o -name 'vendor' -o -name '__pycache__' -o -name '.tox' -o -name '.mypy_cache' \
    -o -name '.pytest_cache' -o -name '.terraform' \) -prune \) -o \
    \( -type f \( -name 'tsconfig.json' -o -name 'tsconfig.*.json' \) -print -quit \))"
  [ -n "$found" ]
}

write_sigilix_tsconfig() {
  cat > "$sigilix_tsconfig" <<'JSON'
{
  "compilerOptions": {
    "allowJs": false,
    "checkJs": false,
    "jsx": "preserve",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "noEmit": true,
    "skipLibCheck": true,
    "strict": false,
    "target": "ES2022",
    "types": []
  },
  "include": ["**/*.ts", "**/*.tsx", "**/*.mts", "**/*.cts"],
  "exclude": [
    ".git",
    ".next",
    ".pytest_cache",
    ".terraform",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "vendor"
  ]
}
JSON
}

run_repo_config_eslint() {
  local eslint_can_scan=true

  echo "::warning::ESLint repo-config mode executes caller repository ESLint config and plugins in the no-OIDC scan job."
  if [[ ! "$ESLINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::ESLint version must be a pinned x.y.z version - emitting empty ESLint SARIF run."
    emit_empty_json
    return
  fi

  mkdir -p "$eslint_install_dir"
  if ! npm install --silent --prefix "$eslint_install_dir" --ignore-scripts --omit=optional \
    --registry=https://registry.npmjs.org --no-audit --no-fund \
    "eslint@${ESLINT_VERSION}" >/dev/null; then
    echo "::warning::ESLint repo-config package install failed - emitting empty ESLint SARIF run."
    eslint_can_scan=false
  elif [ ! -x "$eslint_bin" ]; then
    echo "::warning::ESLint binary missing after repo-config install - emitting empty ESLint SARIF run."
    eslint_can_scan=false
  elif ! eslint_version="$("$eslint_bin" --version 2>/dev/null)"; then
    eslint_can_scan=false
  else
    eslint_version="${eslint_version#v}"
    if [ "$eslint_version" != "$ESLINT_VERSION" ]; then
      eslint_can_scan=false
    fi
  fi

  if [ "$eslint_can_scan" = false ]; then
    echo "::warning::ESLint repo-config version mismatch or unavailable: expected ${ESLINT_VERSION}, got '${eslint_version:-unavailable}' - emitting empty ESLint SARIF run."
    emit_empty_json
    return
  fi

  if ! "$eslint_bin" --format json --no-warn-ignored -- "$@" > "$json"; then
    if [ ! -s "$json" ]; then
      echo "::warning::ESLint repo-config scan failed and produced no JSON output - emitting empty ESLint SARIF run."
      emit_empty_json
    fi
  fi
}

run_sigilix_eslint() {
  local eslint_can_scan=true

  if [[ ! "$ESLINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] \
    || [[ ! "$TYPESCRIPT_ESLINT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] \
    || [[ ! "$TYPESCRIPT_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] \
    || [[ ! "$ESLINT_PLUGIN_SECURITY_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] \
    || [[ ! "$ESLINT_PLUGIN_UNICORN_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
    echo "::warning::ESLint package versions must be pinned x.y.z versions - emitting empty ESLint SARIF run."
    emit_empty_json
    return
  fi

  if [ ! -f "$eslint_config" ]; then
    echo "::warning::ESLint Sigilix config missing at $eslint_config - emitting empty ESLint SARIF run."
    emit_empty_json
    return
  fi

  mkdir -p "$eslint_install_dir"
  if ! npm install --silent --prefix "$eslint_install_dir" --ignore-scripts --omit=optional \
    --registry=https://registry.npmjs.org --no-audit --no-fund \
    "eslint@${ESLINT_VERSION}" \
    "typescript-eslint@${TYPESCRIPT_ESLINT_VERSION}" \
    "typescript@${TYPESCRIPT_VERSION}" \
    "eslint-plugin-security@${ESLINT_PLUGIN_SECURITY_VERSION}" \
    "eslint-plugin-unicorn@${ESLINT_PLUGIN_UNICORN_VERSION}" >/dev/null; then
    echo "::warning::ESLint package install failed - emitting empty ESLint SARIF run."
    eslint_can_scan=false
  elif ! cp -f "$eslint_config" "$runtime_eslint_config"; then
    echo "::warning::ESLint Sigilix config copy failed - emitting empty ESLint SARIF run."
    eslint_can_scan=false
  elif [ ! -x "$eslint_bin" ]; then
    echo "::warning::ESLint binary missing after install - emitting empty ESLint SARIF run."
    eslint_can_scan=false
  elif ! eslint_version="$("$eslint_bin" --version 2>/dev/null)"; then
    eslint_can_scan=false
  else
    eslint_version="${eslint_version#v}"
    if [ "$eslint_version" != "$ESLINT_VERSION" ]; then
      eslint_can_scan=false
    fi
  fi

  if [ "$eslint_can_scan" = false ]; then
    echo "::warning::ESLint version mismatch or unavailable: expected ${ESLINT_VERSION}, got '${eslint_version:-unavailable}' - emitting empty ESLint SARIF run."
    emit_empty_json
    return
  fi

  if has_typescript_file "$@" && has_tsconfig; then
    write_sigilix_tsconfig
    export SIGILIX_ESLINT_TSCONFIG="$sigilix_tsconfig"
  else
    export SIGILIX_ESLINT_TSCONFIG=""
  fi

  if ! "$eslint_bin" --format json --no-config-lookup --config "$runtime_eslint_config" --no-warn-ignored -- "$@" > "$json"; then
    if [ ! -s "$json" ]; then
      echo "::warning::ESLint scan failed and produced no JSON output - emitting empty ESLint SARIF run."
      emit_empty_json
    fi
  fi
}

cd "$SOURCE_DIR"
if ! discover_files > "$files_list"; then
  echo "::warning::ESLint file discovery failed - emitting empty ESLint SARIF run."
  emit_empty_json
else
  files=()
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < "$files_list"
  if [ "${#files[@]}" -eq 0 ]; then
    emit_empty_json
  else
    case "$ESLINT_MODE" in
      safe)
        run_sigilix_eslint "${files[@]}"
        ;;
      repo-config)
        run_repo_config_eslint "${files[@]}"
        ;;
      *)
        echo "::warning::unknown eslint-mode '$ESLINT_MODE'; falling back to safe."
        run_sigilix_eslint "${files[@]}"
        ;;
    esac
  fi
fi

python3 "$RUNNER_DIR/.github/scripts/eslint_to_sarif.py" "$json" "$out" \
  --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
