#!/usr/bin/env bash
set -euo pipefail

: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"
: "${DETEKT_CLI_ALL_JAR_SHA256:?}"
: "${DETEKT_VERSION:?}"
: "${PHPCS_VERSION:?}"
: "${PHPMD_VERSION:?}"
: "${PHPSTAN_VERSION:?}"
: "${PRISMA_LINT_NPM_INTEGRITY:?}"
: "${PRISMA_LINT_VERSION:?}"
: "${RUBOCOP_VERSION:?}"
: "${SQLFLUFF_VERSION:?}"
: "${SWIFTLINT_LINUX_AMD64_SHA256:?}"
: "${SWIFTLINT_VERSION:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP"
high_impact_temp="$(mktemp -d "$RUNNER_TEMP/high-impact.XXXXXX")"
trap 'rm -rf "$high_impact_temp" 2>/dev/null || true' EXIT

validate_bool() {
  local name="$1" value="${2:-false}"
  if [ "$value" != "true" ] && [ "$value" != "false" ]; then
    echo "::error::Invalid boolean value for $name."
    exit 64
  fi
}

run_enabled_tool() {
  local tool="$1" value="$2" function_name="$3" status
  [ "$value" = "true" ] || return 0
  set +e
  (set -euo pipefail; "$function_name")
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    echo "::warning::$tool wrapper failed with exit code $status - emitting empty $tool SARIF run."
    empty_tool "$tool" || true
  fi
}

empty_tool() {
  local tool="$1" raw="$SARIF_DIR/$1.raw.sarif" out="$SARIF_DIR/$1.sarif"
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
  python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
    "$tool" "$raw" "$out" --cap "$RESULT_CAP" --ensure-run
}

convert_tool() {
  local tool="$1" input="$2" out="$SARIF_DIR/$1.sarif"
  python3 "$RUNNER_DIR/.github/scripts/high_impact_to_sarif.py" \
    "$tool" "$input" "$out" --base-dir "$SOURCE_DIR" --cap "$RESULT_CAP"
}

collect_files() {
  local output="$1"
  shift
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name 'vendor' \
    -o -name '.terraform' -o -name 'target' \) -prune \) -o \
    \( -type f \( "$@" \) -print0 \) > "$output"
}

has_files() {
  grep -qz . "$1"
}

find_sqlfluff_config() {
  local config="$high_impact_temp/sqlfluff.cfg"
  cat > "$config" <<'EOF'
[sqlfluff]
dialect = ansi
templater = raw
EOF
  printf '%s\n' "$config"
}

find_prisma_lint_config() {
  local config
  for config in .prismalintrc.json .prismalintrc.yaml .prismalintrc.yml; do
    [ -f "$config" ] && printf '%s\n' "$config" && return
  done
  return 1
}

find_phpstan_config() {
  local config="$high_impact_temp/phpstan.neon"
  cat > "$config" <<'EOF'
parameters:
    level: 5
    paths:
        - .
EOF
  printf '%s\n' "$config"
}

find_phpcs_config() {
  local config
  for config in phpcs.xml phpcs.xml.dist; do
    [ -f "$config" ] || continue
    printf '%s\n' "$config"
    return
  done
  return 1
}

find_rubocop_files() {
  collect_files "$1" \
    -name '*.rb' -o -name '*.rake' -o -name '*.gemspec' -o -name '*.ru' \
    -o -name 'Gemfile' -o -name 'Rakefile' -o -name 'Capfile' -o -name 'Fastfile' \
    -o -name 'Podfile' -o -name 'Vagrantfile'
}

ensure_php_tools() {
  local name="$1" package="$2"
  if ! command -v php >/dev/null 2>&1 || ! command -v composer >/dev/null 2>&1; then
    echo "::warning::PHP or Composer unavailable - emitting empty PHP tool SARIF runs."
    return 1
  fi
  php_tools_dir="$high_impact_temp/php-${name}-tools"
  [ -x "$php_tools_dir/vendor/bin/$name" ] && return 0
  mkdir -p "$php_tools_dir"
  COMPOSER_HOME="$high_impact_temp/composer-home" composer --working-dir "$php_tools_dir" \
    config repositories.packagist composer https://repo.packagist.org >/dev/null
  COMPOSER_HOME="$high_impact_temp/composer-home" composer --working-dir "$php_tools_dir" \
    --no-interaction --no-progress --no-plugins --no-scripts --quiet require \
    "$package"
}

run_sqlfluff() {
  local files_list="$high_impact_temp/sql-files" json="$high_impact_temp/sqlfluff.json" config venv py
  collect_files "$files_list" -name '*.sql' || { echo "::warning::SQLFluff file discovery failed."; empty_tool sqlfluff; return; }
  if ! has_files "$files_list"; then echo "::notice::No SQL files found - emitting empty SQLFluff SARIF run."; empty_tool sqlfluff; return; fi
  config="$(find_sqlfluff_config || true)"
  if [ -z "$config" ]; then echo "::warning::Unable to create SQLFluff config - emitting empty SQLFluff SARIF run."; empty_tool sqlfluff; return; fi
  venv="$high_impact_temp/sqlfluff-${SQLFLUFF_VERSION}"
  py="$venv/bin/python"
  if ! python3 -m venv "$venv" \
    || ! "$py" -m pip install --quiet --disable-pip-version-check --index-url https://pypi.org/simple/ "sqlfluff==${SQLFLUFF_VERSION}"; then
    echo "::warning::SQLFluff install failed - emitting empty SQLFluff SARIF run."; empty_tool sqlfluff; return
  fi
  mapfile -d '' files < "$files_list"
  # Ignored codes match CodeRabbit's SQLFluff tool docs as of 2026-06-12.
  "$py" -m sqlfluff lint --format json --nofail --config "$config" \
    --exclude-rules LT01,LT02,CP01,CP02,CP03,CV06,RF02,RF06,LXR,PRS,TMP \
    "${files[@]}" > "$json" || printf '[]' > "$json"
  convert_tool sqlfluff "$json"
}

run_prisma_lint() {
  local files_list="$high_impact_temp/prisma-files" json="$high_impact_temp/prisma-lint.json" config install_dir package package_name bin
  collect_files "$files_list" -name '*.prisma' || { echo "::warning::Prisma Lint file discovery failed."; empty_tool prisma-lint; return; }
  if ! has_files "$files_list"; then echo "::notice::No Prisma files found - emitting empty Prisma Lint SARIF run."; empty_tool prisma-lint; return; fi
  config="$(find_prisma_lint_config || true)"
  if [ -z "$config" ]; then
    if [ -f .prismalintrc.js ] || [ -f prismalint.config.js ]; then
      echo "::notice::Prisma Lint JS configs are ignored by Sigilix runner - emitting empty Prisma Lint SARIF run."
    else
      echo "::notice::No Prisma Lint config found - emitting empty Prisma Lint SARIF run."
    fi
    empty_tool prisma-lint
    return
  fi
  install_dir="$high_impact_temp/prisma-lint-${PRISMA_LINT_VERSION}"
  mkdir -p "$install_dir"
  if ! pack_json="$(npm pack --json --silent --pack-destination "$install_dir" --registry=https://registry.npmjs.org "prisma-lint@${PRISMA_LINT_VERSION}")"; then
    echo "::warning::Prisma Lint package download failed - emitting empty Prisma Lint SARIF run."; empty_tool prisma-lint; return
  fi
  if ! package_name="$(PACK_JSON="$pack_json" python3 -c 'import json,os; print(json.loads(os.environ["PACK_JSON"])[0]["filename"])')"; then
    echo "::warning::Prisma Lint package metadata invalid - emitting empty Prisma Lint SARIF run."; empty_tool prisma-lint; return
  fi
  package="$install_dir/${package_name##*/}"
  actual="sha512-$(openssl dgst -sha512 -binary "$package" | openssl base64 -A)"
  if [ "$actual" != "$PRISMA_LINT_NPM_INTEGRITY" ]; then
    echo "::warning::Prisma Lint package integrity mismatch - emitting empty Prisma Lint SARIF run."; empty_tool prisma-lint; return
  fi
  if ! npm install --silent --prefix "$install_dir" --ignore-scripts --registry=https://registry.npmjs.org --no-audit --no-fund "$package" >/dev/null; then
    echo "::warning::Prisma Lint install failed - emitting empty Prisma Lint SARIF run."; empty_tool prisma-lint; return
  fi
  bin="$install_dir/node_modules/.bin/prisma-lint"
  mapfile -d '' files < "$files_list"
  "$bin" -c "$config" -o json "${files[@]}" > "$json" || true
  [ -s "$json" ] || printf '{"violations":[]}' > "$json"
  convert_tool prisma-lint "$json"
}

run_rubocop() {
  local files_list="$high_impact_temp/rubocop-files" json="$high_impact_temp/rubocop.json" gem_home config
  find_rubocop_files "$files_list" || { echo "::warning::RuboCop file discovery failed."; empty_tool rubocop; return; }
  if ! has_files "$files_list"; then echo "::notice::No Ruby files found - emitting empty RuboCop SARIF run."; empty_tool rubocop; return; fi
  if ! command -v ruby >/dev/null 2>&1 || ! command -v gem >/dev/null 2>&1; then
    echo "::warning::Ruby or gem unavailable - emitting empty RuboCop SARIF run."; empty_tool rubocop; return
  fi
  gem_home="$high_impact_temp/rubocop-gems"; config="$high_impact_temp/rubocop.yml"
  printf 'AllCops:\n  NewCops: disable\n' > "$config"
  if ! GEM_HOME="$gem_home" gem install --no-document --source https://rubygems.org --install-dir "$gem_home" rubocop -v "$RUBOCOP_VERSION" >/dev/null; then
    echo "::warning::RuboCop install failed - emitting empty RuboCop SARIF run."; empty_tool rubocop; return
  fi
  mapfile -d '' files < "$files_list"
  GEM_HOME="$gem_home" "$gem_home/bin/rubocop" --config "$config" --format json --out "$json" "${files[@]}" || true
  [ -s "$json" ] || printf '{"files":[]}' > "$json"
  convert_tool rubocop "$json"
}

run_phpstan() {
  local files_list="$high_impact_temp/php-files" json="$high_impact_temp/phpstan.json" config
  collect_files "$files_list" -name '*.php' || { echo "::warning::PHPStan file discovery failed."; empty_tool phpstan; return; }
  if ! has_files "$files_list"; then echo "::notice::No PHP files found - emitting empty PHPStan SARIF run."; empty_tool phpstan; return; fi
  config="$(find_phpstan_config || true)"
  if [ -z "$config" ]; then echo "::warning::Unable to create PHPStan config - emitting empty PHPStan SARIF run."; empty_tool phpstan; return; fi
  ensure_php_tools phpstan "phpstan/phpstan:${PHPSTAN_VERSION}" || { empty_tool phpstan; return; }
  "$php_tools_dir/vendor/bin/phpstan" analyse --configuration "$config" --error-format=json --no-progress > "$json" || true
  [ -s "$json" ] || printf '{"files":{}}' > "$json"
  convert_tool phpstan "$json"
}

run_phpmd() {
  local files_list="$high_impact_temp/phpmd-files" json="$high_impact_temp/phpmd.json" csv=""
  collect_files "$files_list" -name '*.php' || { echo "::warning::PHPMD file discovery failed."; empty_tool phpmd; return; }
  if ! has_files "$files_list"; then echo "::notice::No PHP files found - emitting empty PHPMD SARIF run."; empty_tool phpmd; return; fi
  ensure_php_tools phpmd "phpmd/phpmd:${PHPMD_VERSION}" || { empty_tool phpmd; return; }
  while IFS= read -r -d '' file; do
    case "$file" in
      *,*) continue ;;
    esac
    csv="${csv}${csv:+,}$file"
  done < "$files_list"
  if [ -z "$csv" ]; then echo "::notice::No comma-safe PHP files for PHPMD - emitting empty PHPMD SARIF run."; empty_tool phpmd; return; fi
  "$php_tools_dir/vendor/bin/phpmd" "$csv" json unusedcode > "$json" || true
  [ -s "$json" ] || printf '{"files":[]}' > "$json"
  convert_tool phpmd "$json"
}

run_phpcs() {
  local files_list="$high_impact_temp/phpcs-files" json="$high_impact_temp/phpcs.json" config
  collect_files "$files_list" -name '*.php' || { echo "::warning::PHPCS file discovery failed."; empty_tool phpcs; return; }
  if ! has_files "$files_list"; then echo "::notice::No PHP files found - emitting empty PHPCS SARIF run."; empty_tool phpcs; return; fi
  config="$(find_phpcs_config || true)"
  if [ -z "$config" ]; then echo "::notice::No valid PHPCS config found - emitting empty PHPCS SARIF run."; empty_tool phpcs; return; fi
  ensure_php_tools phpcs "squizlabs/php_codesniffer:${PHPCS_VERSION}" || { empty_tool phpcs; return; }
  mapfile -d '' files < "$files_list"
  "$php_tools_dir/vendor/bin/phpcs" --standard=PSR12 --report=json "${files[@]}" > "$json" || true
  [ -s "$json" ] || printf '{"files":{}}' > "$json"
  convert_tool phpcs "$json"
}

run_clippy() {
  local files_list="$high_impact_temp/rust-files" json="$high_impact_temp/clippy.jsonl"
  collect_files "$files_list" -name '*.rs' || { echo "::warning::Clippy file discovery failed."; empty_tool clippy; return; }
  if ! has_files "$files_list"; then echo "::notice::No Rust files found - emitting empty Clippy SARIF run."; empty_tool clippy; return; fi
  if [ ! -f Cargo.toml ]; then echo "::notice::No Cargo.toml found - emitting empty Clippy SARIF run."; empty_tool clippy; return; fi
  if ! command -v cargo >/dev/null 2>&1; then echo "::warning::Cargo unavailable - emitting empty Clippy SARIF run."; empty_tool clippy; return; fi
  cargo clippy --message-format=json --all-targets --no-deps -- -D warnings > "$json" || true
  if [ ! -s "$json" ] || ! grep -q '"compiler-message"' "$json"; then
    echo "::warning::Clippy produced no compiler messages - emitting empty Clippy SARIF run."
    empty_tool clippy
    return
  fi
  convert_tool clippy "$json"
}

run_detekt() {
  local files_list="$high_impact_temp/kotlin-files" jar="$high_impact_temp/detekt-cli-${DETEKT_VERSION}-all.jar" raw="$SARIF_DIR/detekt.raw.sarif" config="$high_impact_temp/detekt.yml" inputs=""
  collect_files "$files_list" -name '*.kt' -o -name '*.kts' || { echo "::warning::detekt file discovery failed."; empty_tool detekt; return; }
  if ! has_files "$files_list"; then echo "::notice::No Kotlin files found - emitting empty detekt SARIF run."; empty_tool detekt; return; fi
  if ! command -v java >/dev/null 2>&1; then echo "::warning::Java unavailable - emitting empty detekt SARIF run."; empty_tool detekt; return; fi
  if ! curl -fsSL -o "$jar" "https://github.com/detekt/detekt/releases/download/v${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar"; then
    echo "::warning::detekt download failed - emitting empty detekt SARIF run."; empty_tool detekt; return
  fi
  if ! printf '%s  %s\n' "$DETEKT_CLI_ALL_JAR_SHA256" "$jar" | sha256sum -c --strict -; then
    echo "::warning::detekt checksum mismatch - emitting empty detekt SARIF run."; empty_tool detekt; return
  fi
  cat > "$config" <<'EOF'
potential-bugs:
  active: true
complexity:
  active: true
style:
  active: false
EOF
  while IFS= read -r -d '' file; do
    case "$file" in
      *,*) continue ;;
    esac
    inputs="${inputs}${inputs:+,}$file"
  done < "$files_list"
  if [ -z "$inputs" ]; then echo "::notice::No comma-safe Kotlin files for detekt - emitting empty detekt SARIF run."; empty_tool detekt; return; fi
  java -jar "$jar" --input "$inputs" --config "$config" \
    --excludes '**/.git/**,**/node_modules/**,**/dist/**,**/build/**,**/coverage/**,**/.next/**,**/out/**,**/vendor/**' \
    --report "sarif:$raw" || true
  [ -s "$raw" ] || { empty_tool detekt; return; }
  python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" detekt "$raw" "$SARIF_DIR/detekt.sarif" --cap "$RESULT_CAP" --ensure-run
}

run_swiftlint() {
  local files_list="$high_impact_temp/swift-files" zip="$high_impact_temp/swiftlint_linux_amd64.zip" bin="$high_impact_temp/swiftlint" json="$high_impact_temp/swiftlint.json" config="$high_impact_temp/swiftlint.yml"
  collect_files "$files_list" -name '*.swift' || { echo "::warning::SwiftLint file discovery failed."; empty_tool swiftlint; return; }
  if ! has_files "$files_list"; then echo "::notice::No Swift files found - emitting empty SwiftLint SARIF run."; empty_tool swiftlint; return; fi
  if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then echo "::warning::SwiftLint unsupported runner platform - emitting empty SwiftLint SARIF run."; empty_tool swiftlint; return; fi
  if ! curl -fsSL -o "$zip" "https://github.com/realm/SwiftLint/releases/download/${SWIFTLINT_VERSION}/swiftlint_linux_amd64.zip"; then
    echo "::warning::SwiftLint download failed - emitting empty SwiftLint SARIF run."; empty_tool swiftlint; return
  fi
  if ! printf '%s  %s\n' "$SWIFTLINT_LINUX_AMD64_SHA256" "$zip" | sha256sum -c --strict -; then
    echo "::warning::SwiftLint checksum mismatch - emitting empty SwiftLint SARIF run."; empty_tool swiftlint; return
  fi
  if ! unzip -q "$zip" swiftlint -d "$high_impact_temp"; then
    echo "::warning::SwiftLint extract failed - emitting empty SwiftLint SARIF run."; empty_tool swiftlint; return
  fi
  chmod +x "$bin"
  cat > "$config" <<'EOF'
# Disabled rules match CodeRabbit's SwiftLint tool docs as of 2026-06-12.
disabled_rules:
  - trailing_whitespace
  - line_length
  - comment_spacing
  - vertical_whitespace
EOF
  "$bin" lint --config "$config" --reporter json > "$json" || true
  [ -s "$json" ] || printf '[]' > "$json"
  convert_tool swiftlint "$json"
}

cd "$SOURCE_DIR"
for name in SQLFLUFF_ENABLED PRISMA_LINT_ENABLED RUBOCOP_ENABLED PHPSTAN_ENABLED PHPMD_ENABLED PHPCS_ENABLED CLIPPY_ENABLED DETEKT_ENABLED SWIFTLINT_ENABLED; do
  validate_bool "$name" "${!name:-false}"
done

run_enabled_tool sqlfluff "${SQLFLUFF_ENABLED:-false}" run_sqlfluff
run_enabled_tool prisma-lint "${PRISMA_LINT_ENABLED:-false}" run_prisma_lint
run_enabled_tool rubocop "${RUBOCOP_ENABLED:-false}" run_rubocop
run_enabled_tool phpstan "${PHPSTAN_ENABLED:-false}" run_phpstan
run_enabled_tool phpmd "${PHPMD_ENABLED:-false}" run_phpmd
run_enabled_tool phpcs "${PHPCS_ENABLED:-false}" run_phpcs
run_enabled_tool clippy "${CLIPPY_ENABLED:-false}" run_clippy
run_enabled_tool detekt "${DETEKT_ENABLED:-false}" run_detekt
run_enabled_tool swiftlint "${SWIFTLINT_ENABLED:-false}" run_swiftlint
