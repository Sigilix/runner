#!/usr/bin/env bash
set -euo pipefail

: "${BRAKEMAN_GEM_SHA256:?}"
: "${BRAKEMAN_VERSION:?}"
: "${RACC_GEM_SHA256:?}"
: "${RACC_VERSION:?}"
: "${RESULT_CAP:?}"
: "${RUNNER_DIR:?}"
: "${RUNNER_TEMP:?}"
: "${SARIF_DIR:?}"
: "${SOURCE_DIR:?}"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
RUNNER_DIR="$(cd "$RUNNER_DIR" && pwd -P)"

raw="$SARIF_DIR/brakeman.raw.sarif"
out="$SARIF_DIR/brakeman.sarif"
roots_list=""
brakeman_config="$RUNNER_TEMP/brakeman-sigilix.yml"
brakeman_ignore="$RUNNER_TEMP/brakeman-ignore.json"
brakeman_gem_cache="$RUNNER_TEMP/brakeman-gem-cache"
brakeman_raw_dir="$RUNNER_TEMP/brakeman-raw"
raw_files=()

mkdir -p "$SARIF_DIR" "$RUNNER_TEMP" "$brakeman_gem_cache" "$brakeman_raw_dir"
roots_list="$(mktemp "$RUNNER_TEMP/brakeman-roots.XXXXXX")"

cleanup_brakeman() {
  rm -f "$roots_list" "$brakeman_config" "$brakeman_ignore"
  rm -rf "$brakeman_gem_cache" "$brakeman_raw_dir"
}
trap cleanup_brakeman EXIT

emit_empty_sarif() {
  printf '{"version":"2.1.0","runs":[]}' > "$raw"
}

discover_rails_roots() {
  find -P . \
    \( -type d \( -name '.git' -o -name 'node_modules' -o -name 'dist' -o -name 'build' \
    -o -name 'coverage' -o -name '.next' -o -name 'out' -o -name 'vendor' -o -name '.terraform' \) -prune \) -o \
    \( -type f -path '*/config/application.rb' -print0 \) \
    | while IFS= read -r -d '' application_file; do
      root="${application_file%/config/application.rb}"
      printf '%s\0' "${root:-.}"
    done \
    | sort -zu
}

write_runner_brakeman_config() {
  printf '%s\n' '--- {}' > "$brakeman_config"
  printf '%s\n' '{"ignored_warnings":[]}' > "$brakeman_ignore"
}

fetch_verified_gem() {
  local name="$1"
  local version="$2"
  local checksum="$3"
  local path="$brakeman_gem_cache/${name}-${version}.gem"
  rm -f "$path"
  if ! (cd "$brakeman_gem_cache" && gem fetch --norc --clear-sources --source https://rubygems.org "$name" -v "$version" >/dev/null); then
    echo "::warning::${name} gem fetch failed - manifest will record missing output."
    rm -f "$path"
    return 1
  fi
  if [ ! -s "$path" ]; then
    echo "::warning::${name} gem package missing after fetch - manifest will record missing output."
    return 1
  fi
  if ! printf '%s  %s\n' "$checksum" "$path" | sha256sum -c --strict -; then
    echo "::warning::${name} gem checksum mismatch - manifest will record missing output."
    return 1
  fi
}

cd "$SOURCE_DIR"
if ! discover_rails_roots > "$roots_list"; then
  echo "::warning::Brakeman Rails root discovery failed - emitting empty Brakeman SARIF run."
  emit_empty_sarif
elif ! grep -qz . "$roots_list"; then
  echo "::notice::No Rails roots found - emitting empty Brakeman SARIF run."
  emit_empty_sarif
elif [[ ! "$BRAKEMAN_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::Brakeman version must be a pinned x.y.z version - manifest will record missing output."
elif [[ ! "$RACC_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "::warning::racc version must be a pinned x.y.z version - manifest will record missing output."
elif [[ ! "$BRAKEMAN_GEM_SHA256" =~ ^[0-9a-f]{64}$ ]] || [[ ! "$RACC_GEM_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::warning::Brakeman gem checksums must be pinned SHA256 values - manifest will record missing output."
elif ! command -v ruby >/dev/null 2>&1 || ! command -v gem >/dev/null 2>&1; then
  echo "::warning::Ruby and gem are required for Brakeman - manifest will record missing output."
else
  export GEM_HOME="$RUNNER_TEMP/brakeman-gems"
  export GEM_PATH="$GEM_HOME"
  export PATH="$GEM_HOME/bin:$PATH"
  mkdir -p "$GEM_HOME"
  write_runner_brakeman_config
  if ! fetch_verified_gem racc "$RACC_VERSION" "$RACC_GEM_SHA256"; then
    :
  elif ! fetch_verified_gem brakeman "$BRAKEMAN_VERSION" "$BRAKEMAN_GEM_SHA256"; then
    :
  elif ! gem install --norc --local --no-document --install-dir "$GEM_HOME" \
    "$brakeman_gem_cache/racc-${RACC_VERSION}.gem" \
    "$brakeman_gem_cache/brakeman-${BRAKEMAN_VERSION}.gem"; then
    echo "::warning::Brakeman install failed - manifest will record missing output."
  elif ! brakeman_version="$(brakeman --version 2>/dev/null)"; then
    echo "::warning::Brakeman version check failed - manifest will record missing output."
  elif ! printf '%s\n' "$brakeman_version" | grep -Eq "(^|[^0-9.])${BRAKEMAN_VERSION}([^0-9.]|$)"; then
    echo "::warning::Brakeman installed version mismatch - manifest will record missing output."
  else
    index=0
    while IFS= read -r -d '' root; do
      root="${root#./}"
      if [ -z "$root" ]; then root="."; fi
      if [[ "$root" == ".." || "$root" == "../"* || "$root" == *"/.." || "$root" == *"/../"* ]]; then
        echo "::warning::Skipping Brakeman root with traversal segments: ${root}"
        continue
      fi
      if [ "$root" = "." ]; then
        root_abs="$SOURCE_DIR"
      elif ! root_abs="$(cd "$SOURCE_DIR/$root" && pwd -P)"; then
        echo "::warning::Unable to resolve Brakeman root ${root} - skipping."
        continue
      fi
      if [[ "$root_abs" != "$SOURCE_DIR" && "$root_abs" != "$SOURCE_DIR"/* ]]; then
        echo "::warning::Brakeman root ${root} resolves outside source directory - skipping."
        continue
      fi
      root_raw="$brakeman_raw_dir/brakeman-${index}.raw.sarif"
      root_normalized="$brakeman_raw_dir/brakeman-${index}.sarif"
      if brakeman \
        --path "$root_abs" \
        --config-file "$brakeman_config" \
        --ignore-config "$brakeman_ignore" \
        --show-ignored \
        --no-exit-on-warn \
        --no-exit-on-error \
        --format sarif \
        --output "$root_raw" \
        --quiet; then
        :
      else
        echo "::warning::Brakeman scan for ${root} exited non-zero - using SARIF output if present."
      fi
      if [ -s "$root_raw" ]; then
        if python3 "$RUNNER_DIR/.github/scripts/brakeman_sarif_paths.py" \
          "$root_raw" "$root_normalized" --root "$root" --base-dir "$SOURCE_DIR" \
          && [ -s "$root_normalized" ]; then
          raw_files+=("$root_normalized")
        else
          echo "::warning::Brakeman SARIF path normalization failed for ${root} - discarding output."
        fi
      else
        echo "::warning::Brakeman scan for ${root} produced no SARIF output."
      fi
      index=$((index + 1))
    done < "$roots_list"
    if [ "${#raw_files[@]}" -eq 0 ]; then
      echo "::warning::Brakeman produced no SARIF output for detected Rails roots - manifest will record missing output."
    elif [ "${#raw_files[@]}" -eq 1 ]; then
      cp "${raw_files[0]}" "$raw" \
        || { echo "::warning::Brakeman failed to copy SARIF output - manifest will record missing output."; rm -f "$raw"; }
    else
      python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_merge.py" \
        "${raw_files[@]}" -o "$raw" \
        || { echo "::warning::Brakeman SARIF merge failed - manifest will record missing output."; rm -f "$raw"; }
    fi
  fi
fi

if [ -s "$raw" ]; then
  python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py" \
    brakeman "$raw" "$out" --cap "$RESULT_CAP" --ensure-run \
    || echo "::warning::Brakeman SARIF normalization failed - manifest will record missing output."
fi
