import argparse
import json
import re
import sys


SIGILIX_SCHEMA_VERSION = 1
SIGILIX_SOURCE = "deterministic-tool"
KNOWN_TOOL_IDS = frozenset(
    {
        "semgrep",
        "opengrep",
        "eslint",
        "tsc",
        "ruff",
        "brakeman",
        "pylint",
        "flake8",
        "knip",
        "golangci-lint",
        "buf",
        "sqlfluff",
        "prisma-lint",
        "rubocop",
        "phpstan",
        "phpmd",
        "phpcs",
        "clippy",
        "detekt",
        "swiftlint",
        "actionlint",
        "shellcheck",
        "gitleaks",
        "osv-scanner",
        "checkov",
        "trivy",
        "trufflehog",
        "zizmor",
        "hadolint",
        "tflint",
        "biome",
        "oxlint",
        "ast-grep",
        "regal",
        "htmlhint",
        "stylelint",
        "yamllint",
        "markdownlint",
        "dotenv-linter",
        "checkmake",
    }
)
DEFAULT_TOOL_NAMES = {
    "semgrep": "Semgrep",
    "opengrep": "OpenGrep",
    "eslint": "ESLint",
    "tsc": "TypeScript Compiler",
    "ruff": "Ruff",
    "brakeman": "Brakeman",
    "pylint": "Pylint",
    "flake8": "Flake8",
    "knip": "Knip",
    "golangci-lint": "golangci-lint",
    "buf": "Buf",
    "sqlfluff": "SQLFluff",
    "prisma-lint": "Prisma Lint",
    "rubocop": "RuboCop",
    "phpstan": "PHPStan",
    "phpmd": "PHPMD",
    "phpcs": "PHPCS",
    "clippy": "Clippy",
    "detekt": "detekt",
    "swiftlint": "SwiftLint",
    "actionlint": "actionlint",
    "shellcheck": "ShellCheck",
    "gitleaks": "gitleaks",
    "osv-scanner": "OSV-Scanner",
    "checkov": "Checkov",
    "trivy": "Trivy",
    "trufflehog": "TruffleHog",
    "zizmor": "zizmor",
    "hadolint": "Hadolint",
    "tflint": "TFLint",
    "biome": "Biome",
    "oxlint": "Oxlint",
    "ast-grep": "ast-grep",
    "regal": "Regal",
    "htmlhint": "HTMLHint",
    "stylelint": "Stylelint",
    "yamllint": "YAMLlint",
    "markdownlint": "markdownlint",
    "dotenv-linter": "dotenv-linter",
    "checkmake": "checkmake",
}

_SEVERITY_RANKS = {
    "error": 0,
    "warning": 1,
    "note": 2,
    "none": 3,
}

_DROPPED_RESULT_KEY_SETS = (
    frozenset({"droppedCount"}),
    frozenset({"droppedCount", "keptCount"}),
)


def _ensure_dict(value):
    return value if isinstance(value, dict) else {}


def _empty_sarif_document():
    return {"version": "2.1.0", "runs": []}


def _load_sarif_document(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except Exception:
        return _empty_sarif_document()
    if not isinstance(document, dict):
        return _empty_sarif_document()
    return document


def _first_location(result):
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return {}
    return _ensure_dict(locations[0])


def _result_path(result):
    location = _first_location(result)
    physical = _ensure_dict(location.get("physicalLocation"))
    artifact = _ensure_dict(physical.get("artifactLocation"))
    return str(artifact.get("uri") or "")


def _result_line(result):
    location = _first_location(result)
    physical = _ensure_dict(location.get("physicalLocation"))
    region = _ensure_dict(physical.get("region"))
    line = region.get("startLine")
    return line if isinstance(line, int) else 0


def _result_rule_id(result):
    return str(result.get("ruleId") or "")


def _result_message(result):
    message = result.get("message")
    if isinstance(message, dict):
        return str(message.get("text") or message.get("markdown") or "")
    return str(message or "")


def _severity_rank(result):
    level = str(result.get("level") or "").lower()
    return _SEVERITY_RANKS.get(level, _SEVERITY_RANKS["none"])


def _cap_sort_key(item):
    index, result = item
    if not isinstance(result, dict):
        result = {}
    return (
        _severity_rank(result),
        _result_path(result),
        _result_line(result),
        _result_rule_id(result),
        _result_message(result),
        index,
    )


def cap_results(results, cap):
    if cap < 0:
        raise ValueError("cap must be non-negative")
    if len(results) <= cap:
        return results, None

    ranked = sorted(enumerate(results), key=_cap_sort_key)
    kept = [result for _, result in ranked[:cap]]
    return kept, {"droppedCount": len(results) - len(kept), "keptCount": len(kept)}


def _validate_dropped_results(dropped_results):
    if not isinstance(dropped_results, dict):
        raise ValueError("dropped_results must be a dict")
    if frozenset(dropped_results.keys()) not in _DROPPED_RESULT_KEY_SETS:
        raise ValueError("dropped_results must contain only droppedCount and optional keptCount")
    for key, value in dropped_results.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"dropped_results {key} must be an integer")
        if value < 0:
            raise ValueError(f"dropped_results {key} must be non-negative")


def attach_sigilix_metadata(run, tool_id, dropped_results=None):
    if tool_id not in KNOWN_TOOL_IDS:
        raise ValueError(f"unknown Sigilix tool id: {tool_id}")
    if dropped_results is not None:
        _validate_dropped_results(dropped_results)

    tool = run.get("tool")
    if not isinstance(tool, dict):
        tool = {}
        run["tool"] = tool
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        driver = {}
        tool["driver"] = driver
    if not isinstance(driver.get("name"), str) or not driver["name"]:
        driver["name"] = DEFAULT_TOOL_NAMES[tool_id]
    properties = driver.get("properties")
    if not isinstance(properties, dict):
        properties = {}
        driver["properties"] = properties
    properties.pop("sigilixRoleHints", None)
    properties["sigilixSchemaVersion"] = SIGILIX_SCHEMA_VERSION
    properties["sigilixToolId"] = tool_id
    properties["sigilixSource"] = SIGILIX_SOURCE
    if dropped_results is None:
        properties.pop("sigilixDroppedResults", None)
    else:
        properties["sigilixDroppedResults"] = dropped_results
    return run


def cap_run_results(run, cap, tool_id=None):
    results = run.get("results")
    if not isinstance(results, list):
        results = []
    kept, summary = cap_results(results, cap)
    run["results"] = kept
    if tool_id is not None:
        attach_sigilix_metadata(run, tool_id, summary)
    return run, summary


def empty_metadata_run(tool_id):
    return attach_sigilix_metadata({"tool": {"driver": {"name": DEFAULT_TOOL_NAMES[tool_id]}}, "results": []}, tool_id)


def _sanitize_run_results(run):
    results = run.get("results")
    if not isinstance(results, list):
        run["results"] = []
        return
    run["results"] = [result for result in results if isinstance(result, dict)]


# SIG-184 Phase 3 — canonical vuln-class stamping. The engine's receipt-join
# (verify-finding-receipt.ts) confirms a security finding into the VERIFIED tier
# only when an independent runner scan flagged the SAME canonical class at the
# same path/line. These class strings MUST match the engine's CanonicalVulnClass
# enum (src/shared/domain/vuln-class.ts) VERBATIM — keep the two in lockstep.
#
# CREDIBILITY (Codex + DeepSeek sign-off): NOT loose substring matching. We map a
# native tool ruleId to the set of classes whose anchored pattern matches; a
# result is stamped ONLY when EXACTLY ONE distinct class matches. Zero or >1
# matches → left UNSET (the engine treats absence as INCONCLUSIVE, never a false
# VERIFIED). So an ambiguous/colliding ruleId is fail-safe, never mis-stamped.
_RULE_CLASS_PATTERNS = {
    "semgrep": [
        (re.compile(r"dangerous-exec|command[-_.]?inj|os[-_.]?command|dangerous-subprocess|spawn.*shell"), "command-injection"),
        (re.compile(r"nosql[-_.]?inj"), "nosql-injection"),
        (re.compile(r"(?<![a-z])sql[-_.]?inj"), "sql-injection"),
        (re.compile(r"path[-_.]?travers|directory[-_.]?travers|zip[-_.]?slip"), "path-traversal"),
        (re.compile(r"(?<![a-z])ssrf|server[-_.]?side[-_.]?request"), "ssrf"),
        (re.compile(r"(?<![a-z])xxe|xml[-_.]?external[-_.]?entit"), "xxe"),
        (re.compile(r"(?<![a-z])ssti|template[-_.]?inj"), "ssti"),
        (re.compile(r"proto(?:type)?[-_.]?pollution"), "proto-pollution"),
        (re.compile(r"open[-_.]?redirect"), "open-redirect"),
        (re.compile(r"hard[-_.]?coded|hardcoded"), "hardcoded-secret"),
        (re.compile(r"insecure[-_.]?random|weak[-_.]?random|insecure.*prng"), "weak-random"),
    ],
}
# OpenGrep runs the same rulesets as Semgrep → reuse the patterns.
_RULE_CLASS_PATTERNS["opengrep"] = _RULE_CLASS_PATTERNS["semgrep"]
# Dedicated secret scanners only ever report hardcoded secrets, so every result
# maps to `hardcoded-secret` (`.+` = any non-empty ruleId). The exactly-one-class
# guard keeps this collision-safe.
_RULE_CLASS_PATTERNS["gitleaks"] = [(re.compile(r".+"), "hardcoded-secret")]
_RULE_CLASS_PATTERNS["trufflehog"] = [(re.compile(r".+"), "hardcoded-secret")]


def stamp_rule_classes(run, tool_id):
    """Stamp per-result properties.sigilixRuleClass (collision-safe). Strips any
    preexisting (untrusted) value first, then sets a class ONLY when exactly one
    pattern-class matches the native ruleId. Mutates + returns ``run``."""
    results = run.get("results")
    if not isinstance(results, list):
        return run
    patterns = _RULE_CLASS_PATTERNS.get(tool_id)
    for result in results:
        if not isinstance(result, dict):
            continue
        props = result.get("properties")
        # Always strip any preexisting class from raw tool output (untrusted).
        if isinstance(props, dict):
            props.pop("sigilixRuleClass", None)
        if not patterns:
            continue
        rule_id = _result_rule_id(result)
        if not rule_id:
            continue
        matched = {cls for (pattern, cls) in patterns if pattern.search(rule_id)}
        if len(matched) != 1:
            continue  # 0 or >1 → fail-safe: leave unset (engine → INCONCLUSIVE).
        if not isinstance(props, dict):
            props = {}
            result["properties"] = props
        props["sigilixRuleClass"] = next(iter(matched))
    return run


def _main(argv):
    parser = argparse.ArgumentParser(description="Attach Sigilix metadata to SARIF runs.")
    parser.add_argument("tool_id", choices=sorted(KNOWN_TOOL_IDS))
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--cap", type=int)
    parser.add_argument("--ensure-run", action="store_true")
    args = parser.parse_args(argv)

    document = _load_sarif_document(args.input)
    runs = document.get("runs")
    if not isinstance(runs, list):
        runs = []
    normalized_runs = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        summary = None
        _sanitize_run_results(run)
        if args.cap is not None:
            _, summary = cap_run_results(run, args.cap)
        attach_sigilix_metadata(run, args.tool_id, summary)
        # SIG-184 Phase 3: stamp the canonical vuln-class on each final result,
        # after capping/metadata (so it runs over the assembled output).
        stamp_rule_classes(run, args.tool_id)
        normalized_runs.append(run)
    if args.ensure_run and not normalized_runs:
        normalized_runs.append(empty_metadata_run(args.tool_id))
    if document.get("version") != "2.1.0":
        document["version"] = "2.1.0"
    document["runs"] = normalized_runs
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
