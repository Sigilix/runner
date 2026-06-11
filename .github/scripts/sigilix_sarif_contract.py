import argparse
import json
import sys


SIGILIX_SCHEMA_VERSION = 1
SIGILIX_SOURCE = "deterministic-tool"
KNOWN_TOOL_IDS = frozenset({"semgrep", "eslint", "ruff", "actionlint", "shellcheck"})

_SEVERITY_RANKS = {
    "error": 0,
    "warning": 1,
    "note": 2,
    "none": 3,
}


def _ensure_dict(value):
    return value if isinstance(value, dict) else {}


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
    return kept, {"dropped": len(results) - len(kept), "kept": len(kept)}


def attach_sigilix_metadata(run, tool_id, dropped_results=None):
    if tool_id not in KNOWN_TOOL_IDS:
        raise ValueError(f"unknown Sigilix tool id: {tool_id}")

    tool = run.setdefault("tool", {})
    driver = tool.setdefault("driver", {})
    properties = driver.setdefault("properties", {})
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


def _main(argv):
    parser = argparse.ArgumentParser(description="Attach Sigilix metadata to SARIF runs.")
    parser.add_argument("tool_id", choices=sorted(KNOWN_TOOL_IDS))
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    runs = document.get("runs") if isinstance(document, dict) else []
    if not isinstance(runs, list):
        runs = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        summary = None
        if args.cap is not None:
            _, summary = cap_run_results(run, args.cap)
        attach_sigilix_metadata(run, args.tool_id, summary)
    document["runs"] = runs
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
