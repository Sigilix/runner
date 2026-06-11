import argparse
import json
import os
import sys

from sigilix_sarif_contract import KNOWN_TOOL_IDS


SCHEMA_VERSION = 1


def _load_sarif(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except Exception:
        return None
    if not isinstance(document, dict):
        return None
    if document.get("version") != "2.1.0":
        return None
    runs = document.get("runs")
    if not isinstance(runs, list):
        return None
    if not all(isinstance(run, dict) for run in runs):
        return None
    return document


def _count_results(runs):
    count = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if isinstance(results, list):
            count += len([result for result in results if isinstance(result, dict)])
    return count


def _manifest_entry(tool_id, enabled, path):
    entry = {"toolId": tool_id, "enabled": bool(enabled)}
    if not enabled:
        entry["status"] = "disabled"
        return entry

    entry["path"] = path
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        entry["status"] = "missing-output"
        return entry

    document = _load_sarif(path)
    if document is None:
        entry["status"] = "invalid-output"
        return entry

    runs = [run for run in document["runs"] if isinstance(run, dict)]
    result_count = _count_results(runs)
    entry["runCount"] = len(runs)
    entry["resultCount"] = result_count
    entry["status"] = "produced" if result_count > 0 else "empty"
    return entry


def build_scan_manifest(tool_specs):
    tool_specs = list(tool_specs)
    if len(tool_specs) > len(KNOWN_TOOL_IDS):
        raise ValueError("too many tool specs")
    seen = set()
    for tool_id, _, _ in tool_specs:
        if tool_id not in KNOWN_TOOL_IDS:
            raise ValueError(f"unknown tool id: {tool_id}")
        if tool_id in seen:
            raise ValueError(f"duplicate tool id: {tool_id}")
        seen.add(tool_id)
    tools = [_manifest_entry(tool_id, enabled, path) for tool_id, enabled, path in tool_specs]
    summary = {"enabled": 0, "produced": 0, "empty": 0, "missing": 0, "invalid": 0}
    for tool in tools:
        if not tool["enabled"]:
            continue
        summary["enabled"] += 1
        status = tool["status"]
        if status == "missing-output":
            summary["missing"] += 1
        elif status == "invalid-output":
            summary["invalid"] += 1
        elif status in ("produced", "empty"):
            summary[status] += 1
    return {"schemaVersion": SCHEMA_VERSION, "tools": tools, "summary": summary}


def _parse_tool_arg(value):
    if "=" not in value:
        raise ValueError("--tool must use tool_id=path")
    tool_id, path = value.split("=", 1)
    tool_id = tool_id.strip()
    if not tool_id:
        raise ValueError("--tool requires a non-empty tool id")
    if tool_id not in KNOWN_TOOL_IDS:
        raise ValueError(f"unknown tool id: {tool_id}")
    return tool_id, True, path


def _main(argv):
    parser = argparse.ArgumentParser(description="Build a Sigilix runner scan manifest.")
    parser.add_argument("--tool", action="append", default=[], help="Enabled tool as tool_id=path.")
    parser.add_argument("--disabled", action="append", default=[], help="Disabled tool id.")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args(argv)

    specs = []
    try:
        specs.extend(_parse_tool_arg(value) for value in args.tool)
        for tool_id in args.disabled:
            tool_id = tool_id.strip()
            if not tool_id:
                continue
            if tool_id not in KNOWN_TOOL_IDS:
                raise ValueError(f"unknown tool id: {tool_id}")
            specs.append((tool_id, False, ""))
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 2

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(build_scan_manifest(specs), handle, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
