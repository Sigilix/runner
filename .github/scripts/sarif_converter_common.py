import json
import os

from sigilix_sarif_contract import attach_sigilix_metadata, cap_run_results


def empty_document(tool_name, tool_id, information_uri=None):
    return make_document(tool_name, tool_id, [], information_uri=information_uri)


def make_document(tool_name, tool_id, results, information_uri=None, cap=None):
    driver = {"name": tool_name, "rules": _rules_for_results(results)}
    if information_uri:
        driver["informationUri"] = information_uri
    run = {"tool": {"driver": driver}, "results": results}
    if cap is None:
        attach_sigilix_metadata(run, tool_id)
    else:
        cap_run_results(run, cap, tool_id=tool_id)
    return {"version": "2.1.0", "runs": [run]}


def make_result(rule_id, level, message, path, line=None, column=None, end_line=None, end_column=None, base_dir="."):
    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": normalize_path(path, base_dir=base_dir)},
                    "region": make_region(line, column, end_line, end_column),
                }
            }
        ],
    }
    if not result["locations"][0]["physicalLocation"]["region"]:
        result["locations"][0]["physicalLocation"].pop("region")
    return result


def make_region(line=None, column=None, end_line=None, end_column=None):
    region = {}
    for key, value in (
        ("startLine", line),
        ("startColumn", column),
        ("endLine", end_line),
        ("endColumn", end_column),
    ):
        integer = int_or_none(value)
        if integer is not None and integer > 0:
            region[key] = integer
    return region


def int_or_none(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def normalize_path(path, base_dir="."):
    text = str(path or "")
    if os.path.isabs(text):
        try:
            relative = os.path.relpath(text, base_dir)
        except ValueError:
            relative = text
        if not relative.startswith(".."):
            text = relative
    text = text.replace(os.sep, "/").replace("\\", "/")
    if text.startswith("./"):
        return text[2:]
    return text


def load_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def write_json_file(path, document):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, separators=(",", ":"))


def _rules_for_results(results):
    rules = []
    seen = set()
    for result in results:
        rule_id = result.get("ruleId")
        if not isinstance(rule_id, str) or not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)
        rules.append({"id": rule_id, "shortDescription": {"text": rule_id}})
    return rules
