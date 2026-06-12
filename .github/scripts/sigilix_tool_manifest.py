import json
import os
import re

from sigilix_sarif_contract import KNOWN_TOOL_IDS


TOOL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ENV_RE = re.compile(r"^[A-Z0-9_]+_ENABLED$")
OUTPUT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*\.sarif$")


def _require_string(row, key, index):
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"tool manifest row {index} requires non-empty string {key}")
    return value


def validate_tool_manifest(document):
    if not isinstance(document, dict) or set(document.keys()) != {"tools"}:
        raise ValueError("tool manifest must be an object with only a tools key")
    rows = document["tools"]
    if not isinstance(rows, list):
        raise ValueError("tool manifest tools must be a list")

    validated = []
    seen_ids = set()
    seen_envs = set()
    seen_outputs = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row.keys()) != {"id", "env", "output"}:
            raise ValueError(f"tool manifest row {index} must contain id, env, and output")
        tool_id = _require_string(row, "id", index)
        env_var = _require_string(row, "env", index)
        output = _require_string(row, "output", index)

        if not TOOL_ID_RE.fullmatch(tool_id) or tool_id not in KNOWN_TOOL_IDS:
            raise ValueError(f"invalid tool id: {tool_id}")
        if not ENV_RE.fullmatch(env_var):
            raise ValueError(f"invalid env var for {tool_id}: {env_var}")
        if not OUTPUT_RE.fullmatch(output) or os.path.basename(output) != output:
            raise ValueError(f"invalid output for {tool_id}: {output}")
        if tool_id in seen_ids:
            raise ValueError(f"duplicate tool id: {tool_id}")
        if env_var in seen_envs:
            raise ValueError(f"duplicate env var: {env_var}")
        if output in seen_outputs:
            raise ValueError(f"duplicate output: {output}")

        seen_ids.add(tool_id)
        seen_envs.add(env_var)
        seen_outputs.add(output)
        validated.append({"id": tool_id, "env": env_var, "output": output})

    if set(seen_ids) != KNOWN_TOOL_IDS:
        missing = ", ".join(sorted(KNOWN_TOOL_IDS - seen_ids))
        extra = ", ".join(sorted(seen_ids - KNOWN_TOOL_IDS))
        detail_parts = []
        if missing:
            detail_parts.append(f"missing: {missing}")
        if extra:
            detail_parts.append(f"extra: {extra}")
        detail = "; ".join(detail_parts)
        raise ValueError(f"tool manifest ids must match known tool ids ({detail})")
    return validated


def load_tool_manifest(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except json.JSONDecodeError as err:
        raise ValueError(f"invalid tool manifest JSON: {err}") from err
    except OSError as err:
        raise ValueError(f"unable to read tool manifest {path}: {err}") from err
    return validate_tool_manifest(document)


def manifest_tool_specs(path, sarif_dir, environ=None):
    environ = os.environ if environ is None else environ
    specs = []
    for row in load_tool_manifest(path):
        enabled = environ.get(row["env"], "false") == "true"
        output_path = os.path.join(sarif_dir, row["output"]) if enabled else ""
        specs.append((row["id"], enabled, output_path))
    return specs


def manifest_sarif_paths(path, sarif_dir):
    # Merge intentionally includes every configured output; missing disabled outputs read as empty SARIF.
    return [os.path.join(sarif_dir, row["output"]) for row in load_tool_manifest(path)]
