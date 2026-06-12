import argparse
import json
import sys
from urllib.parse import urlparse

from sarif_converter_common import load_json_file, normalize_path, write_json_file


def _is_external_uri(uri):
    parsed = urlparse(uri)
    return bool(parsed.scheme and parsed.scheme.lower() != "file")


def _strip_file_uri(uri):
    parsed = urlparse(uri)
    if parsed.scheme.lower() != "file":
        return uri
    return parsed.path or ""


def _prefixed_path(uri, root, base_dir):
    if not isinstance(uri, str) or not uri or _is_external_uri(uri):
        return uri
    normalized = normalize_path(_strip_file_uri(uri), base_dir=base_dir)
    if root == "." or normalized == root or normalized.startswith(f"{root}/"):
        return normalized
    return f"{root}/{normalized}"


def _normalize_artifact_locations(value, root, base_dir):
    if isinstance(value, list):
        for item in value:
            _normalize_artifact_locations(item, root, base_dir)
        return
    if not isinstance(value, dict):
        return
    if isinstance(value.get("uri"), str):
        value["uri"] = _prefixed_path(value["uri"], root, base_dir)
    for child in value.values():
        _normalize_artifact_locations(child, root, base_dir)


def normalize_brakeman_sarif_paths(document, root, base_dir="."):
    if not isinstance(document, dict):
        raise ValueError("invalid Brakeman SARIF input")
    if document.get("version") != "2.1.0":
        document["version"] = "2.1.0"
    runs = document.get("runs")
    if not isinstance(runs, list):
        document["runs"] = []
        return document
    root = normalize_path(root or ".", base_dir=base_dir)
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = run.setdefault("tool", {}).setdefault("driver", {})
        if root != ".":
            driver["name"] = f"Brakeman ({root})"
        _normalize_artifact_locations(run.get("results"), root, base_dir)
    return document


def _main(argv):
    parser = argparse.ArgumentParser(description="Normalize Brakeman SARIF paths for nested Rails roots.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--root", required=True)
    parser.add_argument("--base-dir", default=".")
    args = parser.parse_args(argv)

    document = load_json_file(args.input)
    if not isinstance(document, dict):
        print("invalid Brakeman SARIF input", file=sys.stderr)
        return 1
    normalized = normalize_brakeman_sarif_paths(document, root=args.root, base_dir=args.base_dir)
    write_json_file(args.output, normalized)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
