import argparse
import os
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


KNIP_TOOL_ID = "knip"
KNIP_TOOL_NAME = "Knip"
KNIP_INFORMATION_URI = "https://knip.dev/"
MAX_ISSUE_NAME_LENGTH = 500
TRUNCATION_SUFFIX = "..."

_ISSUE_TYPES = {
    "unlisted": "unlisted dependency",
    "unresolved": "unresolved import",
    "binaries": "missing binary",
}


def convert_knip_json(data, base_dir=".", cap=None):
    results = []
    for issue in _issues(data):
        path = _safe_path(issue.get("file"), base_dir)
        for issue_type, label in _ISSUE_TYPES.items():
            for item in _items(issue.get(issue_type)):
                name = _bounded_text(item.get("name"), issue_type, MAX_ISSUE_NAME_LENGTH)
                results.append(
                    make_result(
                        f"knip/{issue_type}",
                        "error",
                        f"Knip found {label} '{name}'.",
                        path,
                        line=_positive_int(item.get("line")),
                        column=_column(item),
                        base_dir=base_dir,
                    )
                )
    return make_document(KNIP_TOOL_NAME, KNIP_TOOL_ID, results, information_uri=KNIP_INFORMATION_URI, cap=cap)


def _issues(data):
    if not isinstance(data, dict):
        return []
    issues = data.get("issues")
    return [issue for issue in issues if isinstance(issue, dict)] if isinstance(issues, list) else []


def _items(value):
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _column(item):
    column = _positive_int(item.get("col"))
    return column if column is not None else _positive_int(item.get("column"))


def _positive_int(value):
    if isinstance(value, bool):
        return None
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None


def _bounded_text(value, default, limit):
    text = _safe_text(value, default)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    if limit <= len(TRUNCATION_SUFFIX):
        return TRUNCATION_SUFFIX[: max(limit, 0)]
    target = limit - len(TRUNCATION_SUFFIX)
    output = []
    size = 0
    for char in text:
        char_size = len(char.encode("utf-8"))
        if size + char_size > target:
            break
        output.append(char)
        size += char_size
    return "".join(output) + TRUNCATION_SUFFIX


def _safe_text(value, default):
    text = str(value or default).strip().encode("utf-8", errors="replace").decode("utf-8")
    if not text:
        text = str(default).encode("utf-8", errors="replace").decode("utf-8")
    return text or "knip"


def _safe_path(value, base_dir):
    text = str(value or "")
    if "\0" in text or "://" in text:
        return "."
    base = os.path.realpath(base_dir)
    path = os.path.realpath(text if os.path.isabs(text) else os.path.join(base, text))
    try:
        relative = os.path.relpath(path, base)
    except ValueError:
        return "."
    if relative == ".." or relative.startswith(f"..{os.sep}") or os.path.isabs(relative):
        return "."
    relative = relative.replace(os.sep, "/").replace("\\", "/")
    if not relative or relative == ".":
        return "."
    return relative[2:] if relative.startswith("./") else relative


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert Knip JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    document = convert_knip_json(load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
