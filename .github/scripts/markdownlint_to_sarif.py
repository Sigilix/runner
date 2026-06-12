import argparse
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


MARKDOWNLINT_TOOL_NAME = "markdownlint"
MARKDOWNLINT_TOOL_ID = "markdownlint"
MARKDOWNLINT_INFORMATION_URI = "https://github.com/DavidAnson/markdownlint"


def convert_markdownlint_json(data, base_dir=".", cap=None):
    results = []
    for item in _list_or_empty(data):
        if not isinstance(item, dict):
            continue
        results.append(
            make_result(
                _rule_id(item),
                _level(item),
                _message(item),
                item.get("fileName") or "",
                line=item.get("lineNumber"),
                column=_start_column(item),
                end_column=_end_column(item),
                base_dir=base_dir,
            )
        )
    return make_document(
        MARKDOWNLINT_TOOL_NAME,
        MARKDOWNLINT_TOOL_ID,
        results,
        information_uri=MARKDOWNLINT_INFORMATION_URI,
        cap=cap,
    )


def _rule_id(item):
    names = item.get("ruleNames")
    if isinstance(names, list) and names:
        return str(names[0] or "markdownlint")
    return str(item.get("ruleName") or "markdownlint")


def _level(item):
    severity = str(item.get("severity") or "").lower()
    if severity in ("error", "warning", "note"):
        return severity
    return "warning"


def _message(item):
    description = str(item.get("ruleDescription") or _rule_id(item))
    detail = item.get("errorDetail")
    if isinstance(detail, str) and detail:
        return f"{description}: {detail}"
    return description


def _start_column(item):
    error_range = item.get("errorRange")
    if isinstance(error_range, list) and len(error_range) >= 1:
        return error_range[0]
    return None


def _end_column(item):
    error_range = item.get("errorRange")
    if isinstance(error_range, list) and len(error_range) >= 2:
        start = error_range[0]
        length = error_range[1]
        if isinstance(start, int) and isinstance(length, int):
            return start + length
    return None


def _list_or_empty(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("results", "files"):
            if isinstance(value.get(key), list):
                return value[key]
    return []


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert markdownlint JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    document = convert_markdownlint_json(load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
