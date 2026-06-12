import argparse
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


STYLELINT_TOOL_ID = "stylelint"
STYLELINT_TOOL_NAME = "Stylelint"
STYLELINT_INFORMATION_URI = "https://stylelint.io/"
_LEVELS = {"error": "error", "warning": "warning", "info": "note"}


def convert_stylelint_json(data, base_dir=".", cap=None):
    results = []
    for entry in _list_or_empty(data):
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source") or "")
        for warning in _list_or_empty(entry.get("warnings")):
            if not isinstance(warning, dict):
                continue
            results.append(_warning_to_result(source, warning, base_dir=base_dir))
    return make_document(STYLELINT_TOOL_NAME, STYLELINT_TOOL_ID, results, information_uri=STYLELINT_INFORMATION_URI, cap=cap)


def _warning_to_result(source, warning, base_dir="."):
    rule = str(warning.get("rule") or "stylelint").strip() or "stylelint"
    severity = str(warning.get("severity") or "").lower()
    line = warning.get("line")
    column = warning.get("column")
    return make_result(
        rule,
        _LEVELS.get(severity, "warning"),
        str(warning.get("text") or ""),
        source,
        line=line,
        column=column,
        end_line=warning.get("endLine") if _is_positive_int(line) else None,
        end_column=warning.get("endColumn") if _is_positive_int(column) else None,
        base_dir=base_dir,
    )


def _list_or_empty(value):
    return value if isinstance(value, list) else []


def _is_positive_int(value):
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert Stylelint JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    document = convert_stylelint_json(load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
