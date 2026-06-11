import argparse
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


ESLINT_TOOL_NAME = "ESLint"
ESLINT_TOOL_ID = "eslint"
ESLINT_INFORMATION_URI = "https://eslint.org/"


def convert_eslint_json(data, base_dir=".", cap=None):
    results = []
    for file_report in _list_or_empty(data):
        if not isinstance(file_report, dict):
            continue
        path = file_report.get("filePath") or file_report.get("path") or ""
        for message in _list_or_empty(file_report.get("messages")):
            if not isinstance(message, dict):
                continue
            results.append(_message_to_result(message, path, base_dir=base_dir))
    return make_document(ESLINT_TOOL_NAME, ESLINT_TOOL_ID, results, information_uri=ESLINT_INFORMATION_URI, cap=cap)


def _message_to_result(message, path, base_dir="."):
    rule_id = message.get("ruleId") or "eslint/fatal"
    return make_result(
        str(rule_id),
        _level_for_severity(message.get("severity")),
        str(message.get("message") or ""),
        path,
        line=message.get("line"),
        column=message.get("column"),
        end_line=message.get("endLine"),
        end_column=message.get("endColumn"),
        base_dir=base_dir,
    )


def _level_for_severity(severity):
    if severity in (2, "2", "error"):
        return "error"
    if severity in (1, "1", "warn", "warning"):
        return "warning"
    return "note"


def _list_or_empty(value):
    return value if isinstance(value, list) else []


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert ESLint JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    document = convert_eslint_json(load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
