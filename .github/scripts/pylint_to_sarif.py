import argparse
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


PYLINT_TOOL_ID = "pylint"
PYLINT_TOOL_NAME = "Pylint"
PYLINT_INFORMATION_URI = "https://pylint.pycqa.org/"
MAX_RULE_ID_LENGTH = 256
MAX_MESSAGE_LENGTH = 4096

_LEVELS = {
    "fatal": "error",
    "error": "error",
    "warning": "warning",
    "refactor": "note",
    "convention": "note",
    "info": "note",
}


def convert_pylint_json(data, base_dir=".", cap=None):
    results = []
    for message in _list_or_empty(data):
        if not isinstance(message, dict):
            continue
        results.append(_message_to_result(message, base_dir=base_dir))
    return make_document(PYLINT_TOOL_NAME, PYLINT_TOOL_ID, results, information_uri=PYLINT_INFORMATION_URI, cap=cap)


def _message_to_result(message, base_dir="."):
    message_id = _bounded_text(message.get("message-id"), "pylint", MAX_RULE_ID_LENGTH)
    symbol = _bounded_text(message.get("symbol"), "", MAX_RULE_ID_LENGTH)
    rule_id = _bounded_text(f"{message_id}/{symbol}" if symbol else message_id, "pylint", MAX_RULE_ID_LENGTH)
    return make_result(
        rule_id,
        _LEVELS.get(str(message.get("type") or "").lower(), "warning"),
        _bounded_text(message.get("message"), "", MAX_MESSAGE_LENGTH),
        str(message.get("path") or ""),
        line=message.get("line"),
        column=_one_based(message.get("column")),
        end_line=message.get("endLine"),
        end_column=_one_based(message.get("endColumn")),
        base_dir=base_dir,
    )


def _one_based(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value + 1


def _list_or_empty(value):
    return value if isinstance(value, list) else []


def _bounded_text(value, default, limit):
    text = str(value or default).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert Pylint JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    document = convert_pylint_json(load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
