import argparse
import json
import sys

from sarif_converter_common import make_document, make_result, write_json_file


ACTIONLINT_TOOL_NAME = "actionlint"
ACTIONLINT_TOOL_ID = "actionlint"
ACTIONLINT_INFORMATION_URI = "https://github.com/rhysd/actionlint"


def convert_actionlint_json(data, base_dir=".", cap=None):
    results = []
    for error in _actionlint_errors(data):
        path = _field(error, "filepath", "Filepath") or ""
        kind = _field(error, "kind", "Kind") or "actionlint"
        message = _field(error, "message", "Message") or ""
        results.append(
            make_result(
                str(kind),
                "error",
                str(message),
                path,
                line=_field(error, "line", "Line"),
                column=_field(error, "column", "Column"),
                end_column=_field(error, "endColumn", "EndColumn"),
                base_dir=base_dir,
            )
        )
    return make_document(ACTIONLINT_TOOL_NAME, ACTIONLINT_TOOL_ID, results, information_uri=ACTIONLINT_INFORMATION_URI, cap=cap)


def _actionlint_errors(data):
    if isinstance(data, str):
        return _parse_text(data)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _parse_text(text):
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        return [parsed]

    errors = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            errors.append(item)
    return errors


def _field(mapping, *names):
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert actionlint JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            content = handle.read()
    except Exception:
        content = ""
    document = convert_actionlint_json(content, base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
