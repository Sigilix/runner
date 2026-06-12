import argparse
import json
import sys

from sarif_converter_common import make_document, make_result, write_json_file


BUF_TOOL_ID = "buf"
BUF_TOOL_NAME = "Buf"
BUF_INFORMATION_URI = "https://buf.build/docs/lint/"


def convert_buf_json_lines(text, base_dir=".", cap=None):
    results = []
    for line_number, line in enumerate(str(text or "").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid Buf JSON on line {line_number}") from err
        if not isinstance(entry, dict):
            raise ValueError(f"invalid Buf JSON on line {line_number}")
        results.append(_entry_to_result(entry, base_dir=base_dir))
    return make_document(BUF_TOOL_NAME, BUF_TOOL_ID, results, information_uri=BUF_INFORMATION_URI, cap=cap)


def _entry_to_result(entry, base_dir="."):
    rule_id = str(entry.get("type") or "buf").strip() or "buf"
    message = str(entry.get("message") or rule_id)
    return make_result(
        rule_id,
        "warning",
        message,
        str(entry.get("path") or "."),
        line=entry.get("start_line"),
        column=entry.get("start_column"),
        end_line=entry.get("end_line"),
        end_column=entry.get("end_column"),
        base_dir=base_dir,
    )


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert Buf JSON-lines lint output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    try:
        with open(args.input, encoding="utf-8") as handle:
            content = handle.read()
    except OSError:
        content = ""
    try:
        document = convert_buf_json_lines(content, base_dir=args.base_dir, cap=args.cap)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 1
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
