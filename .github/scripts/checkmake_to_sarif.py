import argparse
import json
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


CHECKMAKE_TOOL_NAME = "checkmake"
CHECKMAKE_TOOL_ID = "checkmake"
CHECKMAKE_INFORMATION_URI = "https://github.com/checkmake/checkmake"


def convert_checkmake_json(data, base_dir=".", cap=None):
    results = []
    for item in _findings(data):
        results.append(
            make_result(
                str(item.get("rule") or "checkmake"),
                "warning",
                str(item.get("violation") or ""),
                item.get("file_name") or "",
                line=item.get("line_number"),
                base_dir=base_dir,
            )
        )
    return make_document(
        CHECKMAKE_TOOL_NAME,
        CHECKMAKE_TOOL_ID,
        results,
        information_uri=CHECKMAKE_INFORMATION_URI,
        cap=cap,
    )


def _findings(data):
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    if isinstance(data, str):
        return _parse_text(data)
    return []


def _parse_text(text):
    findings = []
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            newline = text.find("\n", index)
            if newline == -1:
                break
            index = newline + 1
            continue
        findings.extend(_findings(value))
    return findings


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert checkmake JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    data = load_json_file(args.input)
    if data is None:
        try:
            with open(args.input, "r", encoding="utf-8") as handle:
                data = handle.read()
        except Exception:
            data = ""
    document = convert_checkmake_json(data, base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
