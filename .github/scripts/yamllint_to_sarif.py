import argparse
import re
import sys

from sarif_converter_common import make_document, make_result, write_json_file


YAMLLINT_TOOL_NAME = "YAMLlint"
YAMLLINT_TOOL_ID = "yamllint"
YAMLLINT_INFORMATION_URI = "https://yamllint.readthedocs.io/"
PARSABLE_RE = re.compile(r"^(.+):(\d+):(\d+): \[(error|warning)\] (.+)$")
RULE_RE = re.compile(r"^(.*) \(([^()]+)\)$")


def convert_yamllint_output(text, base_dir=".", cap=None):
    results = []
    for line in str(text or "").splitlines():
        result = _parse_line(line, base_dir=base_dir)
        if result is not None:
            results.append(result)
    return make_document(YAMLLINT_TOOL_NAME, YAMLLINT_TOOL_ID, results, information_uri=YAMLLINT_INFORMATION_URI, cap=cap)


def _parse_line(line, base_dir="."):
    match = PARSABLE_RE.match(line)
    if match is None:
        return None

    path, line_number, column, level, message = match.groups()
    rule_id = "yamllint"
    rule_match = RULE_RE.match(message)
    if rule_match is not None:
        message, rule_id = rule_match.groups()
    return make_result(rule_id, level, message, path, line=int(line_number), column=int(column), base_dir=base_dir)


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert YAMLlint parsable output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            content = handle.read()
    except Exception as err:
        print(f"::warning::failed to read yamllint output file {args.input}: {err}", file=sys.stderr)
        content = ""
    document = convert_yamllint_output(content, base_dir=args.base_dir, cap=args.cap)
    if content.strip() and not document["runs"][0]["results"]:
        print(f"::warning::yamllint output file {args.input} contained no parsable results", file=sys.stderr)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
