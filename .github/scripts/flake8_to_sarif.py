import argparse
import re
import sys

from sarif_converter_common import make_document, make_result, write_json_file


FLAKE8_TOOL_ID = "flake8"
FLAKE8_TOOL_NAME = "Flake8"
FLAKE8_INFORMATION_URI = "https://flake8.pycqa.org/"

_LINE_RE = re.compile(r"^(?P<path>.+):(?P<line>\d+):(?P<column>\d+): (?P<code>[A-Z]\d{3}) (?P<message>.*)$")


def convert_flake8_output(text, base_dir=".", cap=None):
    results = []
    for line in str(text or "").splitlines():
        match = _LINE_RE.match(line)
        if not match:
            continue
        results.append(
            make_result(
                match.group("code"),
                _level_for_code(match.group("code")),
                match.group("message"),
                match.group("path"),
                line=_int_or_none(match.group("line")),
                column=_int_or_none(match.group("column")),
                base_dir=base_dir,
            )
        )
    return make_document(FLAKE8_TOOL_NAME, FLAKE8_TOOL_ID, results, information_uri=FLAKE8_INFORMATION_URI, cap=cap)


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _level_for_code(code):
    return "error" if str(code or "").startswith("E9") else "warning"


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert Flake8 text output to Sigilix SARIF.")
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
    document = convert_flake8_output(content, base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
