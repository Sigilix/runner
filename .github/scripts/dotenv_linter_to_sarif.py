import argparse
import re
import sys

from sarif_converter_common import make_document, make_result, write_json_file


DOTENV_LINTER_TOOL_NAME = "dotenv-linter"
DOTENV_LINTER_TOOL_ID = "dotenv-linter"
DOTENV_LINTER_INFORMATION_URI = "https://github.com/dotenv-linter/dotenv-linter"
FINDING_RE = re.compile(r"^(.+):(\d+) ([A-Za-z][A-Za-z0-9]*): (.+)$")
ASSIGNMENT_VALUE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*=)(?:\"[^\"\\]*(?:\\.[^\"\\]*)*\"|'[^']*'|`[^`]*`|[^\s]+)")
ASSIGNMENT_TAIL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*=).*", re.DOTALL)


def convert_dotenv_linter_output(text, base_dir=".", cap=None):
    results = []
    for line in str(text or "").splitlines():
        match = FINDING_RE.match(line.strip())
        if match is None:
            continue
        path, line_number, rule_id, message = match.groups()
        results.append(
            make_result(
                rule_id,
                "warning",
                _sanitize_message(message),
                path,
                line=int(line_number),
                base_dir=base_dir,
            )
        )
    return make_document(
        DOTENV_LINTER_TOOL_NAME,
        DOTENV_LINTER_TOOL_ID,
        results,
        information_uri=DOTENV_LINTER_INFORMATION_URI,
        cap=cap,
    )


def _sanitize_message(message):
    text = ASSIGNMENT_VALUE_RE.sub(r"\1[redacted]", str(message or ""))
    return ASSIGNMENT_TAIL_RE.sub(r"\1[redacted]", text)


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert dotenv-linter plain output to Sigilix SARIF.")
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
    document = convert_dotenv_linter_output(content, base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
