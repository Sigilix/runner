import argparse
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


SHELLCHECK_TOOL_NAME = "ShellCheck"
SHELLCHECK_TOOL_ID = "shellcheck"
SHELLCHECK_INFORMATION_URI = "https://www.shellcheck.net/"


def convert_shellcheck_json(data, base_dir=".", cap=None):
    results = []
    for comment in _comments(data):
        results.append(
            make_result(
                _rule_id(comment.get("code")),
                _level_for_shellcheck(comment.get("level")),
                str(comment.get("message") or ""),
                comment.get("file") or "",
                line=comment.get("line"),
                column=comment.get("column"),
                end_line=comment.get("endLine"),
                end_column=comment.get("endColumn"),
                base_dir=base_dir,
            )
        )
    return make_document(SHELLCHECK_TOOL_NAME, SHELLCHECK_TOOL_ID, results, information_uri=SHELLCHECK_INFORMATION_URI, cap=cap)


def _comments(data):
    if isinstance(data, dict):
        comments = data.get("comments")
        return [comment for comment in comments if isinstance(comment, dict)] if isinstance(comments, list) else []
    if isinstance(data, list):
        return [comment for comment in data if isinstance(comment, dict)]
    return []


def _rule_id(code):
    text = str(code or "").strip()
    if text.upper().startswith("SC"):
        return text.upper()
    if text.isdigit():
        return f"SC{text}"
    return "shellcheck"


def _level_for_shellcheck(level):
    normalized = str(level or "").lower()
    if normalized == "error":
        return "error"
    if normalized == "warning":
        return "warning"
    return "note"


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert ShellCheck JSON output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    document = convert_shellcheck_json(load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
