import argparse
import json
import sys

from sarif_converter_common import load_json_file, make_document, make_result, write_json_file


TOOL_NAMES = {
    "sqlfluff": "SQLFluff",
    "prisma-lint": "Prisma Lint",
    "rubocop": "RuboCop",
    "phpstan": "PHPStan",
    "phpmd": "PHPMD",
    "phpcs": "PHPCS",
    "clippy": "Clippy",
    "swiftlint": "SwiftLint",
}
INFORMATION_URIS = {
    "sqlfluff": "https://docs.sqlfluff.com/",
    "prisma-lint": "https://github.com/loop-payments/prisma-lint",
    "rubocop": "https://rubocop.org/",
    "phpstan": "https://phpstan.org/",
    "phpmd": "https://phpmd.org/",
    "phpcs": "https://github.com/squizlabs/PHP_CodeSniffer",
    "clippy": "https://github.com/rust-lang/rust-clippy",
    "swiftlint": "https://realm.github.io/SwiftLint/",
}


def convert_sqlfluff(data, base_dir=".", cap=None):
    results = []
    for file_entry in _list(data):
        path = str(file_entry.get("filepath") or file_entry.get("file") or "")
        for violation in _list(file_entry.get("violations")):
            results.append(
                make_result(
                    str(violation.get("code") or "sqlfluff"),
                    "warning",
                    str(violation.get("description") or violation.get("name") or ""),
                    path,
                    line=violation.get("line_no"),
                    column=violation.get("line_pos"),
                    base_dir=base_dir,
                )
            )
    return _document("sqlfluff", results, cap=cap)


def convert_prisma_lint(data, base_dir=".", cap=None):
    results = []
    for violation in _list(_dict(data).get("violations")):
        location = _dict(violation.get("location"))
        results.append(
            make_result(
                str(violation.get("ruleName") or "prisma-lint"),
                "warning",
                str(violation.get("message") or ""),
                str(violation.get("fileName") or violation.get("file") or "."),
                line=location.get("startLine"),
                column=location.get("startColumn"),
                end_line=location.get("endLine"),
                end_column=location.get("endColumn"),
                base_dir=base_dir,
            )
        )
    return _document("prisma-lint", results, cap=cap)


def convert_rubocop(data, base_dir=".", cap=None):
    results = []
    for file_entry in _list(_dict(data).get("files")):
        path = str(file_entry.get("path") or "")
        for offense in _list(file_entry.get("offenses")):
            location = _dict(offense.get("location"))
            results.append(
                make_result(
                    str(offense.get("cop_name") or "rubocop"),
                    _level(str(offense.get("severity") or "")),
                    str(offense.get("message") or ""),
                    path,
                    line=location.get("start_line") or location.get("line"),
                    column=location.get("start_column") or location.get("column"),
                    base_dir=base_dir,
                )
            )
    return _document("rubocop", results, cap=cap)


def convert_phpstan(data, base_dir=".", cap=None):
    results = []
    for path, file_entry in _dict(_dict(data).get("files")).items():
        for message in _list(_dict(file_entry).get("messages")):
            results.append(
                make_result(
                    str(message.get("identifier") or "phpstan"),
                    "warning",
                    str(message.get("message") or ""),
                    path,
                    line=message.get("line"),
                    base_dir=base_dir,
                )
            )
    return _document("phpstan", results, cap=cap)


def convert_phpcs(data, base_dir=".", cap=None):
    results = []
    for path, file_entry in _dict(_dict(data).get("files")).items():
        for message in _list(_dict(file_entry).get("messages")):
            results.append(
                make_result(
                    str(message.get("source") or "phpcs"),
                    _level(str(message.get("type") or message.get("severity") or "")),
                    str(message.get("message") or ""),
                    path,
                    line=message.get("line"),
                    column=message.get("column"),
                    base_dir=base_dir,
                )
            )
    return _document("phpcs", results, cap=cap)


def convert_phpmd(data, base_dir=".", cap=None):
    results = []
    file_entries = _dict(data).get("files") if isinstance(data, dict) else data
    for file_entry in _list(file_entries):
        if not isinstance(file_entry, dict):
            continue
        path = str(file_entry.get("file") or file_entry.get("path") or "")
        for violation in _list(file_entry.get("violations")):
            results.append(
                make_result(
                    str(violation.get("rule") or "phpmd"),
                    _phpmd_level(violation.get("priority")),
                    str(violation.get("description") or violation.get("message") or ""),
                    path,
                    line=violation.get("beginLine") or violation.get("line"),
                    end_line=violation.get("endLine"),
                    base_dir=base_dir,
                )
            )
    return _document("phpmd", results, cap=cap)


def convert_swiftlint(data, base_dir=".", cap=None):
    results = []
    for violation in _list(data):
        results.append(
            make_result(
                str(violation.get("rule_id") or violation.get("rule") or "swiftlint"),
                _level(str(violation.get("severity") or "")),
                str(violation.get("reason") or violation.get("message") or ""),
                str(violation.get("file") or "."),
                line=violation.get("line"),
                column=violation.get("character"),
                base_dir=base_dir,
            )
        )
    return _document("swiftlint", results, cap=cap)


def convert_clippy_json_lines(text, base_dir=".", cap=None):
    results = []
    for line_number, line in enumerate(str(text or "").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"invalid Clippy JSON on line {line_number}") from err
        if _dict(entry).get("reason") != "compiler-message":
            continue
        message = _dict(entry.get("message"))
        if not message:
            continue
        span = _primary_span(message)
        if not span.get("file_name"):
            continue
        code = _dict(message.get("code"))
        results.append(
            make_result(
                str(code.get("code") or "clippy"),
                _level(str(message.get("level") or "")),
                str(message.get("message") or ""),
                str(span.get("file_name") or "."),
                line=span.get("line_start"),
                column=span.get("column_start"),
                end_line=span.get("line_end"),
                end_column=span.get("column_end"),
                base_dir=base_dir,
            )
        )
    return _document("clippy", results, cap=cap)


def _primary_span(message):
    spans = _list(message.get("spans"))
    for span in spans:
        if span.get("is_primary") is True:
            return span
    return spans[0] if spans else {}


def _document(tool_id, results, cap=None):
    return make_document(TOOL_NAMES[tool_id], tool_id, results, information_uri=INFORMATION_URIS[tool_id], cap=cap)


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _level(value):
    value = value.lower()
    if value in {"error", "fatal"}:
        return "error"
    if value in {"info", "note", "refactor", "convention"}:
        return "note"
    return "warning"


def _phpmd_level(priority):
    if isinstance(priority, int) and priority <= 2:
        return "error"
    return "warning"


CONVERTERS = {
    "sqlfluff": convert_sqlfluff,
    "prisma-lint": convert_prisma_lint,
    "rubocop": convert_rubocop,
    "phpstan": convert_phpstan,
    "phpmd": convert_phpmd,
    "phpcs": convert_phpcs,
    "swiftlint": convert_swiftlint,
}


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert high-impact language tool output to Sigilix SARIF.")
    parser.add_argument("tool", choices=sorted([*CONVERTERS.keys(), "clippy"]))
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    try:
        if args.tool == "clippy":
            with open(args.input, encoding="utf-8") as handle:
                document = convert_clippy_json_lines(handle.read(), base_dir=args.base_dir, cap=args.cap)
        else:
            document = CONVERTERS[args.tool](load_json_file(args.input), base_dir=args.base_dir, cap=args.cap)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 1
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
