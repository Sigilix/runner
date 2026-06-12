import argparse
import os
import re
import sys

from sarif_converter_common import make_document, make_result, write_json_file


TSC_TOOL_ID = "tsc"
TSC_TOOL_NAME = "TypeScript Compiler"
TSC_INFORMATION_URI = "https://www.typescriptlang.org/docs/handbook/compiler-options.html"
MAX_MESSAGE_LENGTH = 4096
DEPENDENCY_NOISE_CODES = frozenset({"TS2307", "TS2688", "TS7016"})

_DIAGNOSTIC_RE = re.compile(
    r"^(?P<path>.+)\((?P<line>[0-9]+),(?P<column>[0-9]+)\): "
    r"(?P<severity>error|warning) (?P<code>TS[0-9]+): (?P<message>.*)$"
)
_QUOTED_SPECIFIER_RE = re.compile(r"'([^']+)'")


def convert_tsc_text(text, base_dir=".", cap=None):
    results = []
    for diagnostic in _diagnostics(text):
        code = diagnostic["code"]
        if _is_dependency_noise(diagnostic):
            continue
        if not _is_inside_base_dir(diagnostic["path"], base_dir):
            continue
        results.append(
            make_result(
                f"tsc/{code}",
                _level_for_severity(diagnostic["severity"]),
                _bounded_text(diagnostic["message"], MAX_MESSAGE_LENGTH),
                diagnostic["path"],
                line=diagnostic["line"],
                column=diagnostic["column"],
                base_dir=base_dir,
            )
        )
    return make_document(TSC_TOOL_NAME, TSC_TOOL_ID, results, information_uri=TSC_INFORMATION_URI, cap=cap)


def _diagnostics(text):
    for line in str(text or "").splitlines():
        match = _DIAGNOSTIC_RE.match(line)
        if not match:
            continue
        groups = match.groupdict()
        yield {
            "path": groups["path"],
            "line": _positive_int(groups["line"]),
            "column": _positive_int(groups["column"]),
            "severity": groups["severity"],
            "code": groups["code"],
            "message": groups["message"],
        }


def _level_for_severity(severity):
    return "error" if severity == "error" else "warning"


def _is_dependency_noise(diagnostic):
    code = diagnostic["code"]
    if code not in DEPENDENCY_NOISE_CODES:
        return False
    specifier = _quoted_specifier(diagnostic["message"])
    return _looks_like_external_package(specifier)


def _quoted_specifier(message):
    match = _QUOTED_SPECIFIER_RE.search(str(message or ""))
    return match.group(1) if match else ""


def _looks_like_external_package(specifier):
    if not specifier:
        return True
    if specifier.startswith((".", "/", "#", "@/")):
        return False
    if specifier.startswith("~") and (len(specifier) == 1 or specifier[1] == "/"):
        return False
    return "/" not in specifier


def _is_inside_base_dir(path, base_dir):
    base = os.path.realpath(base_dir or ".")
    candidate = path if os.path.isabs(str(path or "")) else os.path.join(base, str(path or ""))
    candidate = os.path.realpath(candidate)
    try:
        return os.path.commonpath([base, candidate]) == base
    except ValueError:
        return False


def _positive_int(value):
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer > 0 else None


def _bounded_text(value, limit):
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert TypeScript compiler output to Sigilix SARIF.")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--cap", type=int)
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"::warning::Failed to read TypeScript output: {exc}", file=sys.stderr)
        text = ""
    document = convert_tsc_text(text, base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
