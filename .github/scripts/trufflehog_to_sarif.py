import argparse
import json
import sys

from sarif_converter_common import make_document, make_result, write_json_file


TRUFFLEHOG_TOOL_NAME = "TruffleHog"
TRUFFLEHOG_TOOL_ID = "trufflehog"
TRUFFLEHOG_INFORMATION_URI = "https://github.com/trufflesecurity/trufflehog"


def convert_trufflehog_json(data, base_dir=".", cap=None):
    results = []
    for index, finding in enumerate(_findings(data)):
        dedupe_discriminator = index if _has_secret_payload(finding) else None
        finding = _without_secret_values(finding)
        rule_id = str(finding.get("DetectorName") or finding.get("DetectorType") or "trufflehog")
        path, line = _source_location(finding)
        verified = _is_verified(finding.get("Verified"))
        result = make_result(
            rule_id,
            "error" if verified else "warning",
            _message(rule_id),
            path,
            line=line,
            base_dir=base_dir,
        )
        result["properties"] = {"trufflehogVerified": verified}
        results.append((result, dedupe_discriminator))
    return make_document(
        TRUFFLEHOG_TOOL_NAME,
        TRUFFLEHOG_TOOL_ID,
        _dedupe_results(results),
        information_uri=TRUFFLEHOG_INFORMATION_URI,
        cap=cap,
    )


def _findings(data):
    if isinstance(data, str):
        return _parse_text(data)
    if isinstance(data, list):
        return _dict_items(data)
    if isinstance(data, dict):
        return [data]
    return []


def _parse_text(text):
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return _dict_items(parsed)
    if isinstance(parsed, dict):
        return [parsed]

    findings = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            print("::warning::trufflehog_to_sarif skipped a malformed JSON line.", file=sys.stderr)
            continue
        if isinstance(item, dict):
            findings.append(item)
        else:
            print("::warning::trufflehog_to_sarif skipped a non-object JSON line.", file=sys.stderr)
    return findings


def _message(rule_id):
    return f"TruffleHog found {rule_id} secret"


def _dedupe_results(results):
    deduped = {}
    for result, dedupe_discriminator in results:
        key = _dedupe_key(result, dedupe_discriminator)
        existing = deduped.get(key)
        if existing is None or (existing.get("level") != "error" and result.get("level") == "error"):
            deduped[key] = result
    return list(deduped.values())


def _dedupe_key(result, dedupe_discriminator):
    physical = result["locations"][0]["physicalLocation"]
    artifact = physical["artifactLocation"]
    region = physical.get("region") or {}
    return (result.get("ruleId"), artifact.get("uri"), region.get("startLine"), dedupe_discriminator)


def _has_secret_payload(finding):
    for key in ("Raw", "RawV2", "Redacted", "ExtraData", "StructuredData"):
        if _has_payload_value(finding.get(key)):
            return True
    return False


def _has_payload_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(_has_payload_value(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_payload_value(child) for child in value)
    return True


def _is_verified(value):
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return value == True


def _without_secret_values(finding):
    sanitized = dict(finding)
    for key in ("Raw", "RawV2", "Redacted", "ExtraData", "StructuredData"):
        sanitized.pop(key, None)
    return sanitized


def _dict_items(items):
    findings = []
    for item in items:
        if isinstance(item, dict):
            findings.append(item)
        else:
            print("::warning::trufflehog_to_sarif skipped a non-object JSON item.", file=sys.stderr)
    return findings


def _source_location(finding):
    metadata = finding.get("SourceMetadata")
    data = metadata.get("Data") if isinstance(metadata, dict) else None
    if isinstance(data, dict):
        for source_name in ("Filesystem", "Git"):
            source = data.get(source_name)
            if not isinstance(source, dict):
                continue
            path = _first_direct_value(source, ("file", "path", "filename", "File", "Path"))
            line = _first_direct_value(source, ("line", "lineNumber", "Line", "LineNumber"))
            if path not in (None, "") or line not in (None, ""):
                return path or ".", line
    path = _first_nested_value(data, ("file", "path", "filename", "File", "Path")) or "."
    line = _first_nested_value(data, ("line", "lineNumber", "Line", "LineNumber"))
    return path, line


def _first_direct_value(value, keys):
    for key in keys:
        if key in value and value[key] not in (None, ""):
            return value[key]
    return None


def _first_nested_value(value, keys):
    if isinstance(value, dict):
        for key in keys:
            if key in value and value[key] not in (None, ""):
                return value[key]
        for child in value.values():
            found = _first_nested_value(child, keys)
            if found not in (None, ""):
                return found
    if isinstance(value, list):
        for child in value:
            found = _first_nested_value(child, keys)
            if found not in (None, ""):
                return found
    return None


def _main(argv):
    parser = argparse.ArgumentParser(description="Convert TruffleHog JSON output to Sigilix SARIF.")
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
    document = convert_trufflehog_json(content, base_dir=args.base_dir, cap=args.cap)
    write_json_file(args.output, document)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
