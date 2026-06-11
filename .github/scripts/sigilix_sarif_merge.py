import argparse
import json
import sys


EMPTY_SARIF = {"version": "2.1.0", "runs": []}


def load_sarif_document(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except Exception:
        return dict(EMPTY_SARIF)
    if not isinstance(document, dict):
        return dict(EMPTY_SARIF)
    if not isinstance(document.get("runs"), list):
        document = dict(document)
        document["runs"] = []
    return document


def _encoded_size(document):
    return len(json.dumps(document, separators=(",", ":")).encode("utf-8"))


def _base_document(documents):
    for document in documents:
        if isinstance(document, dict):
            base = {"version": document.get("version") or "2.1.0"}
            if isinstance(document.get("$schema"), str):
                base["$schema"] = document["$schema"]
            base["runs"] = []
            return base
    return dict(EMPTY_SARIF)


def _fit_runs(base, runs, byte_cap):
    merged = dict(base)
    kept_runs = []
    dropped_runs = 0

    for run in runs:
        candidate_runs = kept_runs + [run]
        candidate = dict(base)
        candidate["runs"] = candidate_runs
        if _encoded_size(candidate) <= byte_cap:
            kept_runs = candidate_runs
        else:
            dropped_runs += 1

    merged["runs"] = kept_runs
    if dropped_runs:
        return merged, {"droppedRuns": dropped_runs, "keptRuns": len(kept_runs), "reason": "byte-cap"}
    return merged, None


def merge_sarif_documents(paths, byte_cap=None):
    documents = [load_sarif_document(path) for path in paths]
    base = _base_document(documents)
    runs = []
    for document in documents:
        document_runs = document.get("runs")
        if isinstance(document_runs, list):
            runs.extend(document_runs)

    merged = dict(base)
    merged["runs"] = runs
    if byte_cap is None or _encoded_size(merged) <= byte_cap:
        return merged, None
    return _fit_runs(base, runs, byte_cap)


def write_merged_sarif(paths, output_path, byte_cap=None):
    merged, summary = merge_sarif_documents(paths, byte_cap=byte_cap)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(merged, handle, separators=(",", ":"))
    return merged, summary


def _main(argv):
    parser = argparse.ArgumentParser(description="Merge SARIF documents.")
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--byte-cap", type=int)
    args = parser.parse_args(argv)

    _, summary = write_merged_sarif(args.inputs, args.output, byte_cap=args.byte_cap)
    if summary is not None:
        print(
            "::warning::SARIF merge byte cap dropped "
            f"{summary['droppedRuns']} later run(s); kept {summary['keptRuns']} run(s).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
