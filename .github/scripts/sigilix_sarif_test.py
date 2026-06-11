import json
import os
import tempfile
import unittest

from sigilix_sarif_contract import (
    SIGILIX_SCHEMA_VERSION,
    SIGILIX_SOURCE,
    _main as contract_main,
    attach_sigilix_metadata,
    cap_results,
)
from sigilix_sarif_merge import merge_sarif_documents
from actionlint_to_sarif import convert_actionlint_json
from eslint_to_sarif import convert_eslint_json
from shellcheck_to_sarif import convert_shellcheck_json


def make_result(level, path, line, rule_id, message):
    return {
        "level": level,
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }


class SigilixSarifContractTest(unittest.TestCase):
    def test_metadata_attachment_has_exact_keys_without_role_hints(self):
        run = {"tool": {"driver": {"name": "Semgrep"}}}

        returned = attach_sigilix_metadata(run, "semgrep", dropped_results={"droppedCount": 2, "keptCount": 1})

        self.assertIs(returned, run)
        properties = run["tool"]["driver"]["properties"]
        self.assertEqual(
            properties,
            {
                "sigilixSchemaVersion": SIGILIX_SCHEMA_VERSION,
                "sigilixToolId": "semgrep",
                "sigilixSource": SIGILIX_SOURCE,
                "sigilixDroppedResults": {"droppedCount": 2, "keptCount": 1},
            },
        )
        self.assertNotIn("sigilixRoleHints", properties)

    def test_unknown_tool_id_is_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "bandit")

    def test_old_dropped_summary_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results={"dropped": 1, "kept": 2})

    def test_dropped_summary_extra_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": 1, "toolId": "semgrep"})

    def test_dropped_summary_non_dict_is_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results="droppedCount")

    def test_dropped_summary_bool_values_are_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": True})

    def test_dropped_summary_float_values_are_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": 1.5})

    def test_dropped_summary_negative_values_are_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": 1, "keptCount": -1})

    def test_dropped_summary_non_finite_values_are_rejected(self):
        with self.assertRaises(ValueError):
            attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": float("inf")})

    def test_dropped_summary_accepts_exact_dropped_count_key(self):
        run = attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": 1})

        self.assertEqual(run["tool"]["driver"]["properties"]["sigilixDroppedResults"], {"droppedCount": 1})

    def test_dropped_summary_accepts_exact_dropped_and_kept_count_keys(self):
        run = attach_sigilix_metadata({}, "semgrep", dropped_results={"droppedCount": 1, "keptCount": 2})

        self.assertEqual(
            run["tool"]["driver"]["properties"]["sigilixDroppedResults"],
            {"droppedCount": 1, "keptCount": 2},
        )

    def test_cap_keeps_errors_before_warnings_and_notes_with_summary(self):
        results = [
            make_result("note", "a.py", 1, "N", "note"),
            make_result("warning", "a.py", 1, "W", "warning"),
            make_result("error", "a.py", 1, "E", "error"),
        ]

        kept, summary = cap_results(results, 2)

        self.assertEqual([result["ruleId"] for result in kept], ["E", "W"])
        self.assertEqual(summary, {"droppedCount": 1, "keptCount": 2})

    def test_cap_tie_break_is_stable_by_path_line_rule_and_message(self):
        results = [
            make_result("warning", "b.py", 1, "A", "aaa"),
            make_result("warning", "a.py", 2, "A", "aaa"),
            make_result("warning", "a.py", 1, "B", "aaa"),
            make_result("warning", "a.py", 1, "A", "bbb"),
            make_result("warning", "a.py", 1, "A", "aaa"),
        ]

        kept, summary = cap_results(results, 4)

        self.assertEqual(
            [(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], r["locations"][0]["physicalLocation"]["region"]["startLine"], r["ruleId"], r["message"]["text"]) for r in kept],
            [
                ("a.py", 1, "A", "aaa"),
                ("a.py", 1, "A", "bbb"),
                ("a.py", 1, "B", "aaa"),
                ("a.py", 2, "A", "aaa"),
            ],
        )
        self.assertEqual(summary, {"droppedCount": 1, "keptCount": 4})

    def test_under_cap_preserves_all_results_and_returns_no_summary(self):
        results = [
            make_result("note", "b.py", 2, "N", "note"),
            make_result("error", "a.py", 1, "E", "error"),
        ]

        kept, summary = cap_results(results, 3)

        self.assertEqual(kept, results)
        self.assertIsNone(summary)


class SigilixSarifContractCliTest(unittest.TestCase):
    def run_contract_cli(self, content):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.sarif")
            output_path = os.path.join(tmpdir, "output.sarif")
            with open(input_path, "w", encoding="utf-8") as handle:
                if isinstance(content, str):
                    handle.write(content)
                else:
                    json.dump(content, handle)

            exit_code = contract_main(["semgrep", input_path, output_path])

            with open(output_path, "r", encoding="utf-8") as handle:
                output = json.load(handle)
        return exit_code, output

    def run_contract_cli_with_args(self, content, extra_args):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.sarif")
            output_path = os.path.join(tmpdir, "output.sarif")
            with open(input_path, "w", encoding="utf-8") as handle:
                if isinstance(content, str):
                    handle.write(content)
                else:
                    json.dump(content, handle)

            exit_code = contract_main(["semgrep", input_path, output_path, *extra_args])

            with open(output_path, "r", encoding="utf-8") as handle:
                output = json.load(handle)
        return exit_code, output

    def test_cli_treats_malformed_json_as_empty_sarif(self):
        exit_code, output = self.run_contract_cli("{")

        self.assertEqual(exit_code, 0)
        self.assertEqual(output, {"version": "2.1.0", "runs": []})

    def test_cli_can_ensure_empty_metadata_run(self):
        exit_code, output = self.run_contract_cli_with_args("{", ["--ensure-run"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(output["runs"]), 1)
        self.assertEqual(output["runs"][0]["tool"]["driver"]["name"], "Semgrep")
        self.assertEqual(output["runs"][0]["results"], [])
        self.assertEqual(output["runs"][0]["tool"]["driver"]["properties"]["sigilixToolId"], "semgrep")

    def test_cli_treats_top_level_array_as_empty_sarif(self):
        exit_code, output = self.run_contract_cli([])

        self.assertEqual(exit_code, 0)
        self.assertEqual(output, {"version": "2.1.0", "runs": []})

    def test_cli_treats_non_list_runs_as_empty_runs(self):
        exit_code, output = self.run_contract_cli({"runs": {"bad": True}})

        self.assertEqual(exit_code, 0)
        self.assertEqual(output, {"version": "2.1.0", "runs": []})

    def test_cli_normalizes_invalid_version_with_non_list_runs(self):
        exit_code, output = self.run_contract_cli({"version": 123, "runs": {"bad": True}})

        self.assertEqual(exit_code, 0)
        self.assertEqual(output, {"version": "2.1.0", "runs": []})

    def test_cli_normalizes_malformed_tool_driver_and_properties(self):
        exit_code, output = self.run_contract_cli(
            {
                "version": "2.1.0",
                "runs": [
                    {"tool": "bad"},
                    {"tool": {"driver": "bad"}},
                    {"tool": {"driver": {"properties": "bad"}}},
                    "not-a-run",
                ],
            }
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(output["runs"]), 3)
        for run in output["runs"]:
            self.assertEqual(
                run["tool"]["driver"]["properties"],
                {
                    "sigilixSchemaVersion": SIGILIX_SCHEMA_VERSION,
                    "sigilixToolId": "semgrep",
                    "sigilixSource": SIGILIX_SOURCE,
                },
            )
            self.assertEqual(run["tool"]["driver"]["name"], "Semgrep")

    def test_cli_drops_non_dict_result_entries(self):
        exit_code, output = self.run_contract_cli(
            {"version": "2.1.0", "runs": [{"results": ["bad-result", {"message": {"text": "ok"}}, None]}]}
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(output["version"], "2.1.0")
        self.assertEqual(output["runs"][0]["results"], [{"message": {"text": "ok"}}])


class SigilixSarifMergeTest(unittest.TestCase):
    def write_file(self, directory, name, content):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            if isinstance(content, str):
                handle.write(content)
            else:
                json.dump(content, handle)
        return path

    def test_merge_concatenates_runs_and_treats_bad_inputs_as_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self.write_file(tmpdir, "first.sarif", {"version": "2.1.0", "runs": [{"id": "one"}]})
            second = self.write_file(
                tmpdir,
                "second.sarif",
                {"version": "2.1.0", "$schema": "schema", "runs": ["bad-run", {"id": "two"}]},
            )
            malformed = self.write_file(tmpdir, "bad.sarif", "{")
            missing = os.path.join(tmpdir, "missing.sarif")
            non_object = self.write_file(tmpdir, "array.sarif", [])

            merged, summary = merge_sarif_documents([first, malformed, missing, non_object, second])

        self.assertEqual(merged["version"], "2.1.0")
        self.assertEqual(merged["runs"], [{"id": "one"}, {"id": "two"}])
        self.assertIsNone(summary)

    def test_merge_byte_cap_preserves_earlier_runs_and_reports_dropped_later_runs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self.write_file(tmpdir, "first.sarif", {"version": "2.1.0", "runs": [{"id": "one"}]})
            second = self.write_file(tmpdir, "second.sarif", {"version": "2.1.0", "runs": [{"id": "two", "payload": "x" * 200}]})

            merged, summary = merge_sarif_documents([first, second], byte_cap=120)

        self.assertEqual(merged["runs"], [{"id": "one"}])
        self.assertEqual(summary, {"droppedRuns": 1, "keptRuns": 1, "reason": "byte-cap"})

    def test_merge_byte_cap_drops_all_runs_when_first_run_is_oversized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self.write_file(tmpdir, "first.sarif", {"version": "2.1.0", "runs": [{"id": "one", "payload": "x" * 200}]})
            second = self.write_file(tmpdir, "second.sarif", {"version": "2.1.0", "runs": [{"id": "two"}]})

            merged, summary = merge_sarif_documents([first, second], byte_cap=80)

        self.assertEqual(merged["runs"], [])
        self.assertEqual(summary, {"droppedRuns": 2, "keptRuns": 0, "reason": "byte-cap"})

    def test_merge_byte_cap_discards_oversized_base_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self.write_file(
                tmpdir,
                "first.sarif",
                {"version": "2.1.0", "$schema": "x" * 500, "runs": [{"id": "one"}]},
            )

            merged, summary = merge_sarif_documents([first], byte_cap=80)

        self.assertNotIn("$schema", merged)
        self.assertEqual(merged["runs"], [{"id": "one"}])
        self.assertLessEqual(len(json.dumps(merged, separators=(",", ":")).encode("utf-8")), 80)
        self.assertIsNone(summary)


class ConverterTest(unittest.TestCase):
    def assert_sigilix_properties(self, document, tool_id):
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        properties = document["runs"][0]["tool"]["driver"]["properties"]
        self.assertEqual(properties["sigilixSchemaVersion"], SIGILIX_SCHEMA_VERSION)
        self.assertEqual(properties["sigilixToolId"], tool_id)
        self.assertEqual(properties["sigilixSource"], SIGILIX_SOURCE)
        self.assertNotIn("sigilixRoleHints", properties)

    def test_eslint_json_converts_messages_to_sarif_with_metadata(self):
        document = convert_eslint_json(
            [
                {
                    "filePath": "/repo/src/app.js",
                    "messages": [
                        {
                            "ruleId": "no-undef",
                            "severity": 2,
                            "message": "'foo' is not defined.",
                            "line": 3,
                            "column": 5,
                            "endLine": 3,
                            "endColumn": 8,
                        }
                    ],
                }
            ],
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "eslint")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "no-undef")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["message"], {"text": "'foo' is not defined."})
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/app.js")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startColumn"], 5)

    def test_actionlint_json_array_and_json_lines_convert_to_sarif(self):
        array_document = convert_actionlint_json(
            [
                {
                    "message": "property \"branch\" is not defined",
                    "kind": "syntax-check",
                    "filepath": ".github/workflows/ci.yml",
                    "line": 10,
                    "column": 7,
                    "endColumn": 13,
                }
            ]
        )
        lines_document = convert_actionlint_json(
            '{"message":"bad expression","kind":"expression","filepath":".github/workflows/test.yml","line":4,"column":12}\n'
        )

        self.assert_sigilix_properties(array_document, "actionlint")
        self.assertEqual(array_document["runs"][0]["results"][0]["ruleId"], "syntax-check")
        self.assertEqual(array_document["runs"][0]["results"][0]["level"], "error")
        self.assertEqual(
            array_document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".github/workflows/ci.yml",
        )
        self.assert_sigilix_properties(lines_document, "actionlint")
        self.assertEqual(lines_document["runs"][0]["results"][0]["ruleId"], "expression")

    def test_shellcheck_json1_and_legacy_array_convert_to_sarif(self):
        json1_document = convert_shellcheck_json(
            {
                "comments": [
                    {
                        "file": "scripts/build.sh",
                        "line": 8,
                        "column": 3,
                        "endLine": 8,
                        "endColumn": 12,
                        "level": "warning",
                        "code": 2086,
                        "message": "Double quote to prevent globbing and word splitting.",
                    }
                ]
            }
        )
        legacy_document = convert_shellcheck_json(
            [
                {
                    "file": "script.sh",
                    "line": 2,
                    "column": 1,
                    "level": "style",
                    "code": 2148,
                    "message": "Tips depend on target shell and yours is unknown.",
                }
            ]
        )

        self.assert_sigilix_properties(json1_document, "shellcheck")
        result = json1_document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "SC2086")
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "scripts/build.sh")
        self.assert_sigilix_properties(legacy_document, "shellcheck")
        self.assertEqual(legacy_document["runs"][0]["results"][0]["level"], "note")


if __name__ == "__main__":
    unittest.main()
