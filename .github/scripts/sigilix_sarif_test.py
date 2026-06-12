import contextlib
import io
import json
import os
import re
import tempfile
import unittest

from sigilix_sarif_contract import (
    KNOWN_TOOL_IDS,
    SIGILIX_SCHEMA_VERSION,
    SIGILIX_SOURCE,
    _main as contract_main,
    attach_sigilix_metadata,
    cap_results,
)
from sigilix_sarif_merge import _main as sarif_merge_main
from sigilix_sarif_merge import merge_sarif_documents
from actionlint_to_sarif import convert_actionlint_json
from eslint_to_sarif import convert_eslint_json
from sarif_converter_common import normalize_path
from shellcheck_to_sarif import convert_shellcheck_json
from sigilix_scan_manifest import _main as scan_manifest_main
from sigilix_scan_manifest import build_scan_manifest
from sigilix_tool_manifest import (
    load_tool_manifest,
    manifest_sarif_paths,
    manifest_tool_specs,
    validate_tool_manifest,
)


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

    def test_contract_accepts_legacy_and_next_batch_tool_ids(self):
        for tool_id, expected_name in (
            ("gitleaks", "gitleaks"),
            ("osv-scanner", "OSV-Scanner"),
            ("checkov", "Checkov"),
            ("trivy", "Trivy"),
            ("trufflehog", "TruffleHog"),
            ("zizmor", "zizmor"),
            ("hadolint", "Hadolint"),
            ("tflint", "TFLint"),
            ("biome", "Biome"),
            ("oxlint", "Oxlint"),
            ("ast-grep", "ast-grep"),
        ):
            run = attach_sigilix_metadata({}, tool_id)
            driver = run["tool"]["driver"]
            self.assertEqual(driver["name"], expected_name)
            self.assertEqual(driver["properties"]["sigilixToolId"], tool_id)

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

    def test_merge_cli_requires_manifest_and_sarif_dir_together(self):
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            code = sarif_merge_main(["--tool-manifest", "tool-manifest.json", "-o", "sarif.json"])

        self.assertEqual(code, 2)
        self.assertIn("--tool-manifest and --sarif-dir must be used together", stderr.getvalue())


class SigilixScanManifestTest(unittest.TestCase):
    def write_json(self, directory, name, content):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(content, handle)
        return path

    def test_manifest_distinguishes_disabled_missing_invalid_empty_and_produced_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty = self.write_json(tmpdir, "empty.sarif", {"version": "2.1.0", "runs": []})
            produced = self.write_json(
                tmpdir,
                "produced.sarif",
                {"version": "2.1.0", "runs": [{"results": [{"ruleId": "X"}, {"ruleId": "Y"}]}]},
            )
            invalid = self.write_json(tmpdir, "invalid.sarif", [])
            missing = os.path.join(tmpdir, "missing.sarif")

            manifest = build_scan_manifest(
                [
                    ("eslint", True, empty),
                    ("semgrep", True, produced),
                    ("ruff", True, invalid),
                    ("shellcheck", True, missing),
                    ("actionlint", False, missing),
                ]
            )

        by_tool = {tool["toolId"]: tool for tool in manifest["tools"]}
        self.assertEqual(by_tool["eslint"]["status"], "empty")
        self.assertEqual(by_tool["eslint"]["runCount"], 0)
        self.assertEqual(by_tool["semgrep"]["status"], "produced")
        self.assertEqual(by_tool["semgrep"]["runCount"], 1)
        self.assertEqual(by_tool["semgrep"]["resultCount"], 2)
        self.assertEqual(by_tool["ruff"]["status"], "invalid-output")
        self.assertEqual(by_tool["shellcheck"]["status"], "missing-output")
        self.assertEqual(by_tool["actionlint"]["status"], "disabled")
        self.assertEqual(manifest["summary"], {"enabled": 4, "produced": 1, "empty": 1, "missing": 1, "invalid": 1})

    def test_manifest_rejects_unknown_tool_ids(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty = self.write_json(tmpdir, "empty.sarif", {"version": "2.1.0", "runs": []})

            with self.assertRaises(ValueError):
                build_scan_manifest([("bandit", True, empty)])

    def test_manifest_rejects_duplicate_tool_ids(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty = self.write_json(tmpdir, "empty.sarif", {"version": "2.1.0", "runs": []})

            with self.assertRaises(ValueError):
                build_scan_manifest([("semgrep", True, empty), ("semgrep", False, "")])

    def test_manifest_rejects_more_specs_than_known_tools(self):
        with self.assertRaises(ValueError):
            build_scan_manifest([("semgrep", False, "")] * (len(KNOWN_TOOL_IDS) + 1))

    def test_manifest_cli_requires_manifest_and_sarif_dir_together(self):
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            code = scan_manifest_main(["--tool-manifest", "tool-manifest.json", "-o", "scan-manifest.json"])

        self.assertEqual(code, 2)
        self.assertIn("--tool-manifest and --sarif-dir must be used together", stderr.getvalue())

    def test_manifest_treats_non_object_sarif_runs_as_invalid_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            invalid = self.write_json(tmpdir, "invalid.sarif", {"version": "2.1.0", "runs": [None]})

            manifest = build_scan_manifest([("semgrep", True, invalid)])

        self.assertEqual(manifest["tools"][0]["status"], "invalid-output")
        self.assertEqual(manifest["summary"], {"enabled": 1, "produced": 0, "empty": 0, "missing": 0, "invalid": 1})

    def test_manifest_records_missing_outputs_for_enabled_tools(self):
        expected_outputs = {
            **NEXT_BATCH_TOOL_OUTPUTS,
            **LANGUAGE_SARIF_TOOL_OUTPUTS,
            **CONFIG_TOOL_OUTPUTS,
            **CI_SECURITY_TOOL_OUTPUTS,
            **CONTAINER_TOOL_OUTPUTS,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = build_scan_manifest(
                [
                    (tool_id, True, os.path.join(tmpdir, f"{tool_id}.sarif"))
                    for tool_id in expected_outputs
                ]
            )

        expected = {tool_id: "missing-output" for tool_id in expected_outputs}
        self.assertEqual({tool["toolId"]: tool["status"] for tool in manifest["tools"]}, expected)
        self.assertEqual(
            manifest["summary"],
            {"enabled": len(expected), "produced": 0, "empty": 0, "missing": len(expected), "invalid": 0},
        )

    def test_contract_cli_attaches_metadata_for_new_native_language_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.sarif")
            with open(input_path, "w", encoding="utf-8") as handle:
                json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Native"}}}]}, handle)

            for tool_id in LANGUAGE_SARIF_TOOL_OUTPUTS:
                output_path = os.path.join(tmpdir, f"{tool_id}.sarif")

                exit_code = contract_main([tool_id, input_path, output_path, "--ensure-run"])

                self.assertEqual(exit_code, 0)
                with open(output_path, "r", encoding="utf-8") as handle:
                    output = json.load(handle)
                driver = output["runs"][0]["tool"]["driver"]
                self.assertEqual(driver["name"], "Native")
                self.assertEqual(driver["properties"]["sigilixToolId"], tool_id)


NEXT_BATCH_TOOL_OUTPUTS = {
    "checkov": "checkov.sarif",
    "trivy": "trivy.sarif",
    "trufflehog": "trufflehog.sarif",
    "tflint": "tflint.sarif",
}

LANGUAGE_SARIF_TOOL_OUTPUTS = {"biome": "biome.sarif", "oxlint": "oxlint.sarif", "ast-grep": "ast-grep.sarif"}

CONFIG_TOOL_OUTPUTS = {"yamllint": "yamllint.sarif", "markdownlint": "markdownlint.sarif", "dotenv-linter": "dotenv-linter.sarif", "checkmake": "checkmake.sarif"}

CI_SECURITY_TOOL_OUTPUTS = {
    "zizmor": "zizmor.sarif",
}

CONTAINER_TOOL_OUTPUTS = {
    "hadolint": "hadolint.sarif",
}

ALL_TOOL_OUTPUTS = {
    "semgrep": "semgrep.sarif",
    "eslint": "eslint.sarif",
    "ruff": "ruff.sarif",
    "pylint": "pylint.sarif",
    "actionlint": "actionlint.sarif",
    "shellcheck": "shellcheck.sarif",
    "gitleaks": "gitleaks.sarif",
    "osv-scanner": "osv.sarif",
    **NEXT_BATCH_TOOL_OUTPUTS,
    **LANGUAGE_SARIF_TOOL_OUTPUTS,
    **CONFIG_TOOL_OUTPUTS,
    **CI_SECURITY_TOOL_OUTPUTS,
    **CONTAINER_TOOL_OUTPUTS,
}


class SigilixWorkflowContractTest(unittest.TestCase):
    def workflow_text(self):
        path = os.path.join(os.path.dirname(__file__), "..", "workflows", "scan.yml")
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def workflow_input_block(self, input_name):
        pattern = rf"\n      {re.escape(input_name)}:\n(?P<block>(?:        .+\n)+)"
        match = re.search(pattern, self.workflow_text())
        self.assertIsNotNone(match)
        return match.group("block")

    def tool_manifest(self):
        return load_tool_manifest(self.tool_manifest_path())

    def tool_manifest_path(self):
        return os.path.join(os.path.dirname(__file__), "..", "config", "tool-manifest.json")

    def raw_tool_manifest(self):
        path = os.path.join(os.path.dirname(__file__), "..", "config", "tool-manifest.json")
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def config_text(self, name):
        path = os.path.join(os.path.dirname(__file__), "..", "config", name)
        if not os.path.exists(path):
            return ""
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_static_tool_manifest_matches_known_outputs(self):
        manifest = self.raw_tool_manifest()

        self.assertEqual(set(manifest.keys()), {"tools"})
        rows = self.tool_manifest()
        self.assertEqual(len(rows), len({row["id"] for row in rows}))
        self.assertEqual(len(rows), len({row["output"] for row in rows}))
        self.assertEqual({row["id"]: row["output"] for row in rows}, ALL_TOOL_OUTPUTS)
        self.assertEqual({row["id"] for row in rows}, KNOWN_TOOL_IDS)
        for row in rows:
            self.assertEqual(set(row.keys()), {"id", "env", "output"})
            self.assertRegex(row["env"], r"^[A-Z0-9_]+_ENABLED$")

    def test_tool_manifest_helper_validates_rows_and_builds_paths(self):
        rows = self.tool_manifest()
        env = {row["env"]: "false" for row in rows}
        env["SEMGREP_ENABLED"] = "true"

        with tempfile.TemporaryDirectory() as tmpdir:
            specs = manifest_tool_specs(self.tool_manifest_path(), tmpdir, env)
            paths = manifest_sarif_paths(self.tool_manifest_path(), tmpdir)

        self.assertIn(("semgrep", True, os.path.join(tmpdir, "semgrep.sarif")), specs)
        self.assertIn(("eslint", False, ""), specs)
        self.assertEqual(paths, [os.path.join(tmpdir, row["output"]) for row in rows])

    def test_tool_manifest_rejects_invalid_rows(self):
        with self.assertRaisesRegex(ValueError, "invalid tool id"):
            validate_tool_manifest({"tools": [{"id": "bad;id", "env": "BAD_ENABLED", "output": "bad.sarif"}]})
        with self.assertRaisesRegex(ValueError, "duplicate tool id"):
            validate_tool_manifest(
                {
                    "tools": [
                        {"id": "semgrep", "env": "SEMGREP_ENABLED", "output": "semgrep.sarif"},
                        {"id": "semgrep", "env": "SEMGREP_ENABLED", "output": "semgrep-copy.sarif"},
                    ]
                }
            )
        with self.assertRaisesRegex(ValueError, "invalid output"):
            validate_tool_manifest({"tools": [{"id": "semgrep", "env": "SEMGREP_ENABLED", "output": "../semgrep.sarif"}]})

    def test_tool_manifest_rejects_missing_known_tool_ids(self):
        rows = [row for row in self.raw_tool_manifest()["tools"] if row["id"] != "semgrep"]

        with self.assertRaisesRegex(ValueError, "missing: semgrep"):
            validate_tool_manifest({"tools": rows})

    def test_tool_output_groups_are_disjoint(self):
        legacy_tools = {"semgrep", "eslint", "ruff", "actionlint", "shellcheck", "gitleaks", "osv-scanner"}

        self.assertFalse(legacy_tools & set(NEXT_BATCH_TOOL_OUTPUTS))
        self.assertFalse(legacy_tools & set(LANGUAGE_SARIF_TOOL_OUTPUTS))
        self.assertFalse(set(NEXT_BATCH_TOOL_OUTPUTS) & set(LANGUAGE_SARIF_TOOL_OUTPUTS))
        self.assertNotIn("zizmor", NEXT_BATCH_TOOL_OUTPUTS)
        self.assertIn("zizmor", CI_SECURITY_TOOL_OUTPUTS)
        self.assertNotIn("hadolint", NEXT_BATCH_TOOL_OUTPUTS)
        self.assertIn("hadolint", CONTAINER_TOOL_OUTPUTS)

    def test_workflow_uses_static_tool_manifest_for_manifest_and_merge(self):
        text = self.workflow_text()

        self.assertIn("TOOL_MANIFEST:", text)
        self.assertIn("tool-manifest.json", text)
        self.assertIn('--tool-manifest "$TOOL_MANIFEST"', text)
        self.assertIn('--sarif-dir "$SARIF_DIR"', text)
        self.assertNotIn('python3 - "$TOOL_MANIFEST"', text)
        self.assertNotIn("jq -r", text)

    def test_opt_in_tool_inputs_are_default_off_except_biome_and_oxlint(self):
        text = self.workflow_text()

        self.assertTrue({"biome", "oxlint", "ast-grep"} <= set({**NEXT_BATCH_TOOL_OUTPUTS, **LANGUAGE_SARIF_TOOL_OUTPUTS}))
        for tool_id in set({**NEXT_BATCH_TOOL_OUTPUTS, **LANGUAGE_SARIF_TOOL_OUTPUTS}) - {"biome", "oxlint", "ast-grep"}:
            self.assertRegex(
                text,
                rf"\n      {re.escape(tool_id)}:\n(?:        .+\n)+?        default: false\n",
            )

    def test_yamllint_is_default_on_for_config_feedback(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.tool_manifest()}

        self.assertIn("        default: true\n", self.workflow_input_block("yamllint"))
        self.assertIn("YAMLLINT_ENABLED: ${{ inputs.yamllint }}", text)
        self.assertEqual(rows["yamllint"]["env"], "YAMLLINT_ENABLED")
        self.assertEqual(rows["yamllint"]["output"], "yamllint.sarif")

    def test_zizmor_is_default_on_for_ci_security_feedback(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.tool_manifest()}

        self.assertIn("        default: true\n", self.workflow_input_block("zizmor"))
        self.assertIn("ZIZMOR_ENABLED: ${{ inputs.zizmor }}", text)
        self.assertEqual(rows["zizmor"]["env"], "ZIZMOR_ENABLED")
        self.assertEqual(rows["zizmor"]["output"], "zizmor.sarif")

    def test_hadolint_is_default_on_for_dockerfile_feedback(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.tool_manifest()}

        self.assertIn("        default: true\n", self.workflow_input_block("hadolint"))
        self.assertIn("- name: Run Hadolint to SARIF", text)
        self.assertIn("if: ${{ inputs.hadolint }}", text)
        self.assertIn("HADOLINT_ENABLED: ${{ inputs.hadolint }}", text)
        self.assertEqual(rows["hadolint"]["env"], "HADOLINT_ENABLED")
        self.assertEqual(rows["hadolint"]["output"], "hadolint.sarif")

    def test_catalog_tool_outputs_are_manifested_and_merged(self):
        rows = {row["id"]: row for row in self.tool_manifest()}
        expected_outputs = {
            **NEXT_BATCH_TOOL_OUTPUTS,
            **LANGUAGE_SARIF_TOOL_OUTPUTS,
            **CONFIG_TOOL_OUTPUTS,
            **CI_SECURITY_TOOL_OUTPUTS,
            **CONTAINER_TOOL_OUTPUTS,
        }

        for tool_id, output_name in expected_outputs.items():
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertEqual(rows[tool_id]["env"], env_var)
            self.assertEqual(rows[tool_id]["output"], output_name)

    def test_oxlint_is_default_on_and_empty_tree_emits_empty_sarif(self):
        text = self.workflow_text()

        self.assertRegex(text, r"\n      oxlint:\n(?:        [^\n]+\n)+?        default: true\n")
        self.assertIn('files_list="$RUNNER_TEMP/oxlint-files"', text)
        self.assertIn("find -P . \\\n            \\( -type d \\( -name '.git' -o -name 'node_modules'", text)
        self.assertIn("-name 'dist' -o -name 'build'", text)
        self.assertIn("-name '.next' -o -name 'out' \\) -prune \\) -o", text)
        self.assertIn('printf \'{"version":"2.1.0","runs":[]}\' > "$raw"', text)

    def test_oxlint_separates_options_from_file_paths(self):
        text = self.workflow_text()

        self.assertRegex(text, r"\n\s+-- \\\n\s+\"\$\{files\[@\]\}\" > \"\$raw\"")

    def test_oxlint_uses_sigilix_controlled_correctness_mode(self):
        text = self.workflow_text()
        config_text = self.config_text("oxlint-sigilix.oxlintrc.jsonc")

        self.assertIn("oxlint_config=\"$RUNNER_DIR/.github/config/oxlint-sigilix.oxlintrc.jsonc\"", text)
        self.assertRegex(
            text,
            r'"\$oxlint_bin" \\\n\s+--config "\$oxlint_config" \\\n\s+--disable-nested-config \\\n\s+--no-ignore \\\n\s+-A all -D correctness',
        )
        self.assertIn("Rule selection is controlled entirely by CLI flags", config_text)

    def test_node_runtime_is_pinned_for_npx_tools(self):
        text = self.workflow_text()

        self.assertIn('NODE_VERSION: "22.13.0"', text)
        self.assertIn("uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", text)
        self.assertIn("node-version: ${{ env.NODE_VERSION }}", text)
        self.assertIn("check-latest: false", text)

    def test_oxlint_asserts_pinned_runtime_version_before_scan(self):
        text = self.workflow_text()

        self.assertIn('npm pack --silent --pack-destination "$oxlint_pack_dir"', text)
        self.assertIn('npm install --silent --prefix "$oxlint_install_dir" --ignore-scripts --omit=optional', text)
        self.assertIn("--registry=https://registry.npmjs.org", text)
        self.assertIn("--no-audit --no-fund", text)
        self.assertIn('oxlint_bin="$oxlint_install_dir/node_modules/.bin/oxlint"', text)
        self.assertIn("oxlint_version=\"$(", text)
        self.assertIn('if ! oxlint_version="$("$oxlint_bin" --version 2>/dev/null)"; then', text)
        self.assertIn('oxlint_can_scan=false', text)
        self.assertIn("oxlint_detected_version=\"$(printf '%s\\n' \"$oxlint_version\"", text)
        self.assertIn('[ "$oxlint_detected_version" != "$OXLINT_VERSION" ]', text)
        self.assertIn("oxlint version mismatch or unavailable", text)
        self.assertIn("OXLINT_NPM_INTEGRITY:", text)
        self.assertIn("OXLINT_LINUX_X64_GNU_INTEGRITY:", text)
        self.assertIn('[ "$(sri_sha512 "$oxlint_package")" != "$OXLINT_NPM_INTEGRITY" ]', text)
        self.assertIn('[ "$(sri_sha512 "$oxlint_binding_package")" != "$OXLINT_LINUX_X64_GNU_INTEGRITY" ]', text)
        self.assertIn('[ ! -f "$oxlint_config" ]', text)
        self.assertIn('if [ "$oxlint_can_scan" = true ]; then', text)
        self.assertIn('if [ ! -s "$raw" ]; then', text)

    def test_next_batch_tool_versions_are_pinned(self):
        text = self.workflow_text()

        for env_var in (
            "CHECKOV_VERSION",
            "TRIVY_VERSION",
            "TRUFFLEHOG_VERSION",
            "ZIZMOR_VERSION",
            "HADOLINT_VERSION",
            "TFLINT_VERSION",
            "BIOME_VERSION",
            "OXLINT_VERSION",
        ):
            match = re.search(rf"\n      {env_var}: \"([^\"]+)\"\n", text)
            self.assertIsNotNone(match)
            version = match.group(1)
            self.assertNotIn("${{", version)
            self.assertRegex(version, r"^\d+\.\d+\.\d+$")


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

    def test_trufflehog_json_lines_convert_to_sarif(self):
        from trufflehog_to_sarif import convert_trufflehog_json

        document = convert_trufflehog_json(
            json.dumps(
                {
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env", "line": 4}}},
                    "DetectorName": "AWS",
                    "Verified": True,
                    "Raw": "AKIA_SHOULD_NOT_APPEAR",
                    "Redacted": "AKIA********",
                    "ExtraData": {"account": "SHOULD_NOT_APPEAR"},
                    "StructuredData": {"token": "STRUCTURED_SHOULD_NOT_APPEAR"},
                }
            )
            + "\n",
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "trufflehog")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "AWS")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["message"]["text"], "TruffleHog found AWS secret")
        self.assertEqual(result["properties"], {"trufflehogVerified": True})
        self.assertNotIn("AKIA", json.dumps(document))
        self.assertNotIn("SHOULD_NOT_APPEAR", json.dumps(document))
        self.assertNotIn("STRUCTURED_SHOULD_NOT_APPEAR", json.dumps(document))
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "secrets.env")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 4)

    def test_trufflehog_unverified_findings_are_warning_without_secret_dependent_dedupe(self):
        from trufflehog_to_sarif import convert_trufflehog_json

        finding = {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env", "line": 4}}},
            "DetectorName": "AWS",
            "Verified": False,
            "Raw": "AKIA_DUPLICATE_SECRET",
        }
        document = convert_trufflehog_json("\n".join([json.dumps(finding), json.dumps(finding)]), base_dir="/repo")

        results = document["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["level"], "warning")
        self.assertEqual(results[0]["message"]["text"], "TruffleHog found AWS secret")
        self.assertEqual(results[0]["properties"], {"trufflehogVerified": False})
        self.assertNotIn("AKIA_DUPLICATE_SECRET", json.dumps(document))

        metadata_only = dict(finding)
        metadata_only.pop("Raw")
        document = convert_trufflehog_json(
            "\n".join([json.dumps(metadata_only), json.dumps(metadata_only)]),
            base_dir="/repo",
        )
        self.assertEqual(len(document["runs"][0]["results"]), 1)

        whitespace_raw = dict(finding, Raw="   ")
        document = convert_trufflehog_json("\n".join([json.dumps(whitespace_raw), json.dumps(whitespace_raw)]), base_dir="/repo")
        self.assertEqual(len(document["runs"][0]["results"]), 1)

        numeric_raw = dict(finding, Raw=0)
        document = convert_trufflehog_json("\n".join([json.dumps(numeric_raw), json.dumps(numeric_raw)]), base_dir="/repo")
        self.assertEqual(len(document["runs"][0]["results"]), 2)

    def test_trufflehog_metadata_dedupe_prefers_verified_finding(self):
        from trufflehog_to_sarif import convert_trufflehog_json

        base = {"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env", "line": 4}}}, "DetectorName": "AWS"}
        document = convert_trufflehog_json(
            "\n".join([json.dumps(dict(base, Verified=False)), json.dumps(dict(base, Verified="true"))]),
            base_dir="/repo",
        )

        result = document["runs"][0]["results"][0]
        self.assertEqual(len(document["runs"][0]["results"]), 1)
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"], {"trufflehogVerified": True})

        other = {"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/other.env", "line": 8}}}, "DetectorName": "GCP"}
        document = convert_trufflehog_json("\n".join([json.dumps(base), json.dumps(other)]), base_dir="/repo")
        self.assertEqual([result["ruleId"] for result in document["runs"][0]["results"]], ["AWS", "GCP"])

    def test_trufflehog_ndjson_warns_on_non_object_lines(self):
        from trufflehog_to_sarif import convert_trufflehog_json

        payload = "\n".join(
            [
                json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/first.env", "line": 1}}}, "DetectorName": "AWS"}),
                json.dumps(["unexpected"]),
                json.dumps({"SourceMetadata": {"Data": {"Git": {"file": "/repo/second.env", "line": 2}}}, "DetectorName": "GitHub"}),
            ]
        )
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            document = convert_trufflehog_json(payload, base_dir="/repo")

        self.assert_sigilix_properties(document, "trufflehog")
        self.assertEqual([result["ruleId"] for result in document["runs"][0]["results"]], ["AWS", "GitHub"])
        self.assertIn("skipped a non-object JSON line", stderr.getvalue())

    def test_trufflehog_missing_line_omits_sarif_region(self):
        from trufflehog_to_sarif import convert_trufflehog_json

        document = convert_trufflehog_json(
            json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env"}}}, "DetectorName": "AWS"}),
            base_dir="/repo",
        )

        result = document["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "secrets.env")
        self.assertNotIn("region", result["locations"][0]["physicalLocation"])

    def test_yamllint_parsable_output_converts_to_sarif(self):
        from yamllint_to_sarif import convert_yamllint_output

        document = convert_yamllint_output(
            './config/bad.yaml:2:1: [error] syntax error: expected node content (syntax)\n'
            './config/style.yaml:5:7: [warning] too many spaces inside braces (allowed in flow style) (braces)\n',
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "yamllint")
        results = document["runs"][0]["results"]
        self.assertEqual([result["ruleId"] for result in results], ["syntax", "braces"])
        self.assertEqual([result["level"] for result in results], ["error", "warning"])
        self.assertEqual(results[1]["message"]["text"], "too many spaces inside braces (allowed in flow style)")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "config/bad.yaml")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"], {"startLine": 2, "startColumn": 1})

    def test_yamllint_converter_handles_colons_in_paths(self):
        from yamllint_to_sarif import convert_yamllint_output

        document = convert_yamllint_output("./config/has:colon.yaml:9:3: [error] bad yaml (syntax)")

        result = document["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "config/has:colon.yaml")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"], {"startLine": 9, "startColumn": 3})

    def test_yamllint_converter_ignores_empty_and_unparsable_lines(self):
        from yamllint_to_sarif import convert_yamllint_output

        self.assertEqual(convert_yamllint_output("")["runs"][0]["results"], [])
        document = convert_yamllint_output(
            "not a yamllint line\n./config/bad.yaml:2:1: [error] syntax error (syntax)\n",
            base_dir="/repo",
        )
        self.assertEqual(len(document["runs"][0]["results"]), 1)

    def test_normalize_path_falls_back_for_paths_outside_base_dir(self):
        self.assertEqual(normalize_path("/repo/src/app.js", base_dir="/repo"), "src/app.js")
        self.assertEqual(normalize_path("/etc/passwd", base_dir="/repo"), "passwd")
        self.assertEqual(normalize_path("../secret.txt", base_dir="/repo"), "secret.txt")
        self.assertEqual(normalize_path("sub/../../secret.txt", base_dir="/repo"), "secret.txt")
        self.assertEqual(normalize_path("", base_dir="/repo"), ".")


if __name__ == "__main__":
    unittest.main()
