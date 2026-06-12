import json
import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
CONFIG_DIR = os.path.join(ROOT, ".github", "config")
SCRIPT_DIR = os.path.join(ROOT, ".github", "scripts")

NEW_TOOL_OUTPUTS = {
    "flake8": "flake8.sarif",
    "golangci-lint": "golangci-lint.sarif",
    "htmlhint": "htmlhint.sarif",
    "stylelint": "stylelint.sarif",
}


class LanguageConfigToolsWorkflowTest(unittest.TestCase):
    def read_file(self, path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def workflow_text(self):
        return self.read_file(WORKFLOW_PATH)

    def workflow_input_block(self, input_name):
        pattern = rf"\n      {re.escape(input_name)}:\n(?P<block>(?:        .+\n)+)"
        match = re.search(pattern, self.workflow_text())
        self.assertIsNotNone(match)
        return match.group("block")

    def workflow_step_block(self, step_name):
        pattern = rf"(?ms)^      - name: {re.escape(step_name)}\n.+?(?=^      - name: |\Z)"
        match = re.search(pattern, self.workflow_text())
        self.assertIsNotNone(match)
        return match.group(0)

    def manifest_rows(self):
        with open(MANIFEST_PATH, encoding="utf-8") as handle:
            return {row["id"]: row for row in json.load(handle)["tools"]}

    def config_json(self, filename):
        with open(os.path.join(CONFIG_DIR, filename), encoding="utf-8") as handle:
            return json.load(handle)

    def script_text(self, filename):
        return self.read_file(os.path.join(SCRIPT_DIR, filename))

    def test_new_tools_are_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = self.manifest_rows()

        for tool_id, output in NEW_TOOL_OUTPUTS.items():
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertIn("        default: true\n", self.workflow_input_block(tool_id))
            self.assertIn(f"{env_var}: ${{{{ inputs.{tool_id} }}}}", text)
            self.assertEqual(rows[tool_id], {"id": tool_id, "env": env_var, "output": output})

        self.assertIn("GOLANGCI_LINT_VERSION: \"2.12.2\"", text)
        self.assertIn("GOLANGCI_LINT_LINUX_AMD64_SHA256:", text)
        self.assertIn("FLAKE8_VERSION: \"7.3.0\"", text)
        self.assertIn("HTMLHINT_NPM_INTEGRITY:", text)
        self.assertIn("HTMLHINT_VERSION: \"1.9.2\"", text)
        self.assertIn("STYLELINT_NPM_INTEGRITY:", text)
        self.assertIn("STYLELINT_VERSION: \"17.12.0\"", text)
        self.assertIn("TFLINT_LINUX_AMD64_SHA256:", text)

    def test_workflow_delegates_new_tools_to_runner_scripts(self):
        expectations = {
            "Run Flake8 to SARIF": "run_flake8.sh",
            "Run golangci-lint to SARIF": "run_golangci_lint.sh",
            "Run HTMLHint to SARIF": "run_htmlhint.sh",
            "Run Stylelint to SARIF": "run_stylelint.sh",
            "Run TFLint to SARIF": "run_tflint.sh",
        }

        for step_name, script_name in expectations.items():
            block = self.workflow_step_block(step_name)
            self.assertIn(f'bash "$RUNNER_DIR/.github/scripts/{script_name}"', block)

    def test_flake8_wrapper_uses_marker_gated_high_confidence_profile(self):
        text = self.script_text("run_flake8.sh")

        self.assertIn("FLAKE8_VERSION", text)
        self.assertIn("python3 -m venv \"$flake8_venv\"", text)
        self.assertIn('"flake8==${FLAKE8_VERSION}"', text)
        self.assertIn("find_flake8_marker", text)
        self.assertIn("No .flake8 marker found", text)
        self.assertIn("--isolated", text)
        self.assertIn("--select=E9,F63,F7,F82", text)
        self.assertIn("--format=%(path)s:%(row)d:%(col)d: %(code)s %(text)s", text)
        self.assertIn("flake8_to_sarif.py", text)

    def test_golangci_wrapper_avoids_caller_config_and_requires_go_files(self):
        text = self.script_text("run_golangci_lint.sh")

        self.assertIn("GOLANGCI_LINT_VERSION", text)
        self.assertIn("golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64.tar.gz", text)
        self.assertIn("discover_go_files", text)
        self.assertIn("No Go files found", text)
        self.assertIn("No root go.mod found", text)
        self.assertIn("GOLANGCI_LINT_LINUX_AMD64_SHA256", text)
        self.assertIn("sha256sum -c --strict", text)
        self.assertIn("--no-config", text)
        self.assertIn("--default=standard", text)
        self.assertIn("--output.sarif.path=\"$raw\"", text)
        self.assertIn("--issues-exit-code=0", text)
        self.assertIn("sigilix_sarif_contract.py", text)

    def test_htmlhint_wrapper_uses_runner_config_and_native_sarif(self):
        text = self.script_text("run_htmlhint.sh")
        config = self.config_json("htmlhint-sigilix.json")

        self.assertIn("HTMLHINT_VERSION", text)
        self.assertIn("HTMLHINT_NPM_INTEGRITY", text)
        self.assertIn("npm pack --json --silent", text)
        self.assertIn("PACK_JSON", text)
        self.assertIn("verify_package_integrity", text)
        self.assertIn("htmlhint-${HTMLHINT_VERSION}.XXXXXX", text)
        self.assertIn("htmlhint-[0-9]+[.][0-9]+[.][0-9]+[.]tgz", text)
        self.assertIn("--ignore-scripts --omit=optional", text)
        self.assertIn("htmlhint-sigilix.json", text)
        self.assertIn("--format sarif", text)
        self.assertNotIn("--warn", text)
        self.assertIn("sigilix_sarif_contract.py", text)
        self.assertTrue(config["doctype-first"])
        self.assertTrue(config["tag-pair"])
        self.assertTrue(config["attr-no-duplication"])
        self.assertTrue(config["id-unique"])
        self.assertTrue(config["src-not-empty"])
        self.assertTrue(config["alt-require"])
        self.assertFalse(config["inline-style-disabled"])
        self.assertFalse(config["inline-script-disabled"])

    def test_stylelint_wrapper_uses_runner_config_and_json_converter(self):
        text = self.script_text("run_stylelint.sh")
        config = self.config_json("stylelint-sigilix.json")

        self.assertIn("STYLELINT_VERSION", text)
        self.assertIn("STYLELINT_NPM_INTEGRITY", text)
        self.assertIn("npm pack --json --silent", text)
        self.assertIn("PACK_JSON", text)
        self.assertIn("verify_package_integrity", text)
        self.assertIn("stylelint-${STYLELINT_VERSION}.XXXXXX", text)
        self.assertIn("stylelint-[0-9]+[.][0-9]+[.][0-9]+[.]tgz", text)
        self.assertIn("--ignore-scripts --omit=optional", text)
        self.assertIn("stylelint-sigilix.json", text)
        self.assertIn("--formatter json", text)
        self.assertIn("--output-file \"$json\"", text)
        self.assertIn("--allow-empty-input", text)
        self.assertIn("stylelint_to_sarif.py", text)
        self.assertEqual(config["rules"]["block-no-empty"], True)
        self.assertEqual(config["rules"]["declaration-block-no-duplicate-properties"], True)
        self.assertEqual(config["rules"]["property-no-unknown"], True)
        self.assertEqual(config["rules"]["selector-type-no-unknown"], True)

    def test_tflint_is_default_on_and_scripted_with_terraform_preflight(self):
        text = self.workflow_text()
        script = self.script_text("run_tflint.sh")

        self.assertIn("        default: true\n", self.workflow_input_block("tflint"))
        self.assertIn("TFLINT_ENABLED: ${{ inputs.tflint }}", text)
        self.assertIn("TFLINT_LINUX_AMD64_SHA256", script)
        self.assertIn("sha256sum -c --strict", script)
        self.assertIn("TFLint binary missing or not executable", script)
        self.assertIn("TFLint installed version mismatch", script)
        self.assertIn("discover_terraform_files", script)
        self.assertIn("No Terraform files found", script)
        self.assertIn("tflint_linux_amd64.zip", script)
        self.assertIn("--recursive --format sarif", script)
        self.assertIn("sigilix_sarif_contract.py", script)


class LanguageConfigToolsConverterTest(unittest.TestCase):
    def assert_sigilix_properties(self, document, tool_id):
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        properties = document["runs"][0]["tool"]["driver"]["properties"]
        self.assertEqual(properties["sigilixToolId"], tool_id)
        self.assertEqual(properties["sigilixSource"], "deterministic-tool")

    def test_flake8_output_converts_to_sarif(self):
        from flake8_to_sarif import convert_flake8_output

        document = convert_flake8_output(
            "/repo/app.py:2:9: F821 undefined name 'missing'\n"
            "/repo/broken.py:1:1: E999 SyntaxError: invalid syntax\n"
            "not a flake8 line\n",
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "flake8")
        results = document["runs"][0]["results"]
        self.assertEqual([result["ruleId"] for result in results], ["F821", "E999"])
        self.assertEqual([result["level"] for result in results], ["warning", "error"])
        self.assertEqual(results[0]["message"]["text"], "undefined name 'missing'")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"], {"startLine": 2, "startColumn": 9})

    def test_stylelint_json_converts_to_sarif(self):
        from stylelint_to_sarif import convert_stylelint_json

        document = convert_stylelint_json(
            [
                {
                    "source": "/repo/src/app.css",
                    "warnings": [
                        {
                            "line": 3,
                            "column": 5,
                            "endLine": 3,
                            "endColumn": 10,
                            "rule": "declaration-block-no-duplicate-properties",
                            "severity": "error",
                            "text": "Duplicate property \"color\" (declaration-block-no-duplicate-properties)",
                        }
                    ],
                }
            ],
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "stylelint")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "declaration-block-no-duplicate-properties")
        self.assertEqual(result["level"], "error")
        self.assertIn("Duplicate property", result["message"]["text"])
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/app.css")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

    def test_stylelint_converter_drops_end_region_without_start_region(self):
        from stylelint_to_sarif import convert_stylelint_json

        document = convert_stylelint_json(
            [
                {
                    "source": "/repo/src/app.css",
                    "warnings": [
                        {
                            "endLine": 7,
                            "endColumn": 4,
                            "rule": "stylelint",
                            "severity": "info",
                            "text": "Malformed upstream region",
                        }
                    ],
                }
            ],
            base_dir="/repo",
        )

        result = document["runs"][0]["results"][0]
        self.assertEqual(result["level"], "note")
        self.assertNotIn("region", result["locations"][0]["physicalLocation"])


if __name__ == "__main__":
    unittest.main()
