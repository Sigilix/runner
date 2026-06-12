import json
import os
import re
import tempfile
import unittest

from sigilix_sarif_contract import KNOWN_TOOL_IDS, SIGILIX_SCHEMA_VERSION, SIGILIX_SOURCE


NEW_TOOL_OUTPUTS = {
    "markdownlint": "markdownlint.sarif",
    "dotenv-linter": "dotenv-linter.sarif",
    "checkmake": "checkmake.sarif",
}


class DocsConfigWorkflowTest(unittest.TestCase):
    def workflow_text(self):
        path = os.path.join(os.path.dirname(__file__), "..", "workflows", "scan.yml")
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def workflow_input_block(self, input_name):
        pattern = rf"\n      {re.escape(input_name)}:\n(?P<block>(?:        .+\n)+)"
        match = re.search(pattern, self.workflow_text())
        self.assertIsNotNone(match)
        return match.group("block")

    def tool_manifest_rows(self):
        path = os.path.join(os.path.dirname(__file__), "..", "config", "tool-manifest.json")
        with open(path, "r", encoding="utf-8") as handle:
            return {row["id"]: row for row in json.load(handle)["tools"]}

    def config_text(self, name):
        path = os.path.join(os.path.dirname(__file__), "..", "config", name)
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_docs_config_tools_are_known_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = self.tool_manifest_rows()

        for tool_id, output_name in NEW_TOOL_OUTPUTS.items():
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertIn(tool_id, KNOWN_TOOL_IDS)
            self.assertIn("        default: true\n", self.workflow_input_block(tool_id))
            self.assertIn(f"{env_var}: ${{{{ inputs.{tool_id} }}}}", text)
            self.assertEqual(rows[tool_id]["env"], env_var)
            self.assertEqual(rows[tool_id]["output"], output_name)

    def test_docs_config_tools_use_runner_owned_bounded_scans(self):
        text = self.workflow_text()

        self.assertIn('MARKDOWNLINT_VERSION: "0.48.0"', text)
        self.assertIn('DOTENV_LINTER_VERSION: "4.0.0"', text)
        self.assertIn('CHECKMAKE_VERSION: "0.3.2"', text)
        self.assertIn('markdownlint_config="$RUNNER_DIR/.github/config/markdownlint-sigilix.json"', text)
        self.assertIn('checkmake_config="$RUNNER_DIR/.github/config/checkmake-sigilix.ini"', text)
        self.assertIn("--config \"$markdownlint_config\"", text)
        self.assertIn("--config \"$checkmake_config\"", text)
        self.assertIn("--skip-updates", text)
        self.assertIn("-not -path './node_modules/*'", text)
        self.assertIn("-not -path './dist/*'", text)

    def test_runner_owned_configs_avoid_high_noise_defaults(self):
        markdownlint_config = json.loads(self.config_text("markdownlint-sigilix.json"))
        checkmake_config = self.config_text("checkmake-sigilix.ini")

        self.assertFalse(markdownlint_config["default"])
        self.assertTrue(markdownlint_config["MD011"])
        self.assertTrue(markdownlint_config["MD042"])
        self.assertTrue(markdownlint_config["MD056"])
        self.assertEqual(markdownlint_config["MD024"], {"siblings_only": True})
        self.assertIn("[minphony]", checkmake_config)
        self.assertIn("required =", checkmake_config)


class DocsConfigConverterTest(unittest.TestCase):
    def assert_sigilix_properties(self, document, tool_id):
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        properties = document["runs"][0]["tool"]["driver"]["properties"]
        self.assertEqual(properties["sigilixSchemaVersion"], SIGILIX_SCHEMA_VERSION)
        self.assertEqual(properties["sigilixToolId"], tool_id)
        self.assertEqual(properties["sigilixSource"], SIGILIX_SOURCE)

    def test_markdownlint_json_converts_to_sarif(self):
        from markdownlint_to_sarif import convert_markdownlint_json

        document = convert_markdownlint_json(
            [
                {
                    "fileName": "/repo/README.md",
                    "lineNumber": 3,
                    "ruleNames": ["MD024", "no-duplicate-heading"],
                    "ruleDescription": "Multiple headings with the same content",
                    "errorDetail": "Sibling heading",
                    "severity": "error",
                }
            ],
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "markdownlint")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "MD024")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["message"]["text"], "Multiple headings with the same content: Sibling heading")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "README.md")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

    def test_dotenv_linter_plain_output_converts_without_secret_values(self):
        from dotenv_linter_to_sarif import convert_dotenv_linter_output

        document = convert_dotenv_linter_output(
            ".env:2 DuplicatedKey: The PASSWORD key is duplicated\n"
            ".env:3 ValueWithoutQuotes: SECRET_TOKEN=hunter2 needs quotes\n"
            ".env:4 SpaceCharacter: SESSION_SECRET=sk-secret has spaces\n"
            ".env:5 QuoteCharacter: API_KEY=`secret-value` uses backticks\n"
            ".env:6 ValueWithoutQuotes: SPACED_SECRET=my secret key needs quotes\n",
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "dotenv-linter")
        encoded = json.dumps(document)
        self.assertNotIn("hunter2", encoded)
        self.assertNotIn("sk-secret", encoded)
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn("my secret key", encoded)
        self.assertIn("SECRET_TOKEN=[redacted]", encoded)
        self.assertIn("SESSION_SECRET=[redacted]", encoded)
        self.assertIn("API_KEY=[redacted]", encoded)
        self.assertIn("SPACED_SECRET=[redacted]", encoded)
        results = document["runs"][0]["results"]
        self.assertEqual([result["ruleId"] for result in results], ["DuplicatedKey", "ValueWithoutQuotes", "SpaceCharacter", "QuoteCharacter", "ValueWithoutQuotes"])
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 2)

    def test_checkmake_json_converts_to_sarif(self):
        from checkmake_to_sarif import convert_checkmake_json

        document = convert_checkmake_json(
            [
                {
                    "rule": "uniquetargets",
                    "violation": "Target \"build\" defined multiple times.",
                    "file_name": "/repo/Makefile",
                    "line_number": 4,
                }
            ],
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "checkmake")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "uniquetargets")
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "Makefile")

    def test_checkmake_converter_accepts_multiple_json_arrays(self):
        from checkmake_to_sarif import convert_checkmake_json

        text = (
            '[{"rule":"uniquetargets","violation":"duplicate","file_name":"Makefile","line_number":4}]\n'
            '[{"rule":"timestampexpanded","violation":"timestamp","file_name":"rules.mk","line_number":1}]\n'
        )

        document = convert_checkmake_json(text)

        self.assertEqual([result["ruleId"] for result in document["runs"][0]["results"]], ["uniquetargets", "timestampexpanded"])


if __name__ == "__main__":
    unittest.main()
