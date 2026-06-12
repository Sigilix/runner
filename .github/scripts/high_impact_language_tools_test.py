import json
import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
SCRIPT_DIR = os.path.join(ROOT, ".github", "scripts")

HIGH_IMPACT_OUTPUTS = {
    "sqlfluff": "sqlfluff.sarif",
    "prisma-lint": "prisma-lint.sarif",
    "rubocop": "rubocop.sarif",
    "phpstan": "phpstan.sarif",
    "phpmd": "phpmd.sarif",
    "phpcs": "phpcs.sarif",
    "clippy": "clippy.sarif",
    "detekt": "detekt.sarif",
    "swiftlint": "swiftlint.sarif",
}


class HighImpactLanguageToolsWorkflowTest(unittest.TestCase):
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

    def script_text(self, filename):
        return self.read_file(os.path.join(SCRIPT_DIR, filename))

    def test_high_impact_tools_are_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = self.manifest_rows()

        for tool_id, output in HIGH_IMPACT_OUTPUTS.items():
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertIn("        default: true\n", self.workflow_input_block(tool_id))
            self.assertIn(f"{env_var}: ${{{{ inputs.{tool_id} }}}}", text)
            self.assertEqual(rows[tool_id], {"id": tool_id, "env": env_var, "output": output})

        for version in (
            'SQLFLUFF_VERSION: "4.2.1"',
            'PRISMA_LINT_VERSION: "0.13.1"',
            'RUBOCOP_VERSION: "1.86.2"',
            "PHPSTAN_VERSION:",
            "PHPMD_VERSION:",
            "PHPCS_VERSION:",
            "DETEKT_VERSION:",
            "SWIFTLINT_VERSION:",
        ):
            self.assertIn(version, text)

    def test_workflow_delegates_high_impact_tools_to_group_script(self):
        block = self.workflow_step_block("Run high-impact language tools to SARIF")

        self.assertIn('bash "$RUNNER_DIR/.github/scripts/run_high_impact_language_tools.sh"', block)
        for tool_id in HIGH_IMPACT_OUTPUTS:
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertIn(f"{env_var}: ${{{{ inputs.{tool_id} }}}}", block)

    def test_group_script_uses_safe_presence_and_config_gates(self):
        text = self.script_text("run_high_impact_language_tools.sh")

        for tool_id in HIGH_IMPACT_OUTPUTS:
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertIn(env_var, text)
        self.assertIn("find_sqlfluff_config", text)
        self.assertIn("find_prisma_lint_config", text)
        self.assertIn("find_phpstan_config", text)
        self.assertIn("find_phpcs_config", text)
        self.assertIn("Cargo.toml", text)
        self.assertIn("swiftlint_linux_amd64.zip", text)
        self.assertIn("detekt-cli-${DETEKT_VERSION}-all.jar", text)
        self.assertIn("high_impact_to_sarif.py", text)


class HighImpactLanguageToolsConverterTest(unittest.TestCase):
    def assert_sigilix_properties(self, document, tool_id):
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        properties = document["runs"][0]["tool"]["driver"]["properties"]
        self.assertEqual(properties["sigilixToolId"], tool_id)
        self.assertEqual(properties["sigilixSource"], "deterministic-tool")

    def test_sqlfluff_json_converts_to_sarif(self):
        from high_impact_to_sarif import convert_sqlfluff

        document = convert_sqlfluff(
            [
                {
                    "filepath": "/repo/query.sql",
                    "violations": [
                        {"code": "AL04", "description": "Duplicate alias.", "line_no": 7, "line_pos": 5}
                    ],
                }
            ],
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "sqlfluff")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "AL04")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "query.sql")

    def test_prisma_lint_json_converts_to_sarif(self):
        from high_impact_to_sarif import convert_prisma_lint

        document = convert_prisma_lint(
            {
                "violations": [
                    {
                        "ruleName": "model-name-pascal-case",
                        "message": "Model name should be PascalCase.",
                        "fileName": "/repo/schema.prisma",
                        "location": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 10},
                    }
                ]
            },
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "prisma-lint")
        self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "model-name-pascal-case")

    def test_rubocop_json_converts_to_sarif(self):
        from high_impact_to_sarif import convert_rubocop

        document = convert_rubocop(
            {
                "files": [
                    {
                        "path": "/repo/app.rb",
                        "offenses": [
                            {
                                "cop_name": "Lint/UselessAssignment",
                                "message": "Useless assignment.",
                                "severity": "warning",
                                "location": {"start_line": 3, "start_column": 7},
                            }
                        ],
                    }
                ]
            },
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "rubocop")
        self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "Lint/UselessAssignment")

    def test_php_and_swift_converters_cover_common_json_shapes(self):
        from high_impact_to_sarif import convert_phpcs, convert_phpmd, convert_phpstan, convert_swiftlint

        phpstan = convert_phpstan({"files": {"/repo/src/App.php": {"messages": [{"message": "Bad type.", "line": 5, "identifier": "argument.type"}]}}}, base_dir="/repo")
        phpcs = convert_phpcs({"files": {"/repo/src/App.php": {"messages": [{"message": "Missing visibility.", "source": "Squiz.Scope.MethodScope.Missing", "type": "ERROR", "line": 4, "column": 3}]}}}, base_dir="/repo")
        phpmd = convert_phpmd({"files": [{"file": "/repo/src/App.php", "violations": [{"rule": "UnusedLocalVariable", "description": "Unused variable.", "beginLine": 8}]}]}, base_dir="/repo")
        swiftlint = convert_swiftlint([{"file": "/repo/App.swift", "rule_id": "force_cast", "reason": "Force casts should be avoided.", "line": 9, "character": 12, "severity": "Warning"}], base_dir="/repo")

        self.assert_sigilix_properties(phpstan, "phpstan")
        self.assert_sigilix_properties(phpcs, "phpcs")
        self.assert_sigilix_properties(phpmd, "phpmd")
        self.assert_sigilix_properties(swiftlint, "swiftlint")
        self.assertEqual(phpstan["runs"][0]["results"][0]["ruleId"], "argument.type")
        self.assertEqual(phpcs["runs"][0]["results"][0]["level"], "error")
        self.assertEqual(phpmd["runs"][0]["results"][0]["ruleId"], "UnusedLocalVariable")
        self.assertEqual(swiftlint["runs"][0]["results"][0]["ruleId"], "force_cast")

    def test_clippy_json_lines_convert_to_sarif(self):
        from high_impact_to_sarif import convert_clippy_json_lines

        document = convert_clippy_json_lines(
            '{"reason":"compiler-message","message":{"level":"warning","message":"called `unwrap()`",'
            '"code":{"code":"clippy::unwrap_used"},"spans":[{"is_primary":true,"file_name":"src/lib.rs",'
            '"line_start":2,"column_start":9,"line_end":2,"column_end":17}]}}\n',
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "clippy")
        self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "clippy::unwrap_used")


if __name__ == "__main__":
    unittest.main()
