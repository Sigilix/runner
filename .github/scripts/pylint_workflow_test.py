import json
import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
PYLINT_CONVERTER_PATH = os.path.join(ROOT, ".github", "scripts", "pylint_to_sarif.py")
PYLINT_RUNNER_PATH = os.path.join(ROOT, ".github", "scripts", "run_pylint.sh")


class PylintWorkflowTest(unittest.TestCase):
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

    def workflow_pylint_block(self):
        match = re.search(
            r"(?ms)^      - name: Run Pylint to SARIF\n"
            r".+?"
            r"(?=^      - name: Run actionlint to SARIF)",
            self.workflow_text(),
        )
        self.assertIsNotNone(match)
        return match.group(0)

    def manifest_rows(self):
        with open(MANIFEST_PATH, encoding="utf-8") as handle:
            return json.load(handle)["tools"]

    def test_pylint_is_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.manifest_rows()}

        self.assertIn("        default: true\n", self.workflow_input_block("pylint"))
        self.assertIn('PYLINT_VERSION: "4.0.5"', text)
        self.assertIn("PYLINT_ENABLED: ${{ inputs.pylint }}", text)
        self.assertEqual(rows["pylint"], {"id": "pylint", "env": "PYLINT_ENABLED", "output": "pylint.sarif"})

    def test_pylint_workflow_delegates_to_runner_script(self):
        block = self.workflow_pylint_block()
        text = self.read_file(PYLINT_RUNNER_PATH)

        self.assertIn('bash "$RUNNER_DIR/.github/scripts/run_pylint.sh"', block)
        self.assertIn("python3 -m venv \"$pylint_venv\"", text)
        self.assertIn('"$pylint_python" -m pip install --quiet --disable-pip-version-check "pylint==${PYLINT_VERSION}"', text)
        self.assertIn("Pylint installed version mismatch", text)
        self.assertIn("--rcfile=/dev/null", text)
        self.assertIn("--disable=all", text)
        self.assertIn("--enable=E,F", text)
        self.assertIn("--disable=import-error,no-member", text)
        self.assertIn("--exit-zero", text)
        self.assertIn("--persistent=n", text)
        self.assertIn("--score=n", text)
        self.assertIn("--reports=n", text)
        self.assertIn("pylint_to_sarif.py", text)

    def test_pylint_converter_maps_json_messages_to_sarif(self):
        from pylint_to_sarif import convert_pylint_json

        document = convert_pylint_json(
            [
                {
                    "type": "error",
                    "path": "/repo/app.py",
                    "line": 2,
                    "column": 10,
                    "endLine": 2,
                    "endColumn": 22,
                    "symbol": "undefined-variable",
                    "message-id": "E0602",
                    "message": "Undefined variable 'missing_name'",
                },
                {
                    "type": "fatal",
                    "path": "../secret.py",
                    "line": 1,
                    "column": 0,
                    "symbol": "x" * 400,
                    "message-id": "F0001",
                    "message": "m" * 5000,
                }
            ],
            base_dir="/repo",
        )

        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["properties"]["sigilixToolId"], "pylint")
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "E0602/undefined-variable")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["message"]["text"], "Undefined variable 'missing_name'")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 2)
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startColumn"], 11)
        bounded_result = run["results"][1]
        self.assertLessEqual(len(bounded_result["ruleId"]), 256)
        self.assertTrue(bounded_result["ruleId"].endswith("..."))
        self.assertEqual(len(bounded_result["message"]["text"]), 4096)
        self.assertEqual(bounded_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "secret.py")


if __name__ == "__main__":
    unittest.main()
