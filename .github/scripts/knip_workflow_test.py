import json
import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
KNIP_CONFIG_PATH = os.path.join(ROOT, ".github", "config", "knip-sigilix.json")
KNIP_RUNNER_PATH = os.path.join(ROOT, ".github", "scripts", "run_knip.sh")


class KnipWorkflowTest(unittest.TestCase):
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

    def workflow_knip_block(self):
        match = re.search(
            r"(?ms)^      - name: Run Knip to SARIF\n"
            r".+?"
            r"(?=^      - name: Run actionlint to SARIF)",
            self.workflow_text(),
        )
        self.assertIsNotNone(match)
        return match.group(0)

    def manifest_rows(self):
        with open(MANIFEST_PATH, encoding="utf-8") as handle:
            return json.load(handle)["tools"]

    def test_knip_is_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.manifest_rows()}

        self.assertIn("        default: true\n", self.workflow_input_block("knip"))
        self.assertIn('KNIP_VERSION: "6.16.1"', text)
        self.assertIn("KNIP_ENABLED: ${{ inputs.knip }}", text)
        self.assertEqual(rows["knip"], {"id": "knip", "env": "KNIP_ENABLED", "output": "knip.sarif"})

    def test_knip_runner_uses_safe_profile(self):
        block = self.workflow_knip_block()
        text = self.read_file(KNIP_RUNNER_PATH)
        config = self.read_file(KNIP_CONFIG_PATH)

        self.assertIn('bash "$RUNNER_DIR/.github/scripts/run_knip.sh"', block)
        self.assertIn('"knip@${KNIP_VERSION}"', text)
        self.assertIn('knip-${KNIP_VERSION}-$$', text)
        self.assertIn('cd "$RUNNER_TEMP"', text)
        self.assertIn("npm install --silent --prefix \"$knip_install_dir\" --ignore-scripts", text)
        self.assertNotIn("--omit=optional", text)
        self.assertIn("--config \"$knip_config\"", text)
        self.assertIn("--include unresolved,unlisted,binaries", text)
        self.assertIn("--reporter json", text)
        self.assertIn("--no-exit-code", text)
        self.assertIn("--no-config-hints", text)
        self.assertIn("--no-tag-hints", text)
        self.assertIn("--no-gitignore", text)
        self.assertIn("knip_to_sarif.py", text)
        self.assertIn('"entry"', config)
        self.assertIn('"project"', config)
        self.assertIn('"**/node_modules/**"', config)
        self.assertIn('"**/__fixtures__/**"', config)
        self.assertIn('"**/generated/**"', config)
        self.assertNotIn("exports", text)
        self.assertNotIn("--fix", text)

    def test_knip_converter_maps_dependency_resolution_issues_to_sarif(self):
        from knip_to_sarif import convert_knip_json

        document = convert_knip_json(
            {
                "issues": [
                    {
                        "file": "/repo/src/index.ts",
                        "unlisted": [{"name": "missing-package", "line": 2, "col": 15}],
                        "unresolved": [{"name": "./missing.js", "line": 1, "col": 15}],
                        "binaries": [],
                    },
                    {
                        "file": "/repo/package.json",
                        "unlisted": [],
                        "unresolved": [],
                        "binaries": [{"name": "missing-bin"}, {"name": "x" * 600, "line": "3", "column": "42"}],
                    },
                ]
            },
            base_dir="/repo",
        )

        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["properties"]["sigilixToolId"], "knip")
        results = run["results"]
        self.assertEqual(
            [result["ruleId"] for result in results],
            ["knip/unlisted", "knip/unresolved", "knip/binaries", "knip/binaries"],
        )
        self.assertEqual(results[0]["level"], "error")
        self.assertIn("missing-package", results[0]["message"]["text"])
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/index.ts")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 2)
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"], 15)
        self.assertIn("./missing.js", results[1]["message"]["text"])
        self.assertEqual(results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "package.json")
        self.assertEqual(results[3]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertEqual(results[3]["locations"][0]["physicalLocation"]["region"]["startColumn"], 42)
        self.assertLessEqual(len(results[3]["message"]["text"]), 540)
        self.assertTrue(results[3]["message"]["text"].endswith("...'."))

    def test_knip_converter_normalizes_escaped_paths(self):
        from knip_to_sarif import convert_knip_json

        document = convert_knip_json(
            {"issues": [{"file": "../../etc/passwd", "unresolved": [{"name": "./missing.js"}]}]},
            base_dir="/repo",
        )

        location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], ".")


if __name__ == "__main__":
    unittest.main()
