import json
import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
REGAL_CONFIG_PATH = os.path.join(ROOT, ".github", "config", "regal-sigilix.yaml")
SCRIPT_DIR = os.path.join(ROOT, ".github", "scripts")


class PolicyIacToolsWorkflowTest(unittest.TestCase):
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

    def test_regal_is_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = self.manifest_rows()

        self.assertIn("        default: true\n", self.workflow_input_block("regal"))
        self.assertIn("REGAL_ENABLED: ${{ inputs.regal }}", text)
        self.assertIn('REGAL_VERSION: "0.41.1"', text)
        self.assertIn("REGAL_LINUX_X86_64_SHA256:", text)
        self.assertEqual(rows["regal"], {"id": "regal", "env": "REGAL_ENABLED", "output": "regal.sarif"})

    def test_workflow_delegates_policy_iac_tools_to_runner_scripts(self):
        expectations = {
            "Run zizmor to SARIF": "run_zizmor.sh",
            "Run Hadolint to SARIF": "run_hadolint.sh",
            "Run Regal to SARIF": "run_regal.sh",
        }

        for step_name, script_name in expectations.items():
            block = self.workflow_step_block(step_name)
            self.assertIn(f'bash "$RUNNER_DIR/.github/scripts/{script_name}"', block)

    def test_regal_wrapper_uses_high_confidence_sigilix_profile(self):
        text = self.script_text("run_regal.sh")
        config = self.read_file(REGAL_CONFIG_PATH)

        self.assertIn("REGAL_VERSION", text)
        self.assertIn("REGAL_LINUX_X86_64_SHA256", text)
        self.assertIn("regal_Linux_x86_64", text)
        self.assertIn("sha256sum -c --strict", text)
        self.assertIn("Regal installed version mismatch", text)
        self.assertIn("discover_rego_files", text)
        self.assertIn("No Rego files found", text)
        self.assertIn('regal_config="$RUNNER_DIR/.github/config/regal-sigilix.yaml"', text)
        self.assertIn("--config-file \"$regal_config\"", text)
        for category in ("idiomatic", "style", "performance", "testing", "custom"):
            self.assertIn(f"--disable-category {category}", text)
        self.assertIn("--format sarif", text)
        self.assertIn("--output-file \"$raw\"", text)
        self.assertIn("sigilix_sarif_contract.py", text)
        self.assertIn("use-rego-v1:", config)
        self.assertIn("level: ignore", config)
        self.assertIn("node_modules", config)
        self.assertIn(".terraform", config)

    def test_zizmor_and_hadolint_wrappers_preserve_sarif_contracts(self):
        zizmor = self.script_text("run_zizmor.sh")
        hadolint = self.script_text("run_hadolint.sh")

        self.assertIn("ZIZMOR_VERSION", zizmor)
        self.assertIn("python3 -m pip install --quiet", zizmor)
        self.assertIn("zizmor --format sarif .", zizmor)
        self.assertIn("sigilix_sarif_contract.py", zizmor)
        self.assertIn("HADOLINT_VERSION", hadolint)
        self.assertIn("hadolint-linux-x86_64", hadolint)
        self.assertIn("Dockerfile.*", hadolint)
        self.assertIn("--no-fail --format sarif", hadolint)
        self.assertIn("sigilix_sarif_contract.py", hadolint)


if __name__ == "__main__":
    unittest.main()
