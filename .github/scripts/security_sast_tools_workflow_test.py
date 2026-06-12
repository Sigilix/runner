import json
import os
import re
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
SCRIPT_DIR = os.path.join(ROOT, ".github", "scripts")

SAST_TOOL_OUTPUTS = {
    "opengrep": "opengrep.sarif",
    "brakeman": "brakeman.sarif",
}


class SecuritySastToolsWorkflowTest(unittest.TestCase):
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

    def test_sast_tools_are_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = self.manifest_rows()

        for tool_id, output in SAST_TOOL_OUTPUTS.items():
            env_var = tool_id.upper().replace("-", "_") + "_ENABLED"
            self.assertIn("        default: true\n", self.workflow_input_block(tool_id))
            self.assertIn(f"{env_var}: ${{{{ inputs.{tool_id} }}}}", text)
            self.assertEqual(rows[tool_id], {"id": tool_id, "env": env_var, "output": output})

        self.assertIn('OPENGREP_VERSION: "1.22.0"', text)
        self.assertIn("OPENGREP_MANYLINUX_X86_SHA256:", text)
        self.assertIn("OPENGREP_MANYLINUX_AARCH64_SHA256:", text)
        self.assertIn('BRAKEMAN_VERSION: "8.0.4"', text)
        self.assertIn("BRAKEMAN_GEM_SHA256:", text)
        self.assertIn('RACC_VERSION: "1.8.1"', text)
        self.assertIn("RACC_GEM_SHA256:", text)

    def test_workflow_delegates_sast_tools_to_runner_scripts(self):
        expectations = {
            "Run OpenGrep to SARIF": "run_opengrep.sh",
            "Run Brakeman to SARIF": "run_brakeman.sh",
        }

        for step_name, script_name in expectations.items():
            block = self.workflow_step_block(step_name)
            self.assertIn(f'bash "$RUNNER_DIR/.github/scripts/{script_name}"', block)

    def test_opengrep_wrapper_uses_pinned_release_and_configured_rulesets(self):
        text = self.script_text("run_opengrep.sh")

        self.assertIn("OPENGREP_VERSION", text)
        self.assertIn("OPENGREP_MANYLINUX_X86_SHA256", text)
        self.assertIn("OPENGREP_MANYLINUX_AARCH64_SHA256", text)
        self.assertIn('case "$(uname -m)" in', text)
        self.assertIn("opengrep_manylinux_x86", text)
        self.assertIn("opengrep_manylinux_aarch64", text)
        self.assertIn("sha256sum -c --strict", text)
        self.assertIn("OpenGrep installed version mismatch", text)
        self.assertIn("[^0-9.])${OPENGREP_VERSION}([^0-9.]", text)
        self.assertIn("parse_opengrep_configs", text)
        self.assertIn('"$trimmed" == -*', text)
        self.assertIn(': "${OPENGREP_CONFIG:=p/security-audit,p/owasp-top-ten}"', text)
        self.assertIn("--sarif-output=\"$raw\"", text)
        self.assertIn("--config", text)
        self.assertIn("--exclude=node_modules", text)
        self.assertIn("sigilix_sarif_contract.py", text)

    def test_brakeman_wrapper_detects_rails_before_install_and_ignores_caller_config(self):
        text = self.script_text("run_brakeman.sh")

        self.assertIn("BRAKEMAN_VERSION", text)
        self.assertIn("discover_rails_roots", text)
        self.assertIn("config/application.rb", text)
        self.assertIn("No Rails roots found", text)
        self.assertIn('export GEM_HOME="$RUNNER_TEMP/brakeman-gems"', text)
        self.assertIn("fetch_verified_gem", text)
        self.assertIn('rm -f "$path"', text)
        self.assertIn("gem fetch --norc --clear-sources --source https://rubygems.org", text)
        self.assertIn("sha256sum -c --strict", text)
        self.assertIn("gem install --norc --local --no-document --install-dir \"$GEM_HOME\"", text)
        self.assertIn("Skipping Brakeman root with traversal segments", text)
        self.assertIn("resolves outside source directory", text)
        self.assertIn('--path "$root_abs"', text)
        self.assertIn("--config-file \"$brakeman_config\"", text)
        self.assertIn("--ignore-config \"$brakeman_ignore\"", text)
        self.assertIn("--show-ignored", text)
        self.assertIn("--no-exit-on-warn", text)
        self.assertIn("--no-exit-on-error", text)
        self.assertIn("--format sarif", text)
        self.assertIn("[^0-9.])${BRAKEMAN_VERSION}([^0-9.]", text)
        self.assertIn("Brakeman SARIF path normalization failed", text)
        self.assertIn("Brakeman failed to copy SARIF output", text)
        self.assertIn("Brakeman SARIF merge failed", text)
        self.assertIn("sigilix_sarif_merge.py", text)
        self.assertIn("sigilix_sarif_contract.py", text)


class BrakemanSarifPathTest(unittest.TestCase):
    def test_brakeman_sarif_paths_are_prefixed_for_nested_rails_roots(self):
        from brakeman_sarif_paths import normalize_brakeman_sarif_paths

        with tempfile.TemporaryDirectory() as tmpdir:
            app_dir = os.path.join(tmpdir, "services", "billing")
            os.makedirs(app_dir)
            document = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Brakeman"}},
                        "results": [
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app/models/user.rb"},
                                        }
                                    }
                                ],
                            },
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": f"file://localhost{app_dir}/app/controllers/users_controller.rb",
                                            },
                                        }
                                    }
                                ],
                            },
                        ],
                    }
                ],
            }

            normalized = normalize_brakeman_sarif_paths(document, root="services/billing", base_dir=tmpdir)

        run = normalized["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Brakeman (services/billing)")
        uris = [
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for result in run["results"]
        ]
        self.assertEqual(
            uris,
            [
                "services/billing/app/models/user.rb",
                "services/billing/app/controllers/users_controller.rb",
            ],
        )

    def test_brakeman_sarif_path_normalizer_rejects_invalid_documents(self):
        from brakeman_sarif_paths import normalize_brakeman_sarif_paths

        with self.assertRaises(ValueError):
            normalize_brakeman_sarif_paths([], root=".", base_dir=".")


if __name__ == "__main__":
    unittest.main()
