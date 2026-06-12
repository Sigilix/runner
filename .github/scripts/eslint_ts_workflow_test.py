import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
ESLINT_CONFIG_PATH = os.path.join(ROOT, ".github", "config", "eslint-sigilix.config.mjs")
ESLINT_RUNNER_PATH = os.path.join(ROOT, ".github", "scripts", "run_eslint.sh")


class EslintTypeScriptWorkflowTest(unittest.TestCase):
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

    def workflow_eslint_block(self):
        match = re.search(
            r"(?ms)^      - name: Run ESLint to SARIF\n"
            r".+?"
            r"(?=^      - name: Run Ruff to SARIF)",
            self.workflow_text(),
        )
        self.assertIsNotNone(match)
        return match.group(0)

    def test_eslint_stays_default_on_and_delegates_to_runner_script(self):
        text = self.workflow_text()
        block = self.workflow_eslint_block()

        self.assertIn("        default: true\n", self.workflow_input_block("eslint"))
        self.assertIn("ESLINT_MODE: ${{ inputs.eslint-mode }}", block)
        self.assertIn('bash "$RUNNER_DIR/.github/scripts/run_eslint.sh"', block)
        self.assertIn("TYPESCRIPT_ESLINT_VERSION:", text)
        self.assertIn("TYPESCRIPT_VERSION:", text)
        self.assertIn("ESLINT_PLUGIN_SECURITY_VERSION:", text)
        self.assertIn("ESLINT_PLUGIN_UNICORN_VERSION:", text)

    def test_runner_uses_pinned_runner_owned_eslint_profile(self):
        text = self.read_file(ESLINT_RUNNER_PATH)

        self.assertIn('eslint_config="$RUNNER_DIR/.github/config/eslint-sigilix.config.mjs"', text)
        self.assertIn('runtime_eslint_config="$eslint_install_dir/eslint-sigilix.config.mjs"', text)
        self.assertIn('cp -f "$eslint_config" "$runtime_eslint_config"', text)
        self.assertIn('npm install --silent --prefix "$eslint_install_dir" --ignore-scripts --omit=optional', text)
        self.assertIn('files_list="$(mktemp "$RUNNER_TEMP/eslint-files.XXXXXX")"', text)
        self.assertIn('"eslint@${ESLINT_VERSION}"', text)
        self.assertIn('"typescript-eslint@${TYPESCRIPT_ESLINT_VERSION}"', text)
        self.assertIn('"typescript@${TYPESCRIPT_VERSION}"', text)
        self.assertIn('"eslint-plugin-security@${ESLINT_PLUGIN_SECURITY_VERSION}"', text)
        self.assertIn('"eslint-plugin-unicorn@${ESLINT_PLUGIN_UNICORN_VERSION}"', text)
        self.assertIn('--config "$runtime_eslint_config"', text)
        self.assertIn("--no-config-lookup", text)
        self.assertIn('"$eslint_bin" --format json --no-warn-ignored', text)
        self.assertNotIn("npm exec", text)
        self.assertNotIn("npx --yes", text)
        self.assertIn("repo-config", text)

    def test_runner_discovers_typescript_files_and_gates_typed_rules(self):
        text = self.read_file(ESLINT_RUNNER_PATH)

        for extension in ("*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.mts", "*.cts"):
            self.assertIn(f"-name '{extension}'", text)
        self.assertIn("tsconfig.json", text)
        self.assertIn("tsconfig.*.json", text)
        self.assertIn(".sigilix-eslint-tsconfig.json", text)
        self.assertIn("SIGILIX_ESLINT_TSCONFIG=", text)
        self.assertIn('SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"', text)
        self.assertNotIn("mapfile", text)

    def test_runner_owned_config_enables_ts_logic_security_rules(self):
        text = self.read_file(ESLINT_CONFIG_PATH)

        self.assertIn("typescript-eslint", text)
        self.assertIn("eslint-plugin-security", text)
        self.assertIn("eslint-plugin-unicorn", text)
        self.assertIn("no-undef", text)
        self.assertIn("no-unreachable", text)
        self.assertIn("@typescript-eslint/no-floating-promises", text)
        self.assertIn("@typescript-eslint/no-misused-promises", text)
        self.assertIn("@typescript-eslint/await-thenable", text)
        self.assertIn("security/detect-eval-with-expression", text)
        self.assertIn("security/detect-new-buffer", text)
        self.assertIn("unicorn/no-instanceof-builtins", text)
        self.assertIn("process.env.SIGILIX_ESLINT_TSCONFIG", text)

    def test_config_exports_typed_rules_only_when_tsconfig_env_is_set(self):
        without_tsconfig = self.import_config_rule_ids("")
        with_tsconfig = self.import_config_rule_ids("/tmp/sigilix-eslint-tsconfig.json")

        self.assertNotIn("@typescript-eslint/no-floating-promises", without_tsconfig)
        self.assertIn("@typescript-eslint/no-floating-promises", with_tsconfig)
        self.assertIn("@typescript-eslint/no-misused-promises", with_tsconfig)
        self.assertIn("@typescript-eslint/await-thenable", with_tsconfig)

    def import_config_rule_ids(self, tsconfig_path):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "eslint-sigilix.config.mjs")
            node_modules = os.path.join(tmpdir, "node_modules")
            os.makedirs(node_modules)
            shutil.copyfile(ESLINT_CONFIG_PATH, config_path)
            self.write_stub_package(node_modules, "eslint-plugin-security", "module.exports = { rules: {} };\n")
            self.write_stub_package(node_modules, "eslint-plugin-unicorn", "module.exports = { rules: {} };\n")
            self.write_stub_package(
                node_modules,
                "typescript-eslint",
                "module.exports = { parser: {}, plugin: { rules: {} }, config: (...configs) => configs };\n",
            )
            script = (
                "import config from './eslint-sigilix.config.mjs';"
                "const rules = config.flatMap((entry) => Object.keys(entry.rules || {}));"
                "console.log(JSON.stringify(rules));"
            )
            env = os.environ.copy()
            env["SIGILIX_ESLINT_TSCONFIG"] = tsconfig_path
            output = subprocess.check_output(
                ["node", "--input-type=module", "--eval", script],
                cwd=tmpdir,
                env=env,
                text=True,
            )
            return set(json.loads(output))

    def write_stub_package(self, node_modules, name, index_text):
        package_dir = os.path.join(node_modules, name)
        os.makedirs(package_dir)
        with open(os.path.join(package_dir, "package.json"), "w", encoding="utf-8") as handle:
            handle.write('{"main":"index.cjs"}\n')
        with open(os.path.join(package_dir, "index.cjs"), "w", encoding="utf-8") as handle:
            handle.write(index_text)


if __name__ == "__main__":
    unittest.main()
