import json
import os
import re
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
AST_GREP_CONFIG_DIR = os.path.join(ROOT, ".github", "config", "ast-grep-sigilix")
AST_GREP_RUNNER_PATH = os.path.join(ROOT, ".github", "scripts", "run_ast_grep.sh")


class AstGrepWorkflowTest(unittest.TestCase):
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

    def workflow_ast_grep_block(self):
        match = re.search(
            r"(?ms)^      - name: Run ast-grep to SARIF\n"
            r".+?"
            r"(?=^      - name: Build scan manifest)",
            self.workflow_text(),
        )
        self.assertIsNotNone(match)
        return match.group(0)

    def manifest_rows(self):
        with open(MANIFEST_PATH, encoding="utf-8") as handle:
            return json.load(handle)["tools"]

    def ast_grep_config_text(self, relative_path):
        return self.read_file(os.path.join(AST_GREP_CONFIG_DIR, relative_path))

    def ast_grep_runner_text(self):
        return self.read_file(AST_GREP_RUNNER_PATH)

    def test_ast_grep_is_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.manifest_rows()}

        self.assertIn("        default: true\n", self.workflow_input_block("ast-grep"))
        self.assertIn("AST_GREP_ENABLED: ${{ inputs.ast-grep }}", text)
        self.assertEqual(rows["ast-grep"], {"id": "ast-grep", "env": "AST_GREP_ENABLED", "output": "ast-grep.sarif"})

    def test_ast_grep_install_uses_verified_npm_tarballs(self):
        text = self.ast_grep_runner_text()
        workflow = self.workflow_text()

        self.assertIn('AST_GREP_VERSION: "0.43.0"', workflow)
        self.assertIn("AST_GREP_NPM_INTEGRITY:", workflow)
        self.assertIn("AST_GREP_LINUX_X64_GNU_INTEGRITY:", workflow)
        self.assertIn("DETECT_LIBC_NPM_INTEGRITY:", workflow)
        self.assertIn("npm pack --silent --pack-destination \"$ast_grep_pack_dir\"", text)
        self.assertIn('[[ ! "$AST_GREP_VERSION" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]', text)
        self.assertIn("hashlib.sha512", text)
        self.assertNotIn("openssl", text)
        self.assertIn('"@ast-grep/cli@${AST_GREP_VERSION}"', text)
        self.assertIn('"@ast-grep/cli-linux-x64-gnu@${AST_GREP_VERSION}"', text)
        self.assertIn('"detect-libc@${DETECT_LIBC_VERSION}"', text)
        self.assertIn('[ "$(sri_sha512 "$ast_grep_package")" != "$AST_GREP_NPM_INTEGRITY" ]', text)
        self.assertIn('[ "$(sri_sha512 "$ast_grep_binding_package")" != "$AST_GREP_LINUX_X64_GNU_INTEGRITY" ]', text)
        self.assertIn('[ "$(sri_sha512 "$detect_libc_package")" != "$DETECT_LIBC_NPM_INTEGRITY" ]', text)
        self.assertIn('npm install --silent --prefix "$ast_grep_install_dir" --ignore-scripts --omit=optional', text)
        self.assertIn('ast_grep_bin="$ast_grep_install_dir/node_modules/.bin/ast-grep"', text)
        self.assertIn('if ! ast_grep_version="$("$ast_grep_bin" --version 2>/dev/null)"; then', text)
        self.assertIn('[ "$ast_grep_detected_version" != "$AST_GREP_VERSION" ]', text)
        self.assertNotIn("npx --yes", text)

    def test_ast_grep_scan_uses_runner_rules_and_sarif_contract(self):
        text = self.ast_grep_runner_text()

        self.assertIn('ast_grep_config="$RUNNER_DIR/.github/config/ast-grep-sigilix/sgconfig.yml"', text)
        self.assertIn('bash "$RUNNER_DIR/.github/scripts/run_ast_grep.sh"', self.workflow_ast_grep_block())
        self.assertIn('--config "$ast_grep_config"', text)
        self.assertIn("--format sarif", text)
        self.assertIn("--no-ignore hidden --no-ignore vcs --no-ignore parent --no-ignore exclude --no-ignore global --no-ignore dot", text)
        self.assertNotIn("--follow", text)
        self.assertNotIn("--max-results", text)
        for include in ("*.js", "*.jsx", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.mts", "*.cts"):
            self.assertIn(f"--globs '{include}'", text)
        for excluded in (".git", "node_modules", "dist", "build", "coverage", ".next", "out", ".venv", "vendor", "__pycache__", ".terraform"):
            self.assertIn(f"--globs '!**/{excluded}/**'", text)
        self.assertIn("ast-grep \"$raw\" \"$out\" --cap \"$RESULT_CAP\" --ensure-run", text)

    def test_ast_grep_rule_pack_targets_async_array_logic_with_tests(self):
        sgconfig = self.ast_grep_config_text("sgconfig.yml")
        rules = self.ast_grep_config_text("rules/js-ts-async-array-logic.yml")
        await_test = self.ast_grep_config_text("rule-tests/await-for-each-async-callback-test.yml")
        predicate_test = self.ast_grep_config_text("rule-tests/async-array-predicate-test.yml")

        self.assertIn("ruleDirs:", sgconfig)
        self.assertIn("testConfigs:", sgconfig)
        for rule_id in (
            "js-await-for-each-async-callback",
            "ts-await-for-each-async-callback",
            "tsx-await-for-each-async-callback",
            "js-async-array-predicate",
            "ts-async-array-predicate",
            "tsx-async-array-predicate",
        ):
            self.assertIn(f"id: {rule_id}", rules)
        self.assertIn("forEach does not await async callbacks", rules)
        self.assertIn("Async array predicate callbacks return truthy Promise objects", rules)
        self.assertIn("valid:", await_test)
        self.assertIn("invalid:", await_test)
        self.assertIn("Promise.all(items.map(async", await_test)
        self.assertIn("await items.forEach(async", await_test)
        self.assertIn("items.filter(async", predicate_test)
        self.assertIn("items.some(async", predicate_test)
        self.assertIn("items.every(async", predicate_test)
        self.assertIn("items.find(async", predicate_test)
        self.assertIn("items.findIndex(async", predicate_test)
        self.assertIn("items.findLast(async", predicate_test)
        self.assertIn("items.findLastIndex(async", predicate_test)


if __name__ == "__main__":
    unittest.main()
