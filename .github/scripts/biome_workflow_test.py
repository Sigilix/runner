import json
import os
import re
import unittest


WORKFLOW_PATH = os.path.join(os.path.dirname(__file__), "..", "workflows", "scan.yml")
BIOME_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "biome-sigilix.jsonc")


class BiomeWorkflowRuntimeTest(unittest.TestCase):
    def workflow_text(self):
        with open(WORKFLOW_PATH, encoding="utf-8") as workflow:
            return workflow.read()

    def workflow_biome_block(self):
        text = self.workflow_text()
        match = re.search(
            r"(?ms)^      - name: Run Biome to SARIF\n"
            r".+?"
            r"(?=^      - name: Run Oxlint to SARIF)",
            text,
        )
        self.assertIsNotNone(match)
        return match.group(0)

    def workflow_input_block(self, input_name):
        pattern = rf"\n      {re.escape(input_name)}:\n(?P<block>(?:        .+\n)+)"
        match = re.search(pattern, self.workflow_text())
        self.assertIsNotNone(match)
        return match.group("block")

    def test_biome_defaults_on_after_runner_owned_hardening(self):
        self.assertIn("        default: true\n", self.workflow_input_block("biome"))

    def test_biome_uses_sigilix_configured_lint_mode(self):
        block = self.workflow_biome_block()

        self.assertIn('biome_config="$RUNNER_DIR/.github/config/biome-sigilix.jsonc"', block)
        self.assertIn('npx --yes "@biomejs/biome@${BIOME_VERSION}" lint . \\', block)
        self.assertNotIn('ci . \\', block)
        self.assertNotIn('mapfile -d', block)
        self.assertNotIn('"${files[@]}"', block)
        self.assertIn('--config-path "$biome_config" \\', block)
        self.assertIn("--vcs-use-ignore-file=false \\", block)
        self.assertIn("--files-ignore-unknown=true \\", block)
        self.assertIn("--no-errors-on-unmatched \\", block)
        self.assertIn("--reporter=sarif \\", block)
        self.assertIn('--reporter-file="$raw"; then', block)

    def test_biome_config_limits_files_and_generated_dirs(self):
        config = self.biome_config()
        includes = config["files"]["includes"]

        self.assertEqual(
            includes,
            [
                "**/*.js",
                "**/*.jsx",
                "**/*.mjs",
                "**/*.cjs",
                "**/*.ts",
                "**/*.tsx",
                "**/*.json",
                "**/*.jsonc",
                "!**/.git/**",
                "!**/node_modules/**",
                "!**/dist/**",
                "!**/build/**",
                "!**/coverage/**",
                "!**/.next/**",
                "!**/out/**",
            ],
        )

    def test_empty_tree_relies_on_biome_empty_sarif_output(self):
        block = self.workflow_biome_block()

        self.assertIn("--no-errors-on-unmatched \\", block)
        self.assertNotIn('printf \'{"version":"2.1.0","runs":[]}', block)
        self.assertIn('if [ -s "$raw" ]; then', block)

    def test_nonzero_scan_with_sarif_is_still_normalized(self):
        block = self.workflow_biome_block()

        scan_warning = 'echo "::warning::biome scan failed and produced no SARIF output'
        normalize = 'python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py"'
        self.assertIn(scan_warning, block)
        self.assertIn(normalize, block)
        self.assertLess(block.index(scan_warning), block.index(normalize))

    def test_biome_config_pins_explicit_correctness_rules(self):
        config = self.biome_config()

        self.assertEqual(set(config), {"$schema", "files", "formatter", "linter"})
        self.assertEqual(config["linter"]["rules"]["recommended"], False)
        correctness_rules = config["linter"]["rules"]["correctness"]
        self.assertEqual(
            set(correctness_rules),
            {
                "noInvalidConstructorSuper",
                "noUndeclaredVariables",
                "noUnreachable",
                "noUnusedVariables",
            },
        )
        self.assertNotIn("all", correctness_rules)
        self.assertTrue(all(level in {"error", "warn"} for level in correctness_rules.values()))

    def biome_config(self):
        with open(BIOME_CONFIG_PATH, encoding="utf-8") as handle:
            return json.loads(_strip_jsonc_comments(handle.read()))


def _strip_jsonc_comments(text):
    lines = []
    for line in text.splitlines():
        lines.append(re.sub(r"^\s*//.*$", "", line))
    return "\n".join(lines)


if __name__ == "__main__":
    unittest.main()
