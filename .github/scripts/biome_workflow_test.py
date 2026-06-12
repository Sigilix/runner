import json
import os
import re
import subprocess
import tempfile
import textwrap
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

    def workflow_biome_find_command(self):
        match = re.search(r'(?ms)^[ \t]+if ! (?P<command>find -P .+? > "\$files_list"); then', self.workflow_biome_block())
        self.assertIsNotNone(match)
        return match.group("command")

    def bash_env(self, **values):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **values}

    def test_biome_uses_sigilix_configured_lint_mode(self):
        block = self.workflow_biome_block()

        self.assertIn('biome_config="$RUNNER_DIR/.github/config/biome-sigilix.jsonc"', block)
        self.assertIn('npx --yes "@biomejs/biome@${BIOME_VERSION}" lint \\', block)
        self.assertNotIn('ci . \\', block)
        self.assertIn('--config-path "$biome_config" \\', block)
        self.assertIn("--vcs-use-ignore-file=false \\", block)
        self.assertIn("--files-ignore-unknown=true \\", block)
        self.assertIn("--no-errors-on-unmatched \\", block)
        self.assertIn("--reporter=sarif \\", block)
        self.assertIn('--reporter-file="$raw" \\', block)
        self.assertRegex(block, r"\n\s+-- \\\n\s+\"\$\{files\[@\]\}\"")

    def test_generated_directory_filter_excludes_nested_outputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for path in (
                "src/app.ts",
                "src/data.json",
                "packages/a/dist/app.ts",
                "packages/a/build/app.js",
                "packages/a/coverage/app.tsx",
                "apps/web/.next/app.jsx",
                "packages/a/out/app.mjs",
                "node_modules/pkg/app.ts",
            ):
                full_path = os.path.join(tmpdir, path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8"):
                    pass

            files_list = os.path.join(tmpdir, "biome-files")
            find_command = self.workflow_biome_find_command()
            self.assertIn("-print0", find_command)
            self.assertIn('> "$files_list"', find_command)
            subprocess.check_call(
                [
                    "bash",
                    "-c",
                    'files_list="$BIOME_FILES_LIST"\n' + find_command,
                ],
                cwd=tmpdir,
                env=self.bash_env(**{"BIOME_FILES_LIST": files_list}),
            )
            with open(files_list, "rb") as handle:
                selected = [entry.decode() for entry in handle.read().split(b"\0") if entry]

        self.assertEqual(selected, ["./src/app.ts", "./src/data.json"])

    def test_empty_tree_emits_empty_sarif_before_normalization(self):
        block = self.workflow_biome_block()

        self.assertIn('files_list="$RUNNER_TEMP/biome-files"', block)
        self.assertIn('printf \'{"version":"2.1.0","runs":[]}\' > "$raw"', block)
        self.assertIn('if [ -s "$raw" ]; then', block)

    def test_nonzero_scan_with_sarif_is_still_normalized(self):
        block = self.workflow_biome_block()

        scan_warning = 'echo "::warning::biome scan failed and produced no SARIF output'
        normalize = 'python3 "$RUNNER_DIR/.github/scripts/sigilix_sarif_contract.py"'
        self.assertIn(scan_warning, block)
        self.assertIn(normalize, block)
        self.assertLess(block.index(scan_warning), block.index(normalize))

    def test_biome_config_pins_explicit_correctness_rules(self):
        with open(BIOME_CONFIG_PATH, encoding="utf-8") as handle:
            config = json.loads(_strip_jsonc_comments(handle.read()))

        self.assertEqual(set(config), {"$schema", "formatter", "linter"})
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


def _strip_jsonc_comments(text):
    lines = []
    for line in text.splitlines():
        lines.append(re.sub(r"^\s*//.*$", "", line))
    return "\n".join(lines)


if __name__ == "__main__":
    unittest.main()
