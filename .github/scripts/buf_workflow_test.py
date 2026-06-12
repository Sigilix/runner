import json
import os
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
SCRIPT_DIR = os.path.join(ROOT, ".github", "scripts")


class BufWorkflowTest(unittest.TestCase):
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

    def test_buf_is_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = self.manifest_rows()

        self.assertIn("        default: true\n", self.workflow_input_block("buf"))
        self.assertIn("BUF_ENABLED: ${{ inputs.buf }}", text)
        self.assertIn('BUF_VERSION: "1.70.0"', text)
        self.assertIn(
            'BUF_LINUX_X86_64_SHA256: "e2bbcdd324da09c16a15963dc2dae0525c955c05dc118223cf732f4f7509c5e6"',
            text,
        )
        self.assertEqual(rows["buf"], {"id": "buf", "env": "BUF_ENABLED", "output": "buf.sarif"})

    def test_workflow_delegates_buf_and_oxlint_to_runner_scripts(self):
        expectations = {
            "Run Buf to SARIF": "run_buf.sh",
            "Run Oxlint to SARIF": "run_oxlint.sh",
        }

        for step_name, script_name in expectations.items():
            block = self.workflow_step_block(step_name)
            self.assertIn(f'bash "$RUNNER_DIR/.github/scripts/{script_name}"', block)

    def test_buf_script_pins_binary_and_disambiguates_failures(self):
        text = self.script_text("run_buf.sh")

        self.assertIn("BUF_VERSION", text)
        self.assertIn("BUF_LINUX_X86_64_SHA256", text)
        self.assertIn("buf-Linux-x86_64", text)
        self.assertIn("unsupported runner platform", text)
        self.assertIn("sha256sum -c --strict", text)
        self.assertLess(text.index("sha256sum -c --strict"), text.index('"$buf_bin" --version'))
        self.assertIn("No Protobuf files found", text)
        self.assertIn("Using runner-owned Buf v2 MINIMAL config", text)
        self.assertIn("mktemp -d", text)
        self.assertIn("--config \"$buf_config\"", text)
        self.assertIn("buf_to_sarif.py", text)
        self.assertIn("sigilix_sarif_contract.py", text)

    def test_buf_wrapper_generates_temp_config_and_converts_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            sarif_dir = os.path.join(tmpdir, "sarif")
            runner_temp = os.path.join(tmpdir, "runner-temp")
            bin_dir = os.path.join(tmpdir, "bin")
            proto_dir = os.path.join(source_dir, "proto")
            os.makedirs(proto_dir)
            os.makedirs(sarif_dir)
            os.makedirs(runner_temp)
            os.makedirs(bin_dir)
            with open(os.path.join(proto_dir, "bad.proto"), "w", encoding="utf-8") as handle:
                handle.write('syntax = "proto3";\npackage foo;\n')
            self.write_executable(os.path.join(bin_dir, "uname"), "#!/usr/bin/env bash\nif [ \"$1\" = \"-s\" ]; then echo Linux; else echo x86_64; fi\n")
            self.write_executable(
                os.path.join(bin_dir, "curl"),
                "#!/usr/bin/env bash\nout=''\nwhile [ \"$#\" -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; out=\"$1\"; fi; shift || true; done\n"
                "cat > \"$out\" <<'EOF'\n#!/usr/bin/env bash\nif [ \"$1\" = \"--version\" ]; then echo 1.70.0; exit 0; fi\n"
                "printf '{\"path\":\"proto/bad.proto\",\"start_line\":2,\"start_column\":1,\"type\":\"PACKAGE_DIRECTORY_MATCH\",\"message\":\"bad package\"}\\n'\n"
                "exit 100\nEOF\nchmod +x \"$out\"\n",
            )
            self.write_executable(os.path.join(bin_dir, "sha256sum"), "#!/usr/bin/env bash\ncat >/dev/null\nexit 0\n")

            result = subprocess.run(
                ["bash", os.path.join(SCRIPT_DIR, "run_buf.sh")],
                cwd=source_dir,
                env={
                    "PATH": bin_dir + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
                    "BUF_LINUX_X86_64_SHA256": "e2bbcdd324da09c16a15963dc2dae0525c955c05dc118223cf732f4f7509c5e6",
                    "BUF_VERSION": "1.70.0",
                    "RESULT_CAP": "500",
                    "RUNNER_DIR": ROOT,
                    "RUNNER_TEMP": runner_temp,
                    "SARIF_DIR": sarif_dir,
                    "SOURCE_DIR": source_dir,
                },
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("Using runner-owned Buf v2 MINIMAL config", result.stdout)
            with open(os.path.join(sarif_dir, "buf.sarif"), encoding="utf-8") as handle:
                document = json.load(handle)

        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "PACKAGE_DIRECTORY_MATCH")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "proto/bad.proto")

    def write_executable(self, path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent(content))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


class BufConverterTest(unittest.TestCase):
    def assert_sigilix_properties(self, document):
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        properties = document["runs"][0]["tool"]["driver"]["properties"]
        self.assertEqual(properties["sigilixToolId"], "buf")
        self.assertEqual(properties["sigilixSource"], "deterministic-tool")

    def test_buf_json_lines_convert_to_sarif(self):
        from buf_to_sarif import convert_buf_json_lines

        document = convert_buf_json_lines(
            '{"path":"proto/bad.proto","start_line":3,"start_column":9,'
            '"end_line":3,"end_column":17,"type":"MESSAGE_PASCAL_CASE",'
            '"message":"Message name should be PascalCase."}\n'
            '{"path":"proto/bad.proto","start_line":4,"start_column":10,'
            '"type":"FIELD_LOWER_SNAKE_CASE","message":"Field should be lower_snake_case."}\n',
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document)
        results = document["runs"][0]["results"]
        self.assertEqual([result["ruleId"] for result in results], ["MESSAGE_PASCAL_CASE", "FIELD_LOWER_SNAKE_CASE"])
        self.assertEqual([result["level"] for result in results], ["warning", "warning"])
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "proto/bad.proto")
        self.assertEqual(
            results[0]["locations"][0]["physicalLocation"]["region"],
            {"startLine": 3, "startColumn": 9, "endLine": 3, "endColumn": 17},
        )

    def test_buf_converter_rejects_invalid_json_lines(self):
        from buf_to_sarif import convert_buf_json_lines

        with self.assertRaises(ValueError):
            convert_buf_json_lines('{"path":"ok.proto"}\nnot-json\n', base_dir="/repo")


if __name__ == "__main__":
    unittest.main()
