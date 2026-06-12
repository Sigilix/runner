import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
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

    def write_file(self, path, text):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def runner_env(self, source_dir, sarif_dir, runner_temp, pylint_version):
        env = os.environ.copy()
        env.update(
            {
                "PYLINT_VERSION": pylint_version,
                "RESULT_CAP": "50",
                "RUNNER_DIR": ROOT,
                "RUNNER_TEMP": runner_temp,
                "SARIF_DIR": sarif_dir,
                "SOURCE_DIR": source_dir,
            }
        )
        return env

    def read_sarif_results(self, sarif_dir):
        with open(os.path.join(sarif_dir, "pylint.sarif"), encoding="utf-8") as handle:
            return json.load(handle)["runs"][0]["results"]

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

    def test_pylint_runner_emits_empty_sarif_for_malformed_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = os.path.join(tmp, "src")
            sarif_dir = os.path.join(tmp, "sarif")
            runner_temp = os.path.join(tmp, "runner-temp")
            os.makedirs(source_dir)
            os.makedirs(sarif_dir)
            os.makedirs(runner_temp)
            self.write_file(os.path.join(source_dir, "app.py"), "missing_name\n")

            result = subprocess.run(
                ["bash", PYLINT_RUNNER_PATH],
                cwd=ROOT,
                env=self.runner_env(source_dir, sarif_dir, runner_temp, "4.0"),
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Pylint version must be a pinned x.y.z version", result.stdout)
            self.assertEqual(self.read_sarif_results(sarif_dir), [])

    def test_pylint_runner_accepts_version_suffix_before_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = os.path.join(tmp, "src")
            sarif_dir = os.path.join(tmp, "sarif")
            runner_temp = os.path.join(tmp, "runner-temp")
            fake_bin = os.path.join(tmp, "bin")
            marker = os.path.join(tmp, "scan-ran")
            os.makedirs(source_dir)
            os.makedirs(sarif_dir)
            os.makedirs(runner_temp)
            os.makedirs(fake_bin)
            self.write_file(os.path.join(source_dir, "app.py"), "missing_name\n")
            self.write_file(os.path.join(fake_bin, "python3"), self.fake_python3_script())
            os.chmod(os.path.join(fake_bin, "python3"), 0o755)
            env = self.runner_env(source_dir, sarif_dir, runner_temp, "4.0.5")
            env["PATH"] = fake_bin + os.pathsep + env["PATH"]
            env["PYLINT_FAKE_MARKER"] = marker

            result = subprocess.run(
                ["bash", PYLINT_RUNNER_PATH],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(os.path.exists(marker))
            self.assertEqual(self.read_sarif_results(sarif_dir), [])

    def fake_python3_script(self):
        real_python = shlex.quote(sys.executable)
        return f"""#!/usr/bin/env bash
set -euo pipefail
if [ "${{1:-}}" = "-m" ] && [ "${{2:-}}" = "venv" ]; then
  mkdir -p "$3/bin"
  cat > "$3/bin/python" <<'PYFAKE'
#!/usr/bin/env bash
set -euo pipefail
if [ "${{1:-}}" = "-m" ] && [ "${{2:-}}" = "pip" ]; then
  exit 0
fi
if [ "${{1:-}}" = "-m" ] && [ "${{2:-}}" = "pylint" ]; then
  if [ "${{3:-}}" = "--version" ]; then
    printf '%s\\n' 'pylint 4.0.5, astroid 4.0.2'
    exit 0
  fi
  if [ -n "${{PYLINT_FAKE_MARKER:-}}" ]; then
    printf '%s\\n' ran > "$PYLINT_FAKE_MARKER"
  fi
  printf '[]'
  exit 0
fi
exit 1
PYFAKE
  chmod +x "$3/bin/python"
  exit 0
fi
exec {real_python} "$@"
"""


if __name__ == "__main__":
    unittest.main()
