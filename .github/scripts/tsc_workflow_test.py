import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOW_PATH = os.path.join(ROOT, ".github", "workflows", "scan.yml")
MANIFEST_PATH = os.path.join(ROOT, ".github", "config", "tool-manifest.json")
TSC_RUNNER_PATH = os.path.join(ROOT, ".github", "scripts", "run_tsc.sh")
FAKE_TYPESCRIPT_TARBALL = b"fake typescript package\n"
FAKE_TYPESCRIPT_INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(FAKE_TYPESCRIPT_TARBALL).digest()).decode("ascii")


class TypeScriptCompilerWorkflowTest(unittest.TestCase):
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

    def workflow_tsc_block(self):
        match = re.search(
            r"(?ms)^      - name: Run TypeScript compiler to SARIF\n"
            r".+?"
            r"(?=^      - name: Run Ruff to SARIF)",
            self.workflow_text(),
        )
        self.assertIsNotNone(match)
        return match.group(0)

    def manifest_rows(self):
        with open(MANIFEST_PATH, encoding="utf-8") as handle:
            return json.load(handle)["tools"]

    def runner_env(self, source_dir, sarif_dir, runner_temp, npm_bin):
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{os.path.dirname(npm_bin)}:{env['PATH']}",
                "RESULT_CAP": "50",
                "RUNNER_DIR": ROOT,
                "RUNNER_TEMP": runner_temp,
                "SARIF_DIR": sarif_dir,
                "SOURCE_DIR": source_dir,
                "TYPESCRIPT_NPM_INTEGRITY": FAKE_TYPESCRIPT_INTEGRITY,
                "TYPESCRIPT_VERSION": "6.0.3",
            }
        )
        return env

    def test_tsc_is_default_on_and_manifested(self):
        text = self.workflow_text()
        rows = {row["id"]: row for row in self.manifest_rows()}

        self.assertIn("        default: true\n", self.workflow_input_block("tsc"))
        self.assertIn("TSC_ENABLED: ${{ inputs.tsc }}", text)
        self.assertEqual(rows["tsc"], {"id": "tsc", "env": "TSC_ENABLED", "output": "tsc.sarif"})

    def test_tsc_workflow_delegates_to_runner_script(self):
        block = self.workflow_tsc_block()
        text = self.read_file(TSC_RUNNER_PATH)

        self.assertIn('bash "$RUNNER_DIR/.github/scripts/run_tsc.sh"', block)
        self.assertIn("TYPESCRIPT_NPM_INTEGRITY", self.workflow_text())
        self.assertIn('"typescript@${TYPESCRIPT_VERSION}"', text)
        self.assertIn("npm pack --silent --pack-destination", text)
        self.assertIn("verify_package_integrity", text)
        self.assertIn("npm install --silent --prefix \"$tsc_install_dir\" --ignore-scripts --omit=optional", text)
        self.assertIn("'^(Version|v)[[:space:]]*[0-9]+[.][0-9]+[.][0-9]+'", text)
        self.assertIn("--noEmit", text)
        self.assertIn("--pretty false", text)
        self.assertIn("--skipLibCheck", text)
        self.assertIn("tsc_to_sarif.py", text)
        self.assertIn("-name 'tsconfig.json'", text)
        self.assertIn("-name 'tsconfig.*.json'", text)
        self.assertNotIn("npm exec", text)
        self.assertNotIn("npx --yes", text)

    def test_tsc_converter_maps_compiler_diagnostics_to_sarif(self):
        from tsc_to_sarif import convert_tsc_text

        document = convert_tsc_text(
            "\n".join(
                [
                    "src/index.ts(3,7): error TS2322: Type 'string' is not assignable to type 'number'.",
                    "src/index.ts(1,21): error TS2307: Cannot find module 'missing' or its corresponding type declarations.",
                    "src/index.ts(5,21): error TS2307: Cannot find module '@types/react-dom' or its corresponding type declarations.",
                    "src/index.ts(4,21): error TS2307: Cannot find module './internal' or its corresponding type declarations.",
                    "src/index.ts(2,22): error TS7016: Could not find a declaration file for module 'legacy'.",
                ]
            ),
            base_dir="/repo",
        )

        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["properties"]["sigilixToolId"], "tsc")
        results = run["results"]
        self.assertEqual([result["ruleId"] for result in results], ["tsc/TS2322", "tsc/TS2307"])
        self.assertIn("TS2307", convert_tsc_text.__globals__["DEPENDENCY_NOISE_CODES"])
        self.assertIn("TS7016", convert_tsc_text.__globals__["DEPENDENCY_NOISE_CODES"])
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/index.ts")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"], 7)
        self.assertIn("not assignable", results[0]["message"]["text"])
        self.assertIn("./internal", results[1]["message"]["text"])

    def test_tsc_converter_drops_diagnostics_outside_source_root(self):
        from tsc_to_sarif import convert_tsc_text

        with tempfile.TemporaryDirectory() as tmpdir:
            document = convert_tsc_text(
                "\n".join(
                    [
                        "src/index.ts(3,7): error TS2322: Type 'string' is not assignable to type 'number'.",
                        "../outside.ts(1,1): error TS1005: ';' expected.",
                    ]
                ),
                base_dir=tmpdir,
            )

        results = document["runs"][0]["results"]
        self.assertEqual([result["ruleId"] for result in results], ["tsc/TS2322"])

    def test_tsc_runner_converts_type_errors_and_filters_missing_dependency_noise(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = os.path.join(tmpdir, "source")
            sarif_dir = os.path.join(tmpdir, "sarif")
            runner_temp = os.path.join(tmpdir, "temp")
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(os.path.join(source_dir, "src"))
            os.makedirs(sarif_dir)
            os.makedirs(runner_temp)
            os.makedirs(bin_dir)
            with open(os.path.join(source_dir, "tsconfig.json"), "w", encoding="utf-8") as handle:
                handle.write('{"include":["src/**/*.ts"]}\n')
            with open(os.path.join(source_dir, "src", "index.ts"), "w", encoding="utf-8") as handle:
                handle.write('const value: number = "nope";\n')
            npm_bin = os.path.join(bin_dir, "npm")
            self.write_fake_npm(npm_bin)

            subprocess.check_call(["bash", TSC_RUNNER_PATH], env=self.runner_env(source_dir, sarif_dir, runner_temp, npm_bin))

            with open(os.path.join(sarif_dir, "tsc.sarif"), encoding="utf-8") as handle:
                document = json.load(handle)
            results = document["runs"][0]["results"]
            self.assertEqual([result["ruleId"] for result in results], ["tsc/TS2322"])

    def write_fake_npm(self, path):
        script = r'''#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "pack" ]; then
  destination=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--pack-destination" ]; then
      destination="$2"
      shift 2
    else
      shift
    fi
  done
  mkdir -p "$destination"
  printf '%s' 'fake typescript package
' > "$destination/typescript-6.0.3.tgz"
  printf '%s\n' 'typescript-6.0.3.tgz'
  exit 0
fi
prefix=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--prefix" ]; then
    prefix="$2"
    shift 2
  else
    shift
  fi
done
mkdir -p "$prefix/node_modules/.bin"
cat > "$prefix/node_modules/.bin/tsc" <<'TSCSH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' 'Version 6.0.3'
  exit 0
fi
printf '%s\n' "src/index.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'."
printf '%s\n' "src/index.ts(1,21): error TS2307: Cannot find module 'missing' or its corresponding type declarations."
exit 2
TSCSH
chmod +x "$prefix/node_modules/.bin/tsc"
'''
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
