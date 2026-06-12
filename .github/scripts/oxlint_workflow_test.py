import os
import re
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW_PATH = os.path.join(os.path.dirname(__file__), "..", "workflows", "scan.yml")


class OxlintWorkflowRuntimeTest(unittest.TestCase):
    def workflow_text(self):
        with open(WORKFLOW_PATH, encoding="utf-8") as workflow:
            return workflow.read()

    def workflow_tarball_size_helper(self):
        text = self.workflow_text()
        match = re.search(
            r"(?m)^(?P<indent>[ \t]*)tarball_size\(\) \{\n"
            r"(?:(?P=indent)[ \t]+.*\n)*"
            r"(?P=indent)\}",
            text,
        )
        self.assertIsNotNone(match)
        return textwrap.dedent(match.group(0))

    def bash_env(self, **values):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **values}

    def run_tarball_size_guard(self, package, binding):
        return subprocess.check_output(
            [
                "bash",
                "-c",
                self.workflow_tarball_size_helper()
                + r"""
oxlint_package="$OXLINT_PACKAGE"
oxlint_binding_package="$OXLINT_BINDING_PACKAGE"
if [ "$(tarball_size "$oxlint_package")" -le 1024 ] \
  || [ "$(tarball_size "$oxlint_binding_package")" -le 1024 ]; then
  printf too-small
else
  printf ok
fi""",
            ],
            env=self.bash_env(
                **{
                    "OXLINT_PACKAGE": package,
                    "OXLINT_BINDING_PACKAGE": binding,
                }
            ),
            text=True,
        )

    def test_generated_directory_filter_excludes_nested_outputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for path in (
                "src/app.ts",
                "packages/a/dist/app.js",
                "packages/a/build/app.js",
                "packages/a/coverage/app.js",
                "apps/web/.next/app.js",
                "packages/a/out/app.js",
                "node_modules/pkg/app.js",
            ):
                full_path = os.path.join(tmpdir, path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8"):
                    pass

            output = subprocess.check_output(
                [
                    "bash",
                    "-c",
                    r"""find -P . -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.tsx' \) \
  -not -path '*/.git/*' -not -path '*/node_modules/*' \
  -not -path '*/dist/*' -not -path '*/build/*' \
  -not -path '*/coverage/*' -not -path '*/.next/*' \
  -not -path '*/out/*' -print | sort""",
                ],
                cwd=tmpdir,
                text=True,
            )

        self.assertEqual(output.splitlines(), ["./src/app.ts"])

    def test_tarball_size_guard_runs_before_integrity_checks(self):
        text = self.workflow_text()

        size_guard = 'tarball_size "$oxlint_package"'
        integrity_guard = 'sri_sha512 "$oxlint_package"'
        self.assertIn("tarball_size() {", text)
        self.assertIn("tarball at or below 1024 bytes after download", text)
        self.assertIn('[ "$(tarball_size "$oxlint_package")" -le 1024 ]', text)
        self.assertIn('[ "$(tarball_size "$oxlint_binding_package")" -le 1024 ]', text)
        self.assertLess(text.index(size_guard), text.index(integrity_guard))

    def test_tarball_size_guard_rejects_tiny_packages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            package = os.path.join(tmpdir, "oxlint.tgz")
            binding = os.path.join(tmpdir, "binding.tgz")
            with open(package, "wb") as handle:
                handle.write(b"x" * 1024)
            with open(binding, "wb") as handle:
                handle.write(b"x")

            output = self.run_tarball_size_guard(package, binding)

        self.assertEqual(output, "too-small")

    def test_tarball_size_guard_allows_packages_above_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            package = os.path.join(tmpdir, "oxlint.tgz")
            binding = os.path.join(tmpdir, "binding.tgz")
            for path in (package, binding):
                with open(path, "wb") as handle:
                    handle.write(b"x" * 1025)

            output = self.run_tarball_size_guard(package, binding)

        self.assertEqual(output, "ok")

    def test_tarball_size_helper_returns_zero_for_missing_package(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_package = os.path.join(tmpdir, "missing.tgz")
            output = subprocess.check_output(
                [
                    "bash",
                    "-c",
                    self.workflow_tarball_size_helper() + '\ntarball_size "$MISSING_PACKAGE"',
                ],
                env=self.bash_env(**{"MISSING_PACKAGE": missing_package}),
                text=True,
            )

        self.assertEqual(output, "0")


if __name__ == "__main__":
    unittest.main()
