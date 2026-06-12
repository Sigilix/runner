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

    def workflow_oxlint_find_command(self):
        text = self.workflow_text()
        match = re.search(r'(?ms)^[ \t]+if ! (?P<command>find -P .+? > "\$files_list"); then', text)
        self.assertIsNotNone(match)
        return match.group("command")

    def bash_env(self, **values):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **values}

    def tarball_size_guard_rejects(self, package, binding):
        result = subprocess.run(
            [
                "bash",
                "-c",
                self.workflow_tarball_size_helper()
                + r"""
oxlint_package="$OXLINT_PACKAGE"
oxlint_binding_package="$OXLINT_BINDING_PACKAGE"
if [ "$(tarball_size "$oxlint_package")" -le 1024 ] \
  || [ "$(tarball_size "$oxlint_binding_package")" -le 1024 ]; then
  exit 0
fi
exit 1""",
            ],
            env=self.bash_env(
                **{
                    "OXLINT_PACKAGE": package,
                    "OXLINT_BINDING_PACKAGE": binding,
                }
            ),
            check=False,
        )
        return result.returncode == 0

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

            files_list = os.path.join(tmpdir, "oxlint-files")
            find_command = self.workflow_oxlint_find_command()
            self.assertIn("-print0", find_command)
            self.assertIn('> "$files_list"', find_command)
            subprocess.check_call(
                [
                    "bash",
                    "-c",
                    'files_list="$OXLINT_FILES_LIST"\n' + find_command,
                ],
                cwd=tmpdir,
                env=self.bash_env(**{"OXLINT_FILES_LIST": files_list}),
            )
            with open(files_list, "rb") as handle:
                selected = [entry.decode() for entry in handle.read().split(b"\0") if entry]

        self.assertEqual(selected, ["./src/app.ts"])

    def test_tarball_size_guard_runs_before_integrity_checks(self):
        text = self.workflow_text()

        missing_guard = '[ ! -s "$oxlint_package" ]'
        size_guard = 'tarball_size "$oxlint_package"'
        integrity_guard = 'sri_sha512 "$oxlint_package"'
        self.assertIn("tarball_size() {", text)
        self.assertIn("tarball at or below 1024 bytes after download", text)
        self.assertIn(missing_guard, text)
        self.assertIn('[ "$(tarball_size "$oxlint_package")" -le 1024 ]', text)
        self.assertIn('[ "$(tarball_size "$oxlint_binding_package")" -le 1024 ]', text)
        self.assertLess(text.index(missing_guard), text.index(size_guard))
        self.assertLess(text.index(size_guard), text.index(integrity_guard))

    def test_tarball_size_guard_rejects_tiny_packages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            package = os.path.join(tmpdir, "oxlint.tgz")
            binding = os.path.join(tmpdir, "binding.tgz")
            with open(package, "wb") as handle:
                handle.write(b"x" * 1024)
            with open(binding, "wb") as handle:
                handle.write(b"x")

            rejected = self.tarball_size_guard_rejects(package, binding)

        self.assertTrue(rejected)

    def test_tarball_size_guard_allows_first_byte_above_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            package = os.path.join(tmpdir, "oxlint.tgz")
            binding = os.path.join(tmpdir, "binding.tgz")
            for path in (package, binding):
                with open(path, "wb") as handle:
                    handle.write(b"x" * 1025)

            rejected = self.tarball_size_guard_rejects(package, binding)

        self.assertFalse(rejected)


if __name__ == "__main__":
    unittest.main()
