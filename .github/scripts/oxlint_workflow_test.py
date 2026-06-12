import os
import subprocess
import tempfile
import unittest


class OxlintWorkflowRuntimeTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
