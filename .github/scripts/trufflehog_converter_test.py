import contextlib
import io
import json
import unittest

from sigilix_sarif_contract import SIGILIX_SCHEMA_VERSION, SIGILIX_SOURCE
from trufflehog_to_sarif import convert_trufflehog_json


class TrufflehogConverterTest(unittest.TestCase):
    def assert_sigilix_properties(self, document, tool_id):
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(len(document["runs"]), 1)
        properties = document["runs"][0]["tool"]["driver"]["properties"]
        self.assertEqual(properties["sigilixSchemaVersion"], SIGILIX_SCHEMA_VERSION)
        self.assertEqual(properties["sigilixToolId"], tool_id)
        self.assertEqual(properties["sigilixSource"], SIGILIX_SOURCE)
        self.assertNotIn("sigilixRoleHints", properties)

    def test_trufflehog_json_lines_convert_to_sarif(self):
        document = convert_trufflehog_json(
            json.dumps(
                {
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env", "line": 4}}},
                    "DetectorName": "AWS",
                    "Verified": True,
                    "Raw": "AKIA_SHOULD_NOT_APPEAR",
                    "Redacted": "AKIA********",
                    "ExtraData": {"account": "SHOULD_NOT_APPEAR"},
                    "StructuredData": {"token": "STRUCTURED_SHOULD_NOT_APPEAR"},
                }
            )
            + "\n",
            base_dir="/repo",
        )

        self.assert_sigilix_properties(document, "trufflehog")
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "AWS")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["message"]["text"], "TruffleHog found AWS secret")
        self.assertEqual(result["properties"], {"trufflehogVerified": True})
        self.assertNotIn("AKIA", json.dumps(document))
        self.assertNotIn("SHOULD_NOT_APPEAR", json.dumps(document))
        self.assertNotIn("STRUCTURED_SHOULD_NOT_APPEAR", json.dumps(document))
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "secrets.env")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 4)

    def test_trufflehog_unverified_findings_are_warning_without_secret_dependent_dedupe(self):
        finding = {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env", "line": 4}}},
            "DetectorName": "AWS",
            "Verified": False,
            "Raw": "AKIA_DUPLICATE_SECRET",
        }
        document = convert_trufflehog_json("\n".join([json.dumps(finding), json.dumps(finding)]), base_dir="/repo")

        results = document["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["level"], "warning")
        self.assertEqual(results[0]["message"]["text"], "TruffleHog found AWS secret")
        self.assertEqual(results[0]["properties"], {"trufflehogVerified": False})
        self.assertNotIn("AKIA_DUPLICATE_SECRET", json.dumps(document))

        metadata_only = dict(finding)
        metadata_only.pop("Raw")
        document = convert_trufflehog_json(
            "\n".join([json.dumps(metadata_only), json.dumps(metadata_only)]),
            base_dir="/repo",
        )
        self.assertEqual(len(document["runs"][0]["results"]), 1)

        whitespace_raw = dict(finding, Raw="   ")
        document = convert_trufflehog_json("\n".join([json.dumps(whitespace_raw), json.dumps(whitespace_raw)]), base_dir="/repo")
        self.assertEqual(len(document["runs"][0]["results"]), 1)

        numeric_raw = dict(finding, Raw=0)
        document = convert_trufflehog_json("\n".join([json.dumps(numeric_raw), json.dumps(numeric_raw)]), base_dir="/repo")
        self.assertEqual(len(document["runs"][0]["results"]), 2)

    def test_trufflehog_metadata_dedupe_prefers_verified_finding(self):
        base = {"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env", "line": 4}}}, "DetectorName": "AWS"}
        document = convert_trufflehog_json(
            "\n".join([json.dumps(dict(base, Verified=False)), json.dumps(dict(base, Verified="true"))]),
            base_dir="/repo",
        )

        result = document["runs"][0]["results"][0]
        self.assertEqual(len(document["runs"][0]["results"]), 1)
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"], {"trufflehogVerified": True})

        other = {"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/other.env", "line": 8}}}, "DetectorName": "GCP"}
        document = convert_trufflehog_json("\n".join([json.dumps(base), json.dumps(other)]), base_dir="/repo")
        self.assertEqual([result["ruleId"] for result in document["runs"][0]["results"]], ["AWS", "GCP"])

    def test_trufflehog_ndjson_warns_on_non_object_lines(self):
        payload = "\n".join(
            [
                json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/first.env", "line": 1}}}, "DetectorName": "AWS"}),
                json.dumps(["unexpected"]),
                json.dumps({"SourceMetadata": {"Data": {"Git": {"file": "/repo/second.env", "line": 2}}}, "DetectorName": "GitHub"}),
            ]
        )
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            document = convert_trufflehog_json(payload, base_dir="/repo")

        self.assert_sigilix_properties(document, "trufflehog")
        self.assertEqual([result["ruleId"] for result in document["runs"][0]["results"]], ["AWS", "GitHub"])
        self.assertIn("skipped a non-object JSON line", stderr.getvalue())

    def test_trufflehog_missing_line_omits_sarif_region(self):
        document = convert_trufflehog_json(
            json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/secrets.env"}}}, "DetectorName": "AWS"}),
            base_dir="/repo",
        )

        result = document["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "secrets.env")
        self.assertNotIn("region", result["locations"][0]["physicalLocation"])


if __name__ == "__main__":
    unittest.main()
