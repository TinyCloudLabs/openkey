"""Synthetic-only CLI tests for the private scoreboard exclusions exporter."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("scoreboard-exclusions.py")


class ScoreboardExclusionsTest(unittest.TestCase):
    def export(self, contents):
        with tempfile.TemporaryDirectory(prefix="scoreboard-exclusions-", dir="/var/tmp") as directory:
            path = Path(directory) / "synthetic.csv"
            path.write_text(contents, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def assert_export(self, contents, expected):
        result = self.export(contents)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, json.dumps(expected, separators=(",", ":")) + "\n")

    def test_preserves_all_supported_kinds_and_did_variants(self):
        entries = [
            {"kind": "user_id", "value": "synthetic-user-1"},
            {"kind": "email", "value": "synthetic@example.invalid"},
            {"kind": "email_domain", "value": "example.invalid"},
            {"kind": "evm_address", "value": "0x0000000000000000000000000000000000000001"},
            {"kind": "did", "value": "did:key:zSyntheticFixture"},
            {"kind": "did", "value": "did:pkh:eip155:1:0x0000000000000000000000000000000000000001"},
        ]
        contents = "kind,value,status\n" + "".join(
            f"{entry['kind']},{entry['value']},confirmed\n" for entry in entries
        )
        self.assert_export(contents, entries)

    def test_parses_csv_quoted_commas_and_quotes(self):
        self.assert_export(
            'kind,value,status\nuser_id,"synthetic, ""quoted"" user",confirmed\n',
            [{"kind": "user_id", "value": 'synthetic, "quoted" user'}],
        )

    def test_omits_unsure_in_any_decision_column_case_insensitively(self):
        self.assert_export(
            "kind,value,STATUS,Confidence,decision\n"
            "user_id,synthetic-unsure-status,UnSuRe,,\n"
            "user_id,synthetic-unsure-confidence,confirmed, UNSURE ,\n"
            "user_id,synthetic-unsure-decision,confirmed,,unsure\n"
            "user_id,synthetic-unknown,unknown,,\n"
            "user_id,synthetic-unmarked,,,\n",
            [
                {"kind": "user_id", "value": "synthetic-unknown"},
                {"kind": "user_id", "value": "synthetic-unmarked"},
            ],
        )

    def test_empty_input_rows_produce_empty_array(self):
        self.assert_export("kind,value,status\n", [])

    def test_invalid_kind_errors_do_not_leak_any_values(self):
        result = self.export(
            "kind,value,status\n"
            "user_id,synthetic-valid-but-private,confirmed\n"
            "synthetic-invalid-kind,synthetic-secret-value,confirmed\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")

    def test_empty_and_whitespace_values_are_rejected(self):
        for value in ("", "   "):
            with self.subTest(value=value):
                result = self.export(f"kind,value,status\nuser_id,{value},confirmed\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")

    def test_missing_required_headers_are_rejected(self):
        result = self.export("synthetic_header,value,status\nuser_id,synthetic-user,confirmed\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")

    def test_malformed_csv_is_rejected_without_partial_output(self):
        result = self.export('kind,value,status\nuser_id,"synthetic-unclosed,confirmed\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")

    def test_extra_or_missing_row_fields_are_rejected(self):
        for row in ("user_id,synthetic-user,confirmed,synthetic-extra", "user_id"):
            with self.subTest(row=row):
                result = self.export("kind,value,status\n" + row + "\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")


if __name__ == "__main__":
    unittest.main()
