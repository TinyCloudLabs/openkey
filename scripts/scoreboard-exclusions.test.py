"""Synthetic-only CLI tests for the private scoreboard exclusions exporter."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("scoreboard-exclusions.py")
HEADER = "identifier,id_type,kind,confidence,purge_hold,evidence\n"


class ScoreboardExclusionsTest(unittest.TestCase):
    def export(self, contents):
        with tempfile.TemporaryDirectory(prefix="scoreboard-exclusions-", dir="/var/tmp") as directory:
            path = Path(directory) / "list.csv"
            path.write_text(contents, encoding="utf-8")
            # These files must never be read implicitly alongside list.csv.
            for name in ("unsure.csv", "patterns.csv"):
                (Path(directory) / name).write_text("invalid auxiliary content", encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                capture_output=True, text=True, check=False,
            )

    def assert_export(self, contents, expected):
        result = self.export(contents)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), expected)

    def test_accepts_real_schema_and_all_identity_types(self):
        self.assert_export(
            HEADER
            + "0xABCDEF0000000000000000000000000000000001,eth-address,fixture,medium,true,synthetic\n"
            + "PERSON@EXAMPLE.INVALID,email,fixture,high,false,synthetic\n"
            + "did:key:zSyntheticAgent,did:key,fixture,medium,hold,synthetic\n",
            [
                {"kind": "evm_address", "value": "0xabcdef0000000000000000000000000000000001"},
                {"kind": "email", "value": "person@example.invalid"},
                {"kind": "did", "value": "did:key:zSyntheticAgent"},
            ],
        )

    def test_confidence_kind_and_purge_hold_never_filter_list_rows(self):
        self.assert_export(
            HEADER
            + "first@example.invalid,email,unsure,medium,unsure,synthetic\n"
            + "second@example.invalid,email,fixture,high,yes,synthetic\n"
            + "third@example.invalid,email,fixture,unsure,no,synthetic\n",
            [{"kind": "email", "value": f"{name}@example.invalid"} for name in ("first", "second", "third")],
        )

    def test_quoted_evidence_is_not_interpreted_as_rules(self):
        self.assert_export(
            HEADER + 'person@example.invalid,email,fixture,medium,true,"synthetic, ""quoted"" evidence"\n',
            [{"kind": "email", "value": "person@example.invalid"}],
        )

    def test_empty_list_produces_empty_array(self):
        self.assert_export(HEADER, [])

    def test_patterns_unsure_and_old_schemas_are_rejected(self):
        for header in (
            "rule_type,pattern,what,evidence,condition_before_use\n",
            "identifier,id_type,reason,evidence\n",
            "kind,value,status\n",
        ):
            with self.subTest(header=header):
                self.assert_rejected(header)

    def test_auxiliary_filenames_cannot_be_exported_even_with_list_shaped_content(self):
        with tempfile.TemporaryDirectory(prefix="scoreboard-exclusions-", dir="/var/tmp") as directory:
            for name in ("unsure.csv", "patterns.csv"):
                path = Path(directory) / name
                path.write_text(HEADER + "person@example.invalid,email,fixture,high,,synthetic\n")
                result = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_invalid_identifiers_and_types_are_rejected_without_partial_output(self):
        for identifier, id_type in (
            ("", "email"), ("not-an-email", "email"), ("0x123", "eth-address"),
            ("did:key:not-valid", "did:key"), ("example.invalid", "email-domain"),
            ("private-value", "unknown"),
        ):
            with self.subTest(id_type=id_type):
                self.assert_rejected(
                    HEADER + "valid@example.invalid,email,fixture,high,,synthetic\n"
                    + f"{identifier},{id_type},fixture,medium,hold,synthetic\n"
                )

    def test_malformed_and_wrong_width_csv_are_rejected(self):
        for row in ('"unclosed,email,fixture,medium,,synthetic', "person@example.invalid,email", "a,b,c,d,e,f,g"):
            with self.subTest(row=row):
                self.assert_rejected(HEADER + row + "\n")

    def assert_rejected(self, contents):
        result = self.export(contents)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")


if __name__ == "__main__":
    unittest.main()
