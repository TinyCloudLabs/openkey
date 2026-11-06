"""Synthetic-only CLI tests for the private scoreboard exclusions exporter."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("scoreboard-exclusions.py")
HEADER = "kind,value,evidence\n"


class ScoreboardExclusionsTest(unittest.TestCase):
    def export(self, contents):
        with tempfile.TemporaryDirectory(prefix="scoreboard-exclusions-", dir="/var/tmp") as directory:
            path = Path(directory) / "list.csv"
            path.write_text(contents, encoding="utf-8")
            for name in ("unsure.csv", "patterns.csv"):
                (Path(directory) / name).write_text("invalid auxiliary content", encoding="utf-8")
            return subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)

    def assert_export(self, contents, expected):
        result = self.export(contents)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), expected)

    def test_accepts_current_schema_and_every_kind(self):
        self.assert_export(
            HEADER
            + "address,0xABCDEF0000000000000000000000000000000001,synthetic\n"
            + "did_pkh,did:pkh:eip155:1:0xABCDEF0000000000000000000000000000000001,synthetic\n"
            + "email,PERSON@EXAMPLE.INVALID,synthetic\n"
            + "did_key,did:key:zSyntheticAgent,synthetic\n"
            + "email_domain,DISPOSABLE.EXAMPLE,synthetic\n",
            [
                {"kind": "evm_address", "value": "0xabcdef0000000000000000000000000000000001"},
                {"kind": "email", "value": "person@example.invalid"},
                {"kind": "did", "value": "did:key:zSyntheticAgent"},
                {"kind": "email_domain", "value": "disposable.example"},
            ],
        )

    def test_address_and_pkh_rows_collapse_without_changing_account_exclusion(self):
        address = "0xabcdef0000000000000000000000000000000001"
        rows = [f"address,{address.upper()},synthetic\n", f"did_pkh,did:pkh:eip155:1:{address},synthetic\n"]
        for ordered in (rows, list(reversed(rows))):
            result = self.export(HEADER + "".join(ordered))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [{"kind": "evm_address", "value": address}])
            check = subprocess.run(
                ["bun", "-e", """
import assert from 'node:assert/strict';
import {parseExclusions, classifyExcludedAccounts} from './apps/api/src/services/scoreboard-exclusions';
const raw = await Bun.stdin.text();
const address = '0xabcdef0000000000000000000000000000000001';
const accounts = [{id:'synthetic',email:'person@example.invalid',ethereumKeys:[{address:address.toUpperCase()}]}];
const original = [{kind:'evm_address',value:address},{kind:'did',value:`did:pkh:eip155:1:${address}`}];
assert.deepEqual(classifyExcludedAccounts(accounts,parseExclusions(raw)),classifyExcludedAccounts(accounts,parseExclusions(JSON.stringify(original))));
assert.equal(classifyExcludedAccounts(accounts,parseExclusions(raw)).userIds.size,1);
"""],
                cwd=SCRIPT.parent.parent, input=result.stdout, capture_output=True, text=True,
            )
            self.assertEqual(check.returncode, 0, check.stderr)

    def test_evidence_never_filters_list_rows(self):
        self.assert_export(
            HEADER + 'email,person@example.invalid,"unsure, medium, purge_hold"\n',
            [{"kind": "email", "value": "person@example.invalid"}],
        )

    def test_quoted_evidence_is_not_interpreted_as_rules(self):
        self.assert_export(
            HEADER + 'email,person@example.invalid,"synthetic, ""quoted"" evidence"\n',
            [{"kind": "email", "value": "person@example.invalid"}],
        )

    def test_empty_list_produces_empty_array(self):
        self.assert_export(HEADER, [])

    def test_auxiliary_and_superseded_schemas_are_rejected(self):
        for header in (
            "rule_type,pattern,what,evidence,condition_before_use\n",
            "identifier,id_type,kind,confidence,purge_hold,evidence\n",
            "kind,value,status\n",
        ):
            with self.subTest(header=header):
                self.assert_rejected(header)

    def test_auxiliary_filenames_cannot_be_exported_even_with_list_shaped_content(self):
        with tempfile.TemporaryDirectory(prefix="scoreboard-exclusions-", dir="/var/tmp") as directory:
            for name in ("unsure.csv", "patterns.csv"):
                path = Path(directory) / name
                path.write_text(HEADER + "email,person@example.invalid,synthetic\n")
                result = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_invalid_values_and_kinds_are_rejected_without_partial_output(self):
        for kind, value in (
            ("email", ""), ("email", "not-an-email"), ("address", "0x123"),
            ("did_key", "did:key:not-valid"), ("did_pkh", "did:pkh:eip155:1:0x123"),
            ("email_domain", "*.example.invalid"), ("email_domain", "@example.invalid"),
            ("unmatchable", "private-value"), ("user_id", "private-value"),
        ):
            with self.subTest(kind=kind):
                self.assert_rejected(HEADER + "email,valid@example.invalid,synthetic\n" + f"{kind},{value},synthetic\n")

    def test_malformed_and_wrong_width_csv_are_rejected(self):
        for row in ('email,"unclosed,synthetic', "email,person@example.invalid", "a,b,c,d"):
            with self.subTest(row=row):
                self.assert_rejected(HEADER + row + "\n")

    def assert_rejected(self, contents):
        result = self.export(contents)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Unable to export scoreboard exclusions.\n")


if __name__ == "__main__":
    unittest.main()
