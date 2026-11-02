#!/usr/bin/env python3
"""Convert a private kind,value,status CSV into a SCOREBOARD_EXCLUSIONS JSON value."""

import argparse
import csv
import json
import sys


KINDS = frozenset(("user_id", "email", "email_domain", "evm_address", "did"))
DECISION_COLUMNS = ("status", "confidence", "decision")


def exclusions_from_csv(source):
    reader = csv.DictReader(source, strict=True)
    if reader.fieldnames is None:
        raise ValueError("Invalid CSV")
    headers = [header.strip().casefold() for header in reader.fieldnames]
    if not {"kind", "value"}.issubset(headers) or len(set(headers)) != len(headers):
        raise ValueError("Invalid CSV")
    reader.fieldnames = headers

    exclusions = []
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("Invalid CSV")
        kind = row["kind"].strip()
        value = row["value"]
        if kind not in KINDS or not value.strip():
            raise ValueError("Invalid exclusion")
        if any(row.get(column, "").strip().casefold() == "unsure" for column in DECISION_COLUMNS):
            continue
        exclusions.append({"kind": kind, "value": value})
    return exclusions


def main():
    parser = argparse.ArgumentParser(
        description="Emit private SCOREBOARD_EXCLUSIONS JSON; capture stdout privately, not in logs."
    )
    parser.add_argument("path", help="Path to the authoritative private CSV")
    args = parser.parse_args()
    try:
        with open(args.path, encoding="utf-8-sig", newline="") as source:
            exclusions = exclusions_from_csv(source)
    except (OSError, UnicodeError, csv.Error, ValueError):
        print("Unable to export scoreboard exclusions.", file=sys.stderr)
        return 1
    print(json.dumps(exclusions, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
