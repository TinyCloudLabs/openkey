#!/usr/bin/env python3
"""Convert the private test-identity list.csv into a SCOREBOARD_EXCLUSIONS JSON value."""

import argparse
import csv
import json
from pathlib import Path
import re
import sys


HEADERS = frozenset(("identifier", "id_type", "kind", "confidence", "purge_hold", "evidence"))
KINDS = {"eth-address": "evm_address", "email": "email", "did:key": "did"}
PATTERNS = {
    "eth-address": re.compile(r"0x[0-9a-fA-F]{40}", re.IGNORECASE),
    "email": re.compile(r"[^@\s]+@[^@\s]+"),
    "did:key": re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]+"),
}


def exclusion_from_row(row):
    if None in row or any(value is None for value in row.values()):
        raise ValueError("Invalid CSV row width")
    id_type = row["id_type"].strip()
    if id_type not in KINDS:
        raise ValueError("Unsupported id_type")
    value = row["identifier"].strip()
    if not PATTERNS[id_type].fullmatch(value):
        raise ValueError("Invalid identifier format")
    if id_type != "did:key":
        value = value.lower()
    # Every list.csv row applies; confidence, kind and purge_hold are not exclusion gates.
    return {"kind": KINDS[id_type], "value": value}


def exclusions_from_csv(source):
    reader = csv.DictReader(source, strict=True)
    if reader.fieldnames is None:
        raise ValueError("Invalid CSV header")
    headers = [header.strip().casefold() for header in reader.fieldnames]
    if set(headers) != HEADERS or len(headers) != len(HEADERS):
        raise ValueError("Invalid CSV header")
    reader.fieldnames = headers
    return [exclusion_from_row(row) for row in reader]


def main():
    parser = argparse.ArgumentParser(
        description="Emit private SCOREBOARD_EXCLUSIONS JSON from list.csv only; capture stdout privately, not in logs."
    )
    parser.add_argument("path", help="Path to the authoritative private list.csv; never unsure.csv or patterns.csv")
    args = parser.parse_args()
    try:
        if Path(args.path).name in ("unsure.csv", "patterns.csv") or Path(args.path).resolve().name in ("unsure.csv", "patterns.csv"):
            raise ValueError("Auxiliary identity file")
        with open(args.path, encoding="utf-8-sig", newline="") as source:
            exclusions = exclusions_from_csv(source)
    except (OSError, UnicodeError, csv.Error, ValueError):
        print("Unable to export scoreboard exclusions.", file=sys.stderr)
        return 1
    print(json.dumps(exclusions, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
