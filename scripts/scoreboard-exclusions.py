#!/usr/bin/env python3
"""Convert the private test-identity list.csv into a SCOREBOARD_EXCLUSIONS JSON value."""

import argparse
import csv
import json
from pathlib import Path
import re
import sys


HEADERS = ("kind", "value", "evidence")
KINDS = {"address": "evm_address", "did_pkh": "evm_address", "email": "email", "did_key": "did", "email_domain": "email_domain"}
PATTERNS = {
    "address": re.compile(r"0x[0-9a-f]{40}", re.IGNORECASE),
    "did_pkh": re.compile(r"did:pkh:eip155:\d+:0x[0-9a-f]{40}", re.IGNORECASE),
    "email": re.compile(r"[^@\s]+@[^@\s]+"),
    "did_key": re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]+"),
    "email_domain": re.compile(r"[a-z0-9]+(?:[.-][a-z0-9-]+)*\.[a-z]{2,}", re.IGNORECASE),
}


def exclusion_from_row(row):
    if None in row or any(value is None for value in row.values()):
        raise ValueError("Invalid CSV row width")
    kind = row["kind"].strip()
    if kind not in KINDS:
        raise ValueError("Unsupported kind")
    value = row["value"].strip()
    if not PATTERNS[kind].fullmatch(value):
        raise ValueError("Invalid identifier format")
    if kind != "did_key":
        value = value.lower()
    if kind == "did_pkh":
        value = value.rsplit(":", 1)[1]
    # Every list.csv row applies; evidence is not an exclusion gate.
    return {"kind": KINDS[kind], "value": value}


def exclusions_from_csv(source):
    reader = csv.DictReader(source, strict=True)
    if reader.fieldnames is None:
        raise ValueError("Invalid CSV header")
    if tuple(reader.fieldnames) != HEADERS:
        raise ValueError("Invalid CSV header")
    exclusions = []
    seen = set()
    for row in reader:
        entry = exclusion_from_row(row)
        identity = (entry["kind"], entry["value"])
        if identity not in seen:
            seen.add(identity)
            exclusions.append(entry)
    return exclusions


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
