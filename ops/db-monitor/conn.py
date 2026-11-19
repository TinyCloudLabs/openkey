#!/usr/bin/env python3
"""Turn DATABASE_URL into libpq environment variables, so no connection string, and no password, is ever
passed to psql or any other command on its command line.

    eval "$(python3 conn.py)"             # PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD (+ PGSSLMODE ...)
    python3 conn.py --monitor-url         # the monitor role's URL, to stdout, for a pipe into `age`

The monitor URL keeps the database host, port, name and query string of DATABASE_URL and swaps in the
openkey_monitor role and the password from OPENKEY_MONITOR_PW. A query parameter this script does not know
stops it, so a connection option is never dropped without notice.
"""
import os
import shlex
import sys
from urllib.parse import parse_qsl, quote, unquote, urlsplit

MONITOR_ROLE = "openkey_monitor"

# URL query parameter -> libpq environment variable.
QUERY_ENV = {
    "sslmode": "PGSSLMODE",
    "channel_binding": "PGCHANNELBINDING",
    "options": "PGOPTIONS",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "application_name": "PGAPPNAME",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
}


def parse(url: str):
    parts = urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql"):
        sys.exit("DATABASE_URL must start with postgres:// or postgresql://")
    if not parts.hostname or not parts.path.strip("/"):
        sys.exit("DATABASE_URL must name a host and a database")
    query = parse_qsl(parts.query, keep_blank_values=True)
    unknown = sorted({key for key, _ in query if key not in QUERY_ENV})
    if unknown:
        sys.exit("DATABASE_URL has a query parameter this script does not pass on: " + ", ".join(unknown))
    return parts, query


def main() -> None:
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL is not set")
    parts, query = parse(url)

    if "--monitor-url" in sys.argv[1:]:
        password = os.environ.get("OPENKEY_MONITOR_PW")
        if not password:
            sys.exit("OPENKEY_MONITOR_PW is not set")
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port else ""
        print(f"postgresql://{MONITOR_ROLE}:{quote(password, safe='')}@{host}{port}{parts.path}"
              + (f"?{parts.query}" if parts.query else ""))
        return

    env = {
        "PGHOST": parts.hostname,
        "PGDATABASE": unquote(parts.path.lstrip("/")),
    }
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username is not None:
        env["PGUSER"] = unquote(parts.username)
    if parts.password is not None:
        env["PGPASSWORD"] = unquote(parts.password)
    for key, value in query:
        env[QUERY_ENV[key]] = value
    for name, value in env.items():
        print(f"export {name}={shlex.quote(value)}")


if __name__ == "__main__":
    main()
