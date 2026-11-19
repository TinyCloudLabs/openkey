#!/usr/bin/env bash
# The monitor against the real application schema (TC-3067): apply every Prisma migration to an empty database,
# provision the monitor into it, check that Prisma's drift check (`db:migrate:verify-schema`) still reports no
# difference with the monitor present and after it is dropped, and that the post-checks pass on the schema the
# migrations create, which holds functions PUBLIC can execute (the openkey_* guards).
#
# Run from the repository root, with dependencies installed.
# Environment: TEST_PGHOST, TEST_PGPORT, TEST_PGUSER, TEST_PGPASSWORD (a superuser).
set -euo pipefail
set +x

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${TEST_PGHOST:?}" "${TEST_PGPORT:?}" "${TEST_PGUSER:?}" "${TEST_PGPASSWORD:?}"

PGPASSWORD=$TEST_PGPASSWORD psql -X -q -At -v ON_ERROR_STOP=1 -h "$TEST_PGHOST" -p "$TEST_PGPORT" -U "$TEST_PGUSER" -d postgres \
  -c "DROP DATABASE IF EXISTS monitor_test_migrated" -c "CREATE DATABASE monitor_test_migrated"
export DATABASE_URL="postgresql://$TEST_PGUSER:$TEST_PGPASSWORD@$TEST_PGHOST:$TEST_PGPORT/monitor_test_migrated"

echo "=== migrate"
bun run db:migrate:apply >/dev/null
bun run db:migrate:verify-schema

echo "=== provision"
out=$("$here/db-monitor-role.sh" provision)
printf '%s\n' "$out"
public_functions=$(sed -nE 's/^ +info +info_public_executable_functions +([0-9]+)$/\1/p' <<<"$out")
if [ "${public_functions:-0}" -lt 1 ]; then
  echo "expected the migrated schema to hold functions PUBLIC can execute; found '${public_functions:-none}'" >&2
  exit 1
fi
echo "The migrated schema holds $public_functions functions PUBLIC can execute; none counts against the monitor role."

echo "=== drift check with the monitor present"
bun run db:migrate:verify-schema

echo "=== drop"
"$here/db-monitor-role.sh" drop

echo "=== drift check after drop"
bun run db:migrate:verify-schema

PGPASSWORD=$TEST_PGPASSWORD psql -X -q -At -v ON_ERROR_STOP=1 -h "$TEST_PGHOST" -p "$TEST_PGPORT" -U "$TEST_PGUSER" -d postgres \
  -c "DROP DATABASE IF EXISTS monitor_test_migrated"
echo "migrated-schema checks passed"
