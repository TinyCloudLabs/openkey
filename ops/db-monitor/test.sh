#!/usr/bin/env bash
# Tests of db-monitor-role.sh against a real PostgreSQL server (TC-3067). Needs a superuser connection, which it
# uses only to create scratch databases; the script under test runs in each as the database's owner:
#
#   super  a database owned by a superuser
#   owner  a database owned by a role that is not a superuser, has CREATEROLE and CREATEDB, and may grant
#          pg_read_all_stats and pg_monitor: the shape of a managed Postgres owner
#
# Each runs once for each statistics role the NOLOGIN owner role may join (pg_read_all_stats, pg_monitor).
#
# Environment: TEST_PGHOST, TEST_PGPORT, TEST_PGUSER, TEST_PGPASSWORD (the superuser connection).
# Every scenario is: provision, post-checks, a deliberate deviation that the post-checks must catch, drop.
set -euo pipefail
set +x

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$here/db-monitor-role.sh"
: "${TEST_PGHOST:?}" "${TEST_PGPORT:?}" "${TEST_PGUSER:?}" "${TEST_PGPASSWORD:?}"

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }

super_sql() { PGPASSWORD=$TEST_PGPASSWORD psql -X -q -At -v ON_ERROR_STOP=1 -h "$TEST_PGHOST" -p "$TEST_PGPORT" -U "$TEST_PGUSER" "$@"; }

OWNER_PW=owner-test-pw

# The roles are shared by the whole server: start from a server that has none of them, and no scratch database.
reset_server() {
  local db
  for db in $(super_sql -d postgres -c "SELECT datname FROM pg_database WHERE datname LIKE 'monitor\_test\_%'"); do
    super_sql -d postgres -c "DROP DATABASE \"$db\""
  done
  super_sql -d postgres <<'SQL'
DO $$
DECLARE r text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor_owner') THEN
    FOR r IN SELECT unnest(ARRAY['pg_read_all_stats', 'pg_monitor']) LOOP
      IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'openkey_monitor_owner'::regrole AND roleid = r::regrole) THEN
        EXECUTE format('REVOKE %I FROM openkey_monitor_owner', r);
      END IF;
    END LOOP;
  END IF;
END
$$;
DROP ROLE IF EXISTS openkey_monitor;
DROP ROLE IF EXISTS openkey_monitor_owner;
DROP ROLE IF EXISTS monitor_test_owner;
DROP ROLE IF EXISTS monitor_test_refused;
SQL
}
reset_server

super_sql -d postgres <<SQL
CREATE ROLE monitor_test_owner LOGIN CREATEROLE CREATEDB PASSWORD '$OWNER_PW';
GRANT pg_read_all_stats TO monitor_test_owner WITH ADMIN OPTION;
GRANT pg_monitor TO monitor_test_owner WITH ADMIN OPTION;
-- A database owner that may grant pg_monitor but not pg_read_all_stats, which is what Neon documents for its owner.
CREATE ROLE monitor_test_refused LOGIN CREATEROLE CREATEDB PASSWORD '$OWNER_PW';
GRANT pg_monitor TO monitor_test_refused WITH ADMIN OPTION;
SQL

# Objects the application's database has before the monitor exists: a table with a column and a sequence, a table
# in another schema, and a function PUBLIC can execute (like the migrations' openkey_* guard functions).
fixtures() {
  local url=$1
  psql -X -q -v ON_ERROR_STOP=1 "$url" <<'SQL'
CREATE TABLE public.fx_table (id int PRIMARY KEY, secret text);
CREATE SEQUENCE public.fx_seq;
CREATE SCHEMA other;
CREATE TABLE other.fx_other (id int);
CREATE FUNCTION public.fx_fn() RETURNS int LANGUAGE sql AS 'SELECT 1';
SQL
}

# admin: the database owner under test. as_super: a superuser in the same database, for changes to objects the
# owner role holds, which a database owner that is not a superuser cannot make.
admin() { psql -X -q -At -v ON_ERROR_STOP=1 "$ADMIN_URL" "$@"; }
as_super() { super_sql -d "$DB" "$@"; }
as_monitor() { PGPASSWORD=$1 psql -X -q -At -h "$TEST_PGHOST" -p "$TEST_PGPORT" -U openkey_monitor -d "$DB" "${@:2}"; }

run() { # run <mode>: DATABASE_URL, OPENKEY_MONITOR_PW set by the caller; output in $out, status in $status
  set +e
  out=$("$script" "$@" 2>&1)
  status=$?
  set -e
}

expect_status() { # expect_status <description> <wanted: 0|nonzero>
  if { [ "$2" = 0 ] && [ "$status" = 0 ]; } || { [ "$2" = nonzero ] && [ "$status" != 0 ]; }; then
    ok "$1"
  else
    bad "$1 (exit status $status)"
    printf '%s\n' "$out" | sed 's/^/        /'
  fi
}
expect_line() { # expect_line <description> <fixed text that must be in $out>
  if grep -qF -- "$2" <<<"$out"; then ok "$1"; else bad "$1 (missing: $2)"; printf '%s\n' "$out" | sed 's/^/        /'; fi
}

# A deviation the post-checks must catch: apply it, expect verify to fail on the named check, undo it, expect pass.
# Changes run as a superuser unless DEVIATE_AS=owner.
deviation() { # deviation <description> <named check> <apply sql> <undo sql>
  local sql=as_super
  [ "${DEVIATE_AS:-super}" = owner ] && sql=admin
  $sql -c "$3"
  run verify
  expect_status "verify fails after: $1" nonzero
  expect_line "verify names $2 after: $1" "FAIL  $2"
  $sql -c "$4"
  run verify
  expect_status "verify passes again after undoing: $1" 0
}

scenario() { # scenario <super|owner> <statistics role>
  local kind=$1 stats=$2
  local name="$kind/$stats"
  DB="monitor_test_${kind}_${stats#pg_}"
  export OPENKEY_OWNER_STATS_ROLE=$stats
  if [ "$kind" = super ]; then
    super_sql -d postgres -c "CREATE DATABASE $DB"
    ADMIN_URL="postgresql://$TEST_PGUSER:$TEST_PGPASSWORD@$TEST_PGHOST:$TEST_PGPORT/$DB"
  else
    super_sql -d postgres -c "CREATE DATABASE $DB OWNER monitor_test_owner"
    ADMIN_URL="postgresql://monitor_test_owner:$OWNER_PW@$TEST_PGHOST:$TEST_PGPORT/$DB"
  fi
  export DATABASE_URL=$ADMIN_URL
  echo "=== $name"
  fixtures "$ADMIN_URL"

  local pw1="test-pw-one-$kind-$stats" pw2="test-pw-two-$kind-$stats"
  export OPENKEY_MONITOR_PW=$pw1
  run provision
  expect_status "$name: provision succeeds and its post-checks pass" 0
  expect_line "$name: counts, not names, are printed" "tables_with_any_privilege"
  expect_line "$name: it reports whether the server logs statements" "Server log_statement:"
  expect_line "$name: it reports whether the monitor role may create temporary tables" "info_temporary_tables_for_monitor"
  expect_line "$name: a PUBLIC-executable function is reported, not counted against the monitor" "$(printf 'info  %-46s %s' info_public_executable_functions 1)"
  # The runner consumes `::add-mask::` workflow commands and never shows them; every other line must be free of it.
  if grep -v '^::add-mask::' <<<"$out" | grep -qF -- "$pw1"; then bad "$name: the password is in the output"; else ok "$name: the password is not in the output"; fi
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    if grep -qxF -- "::add-mask::$pw1" <<<"$out"; then ok "$name: the password is masked first"; else bad "$name: the password is not masked"; fi
  fi

  if [ "$(as_monitor "$pw1" -c 'SELECT count(*) FROM monitor.connection_counts()')" = 1 ]; then
    ok "$name: the monitor role reads the function"
  else
    bad "$name: the monitor role cannot read the function"
  fi
  if as_monitor "$pw1" -c 'SELECT * FROM public.fx_table' >/dev/null 2>&1; then bad "$name: the monitor role can read a table"; else ok "$name: the monitor role cannot read a table"; fi
  if as_monitor "$pw1" -c 'CREATE TABLE public.fx_new (id int)' >/dev/null 2>&1; then bad "$name: the monitor role can create a table"; else ok "$name: the monitor role cannot create a table"; fi
  if as_monitor "$pw1" -c 'CREATE FUNCTION monitor.f() RETURNS int LANGUAGE sql AS $$SELECT 1$$' >/dev/null 2>&1; then bad "$name: the monitor role can add to schema monitor"; else ok "$name: the monitor role cannot add to schema monitor"; fi

  # Re-running rotates the password.
  export OPENKEY_MONITOR_PW=$pw2
  run provision
  expect_status "$name: a second provision succeeds" 0
  if as_monitor "$pw1" -c 'SELECT 1' >/dev/null 2>&1; then bad "$name: the old password still works"; else ok "$name: the old password stops working"; fi
  if [ "$(as_monitor "$pw2" -c 'SELECT count(*) FROM monitor.connection_counts()')" = 1 ]; then ok "$name: the new password works"; else bad "$name: the new password does not work"; fi

  # Each of these must fail the post-checks, and pass again once undone.
  deviation "SELECT on a table is granted" tables_with_any_privilege \
    "GRANT SELECT ON public.fx_table TO openkey_monitor" "REVOKE SELECT ON public.fx_table FROM openkey_monitor"
  deviation "SELECT on one column is granted" tables_with_any_privilege \
    "GRANT SELECT (secret) ON public.fx_table TO openkey_monitor" "REVOKE SELECT (secret) ON public.fx_table FROM openkey_monitor"
  deviation "SELECT on a table in another schema is granted to PUBLIC" tables_with_any_privilege \
    "GRANT USAGE ON SCHEMA other TO PUBLIC; GRANT SELECT ON other.fx_other TO PUBLIC" \
    "REVOKE SELECT ON other.fx_other FROM PUBLIC; REVOKE USAGE ON SCHEMA other FROM PUBLIC"
  deviation "a sequence is granted" sequences_with_any_privilege \
    "GRANT USAGE ON SEQUENCE public.fx_seq TO openkey_monitor" "REVOKE USAGE ON SEQUENCE public.fx_seq FROM openkey_monitor"
  deviation "another function is granted to the monitor role alone" functions_with_privilege_beyond_public \
    "REVOKE EXECUTE ON FUNCTION public.fx_fn() FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.fx_fn() TO openkey_monitor" \
    "REVOKE EXECUTE ON FUNCTION public.fx_fn() FROM openkey_monitor; GRANT EXECUTE ON FUNCTION public.fx_fn() TO PUBLIC"
  deviation "the function is executable by PUBLIC" function_execute_for_public \
    "GRANT EXECUTE ON FUNCTION monitor.connection_counts() TO PUBLIC" "REVOKE EXECUTE ON FUNCTION monitor.connection_counts() FROM PUBLIC"
  deviation "the monitor role joins pg_monitor" monitor_is_pg_monitor \
    "GRANT pg_monitor TO openkey_monitor" "REVOKE pg_monitor FROM openkey_monitor"
  deviation "the monitor role joins pg_read_all_stats" monitor_is_pg_read_all_stats \
    "GRANT pg_read_all_stats TO openkey_monitor" "REVOKE pg_read_all_stats FROM openkey_monitor"
  deviation "the monitor role may create objects in schema monitor" schema_create_for_monitor \
    "GRANT CREATE ON SCHEMA monitor TO openkey_monitor" "REVOKE CREATE ON SCHEMA monitor FROM openkey_monitor"
  deviation "the monitor role may create objects in the public schema" public_schema_create_for_monitor \
    "GRANT CREATE ON SCHEMA public TO openkey_monitor" "REVOKE CREATE ON SCHEMA public FROM openkey_monitor"
  deviation "a SECURITY DEFINER function PUBLIC can execute exists" public_executable_security_definer_functions \
    "CREATE FUNCTION public.fx_definer() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'" "DROP FUNCTION public.fx_definer()"
  deviation "the connection limit is raised" monitor_connection_limit \
    "ALTER ROLE openkey_monitor CONNECTION LIMIT 5" "ALTER ROLE openkey_monitor CONNECTION LIMIT 2"
  # The owner role's own grant is revoked by the role that made it.
  local regrant="GRANT $stats TO openkey_monitor_owner"
  [ "$(admin -c "SELECT current_setting('server_version_num')::int >= 160000")" = t ] && regrant="$regrant WITH INHERIT TRUE"
  DEVIATE_AS=owner deviation "the owner role loses $stats, so the function under-counts" function_conns_match_owner_count \
    "REVOKE $stats FROM openkey_monitor_owner" "$regrant"

  # Rollback.
  run drop
  expect_status "$name: drop succeeds and nothing is left" 0
  expect_line "$name: drop reports the monitor role gone" "$(printf 'ok    %-46s %s' monitor_role_exists false)"
  run drop
  expect_status "$name: a second drop succeeds" 0
  run verify
  expect_status "$name: the post-checks fail once it is dropped" nonzero
  if [ "$(admin -c "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'openkey_monitor%'")" = 0 ] \
    && [ "$(admin -c "SELECT count(*) FROM pg_namespace WHERE nspname = 'monitor'")" = 0 ]; then
    ok "$name: no role and no schema is left"
  else
    bad "$name: something is left after drop"
  fi

  # A schema called monitor that something else owns is neither taken over nor dropped.
  admin -c "CREATE SCHEMA monitor; CREATE TABLE monitor.keep (id int)"
  run provision
  expect_status "$name: provision refuses a foreign schema monitor" nonzero
  expect_line "$name: the refusal says why" "not owned by openkey_monitor_owner"
  if [ "$(admin -c "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'openkey_monitor%'")" = 0 ]; then
    ok "$name: the refused provision left no role behind"
  else
    bad "$name: the refused provision left a role behind"
  fi
  as_super -c "DROP SCHEMA monitor CASCADE"
}

for stats in pg_read_all_stats pg_monitor; do
  scenario super "$stats"
  scenario owner "$stats"
done

# A value that is neither is refused before the database is touched.
export DATABASE_URL="postgresql://$TEST_PGUSER:$TEST_PGPASSWORD@$TEST_PGHOST:$TEST_PGPORT/postgres"
export OPENKEY_MONITOR_PW=invalid-stats-test-pw
OPENKEY_OWNER_STATS_ROLE=pg_signal_backend run provision
expect_status "an owner statistics role other than the two allowed is refused" nonzero
expect_line "the refusal names the allowed values" "must be pg_read_all_stats or pg_monitor"
if [ "$(super_sql -d postgres -c "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'openkey_monitor%'")" = 0 ]; then
  ok "the refused value left no role behind"
else
  bad "the refused value left a role behind"
fi

# An owner that may grant pg_monitor but not pg_read_all_stats (what Neon documents for its owner): the default value
# stops with the reason and leaves nothing behind, with no fallback; asking for pg_monitor succeeds. Only PostgreSQL 16
# and later check this: before 16, CREATEROLE may grant any role that is not a superuser.
if [ "$(super_sql -d postgres -c "SELECT current_setting('server_version_num')::int >= 160000")" = t ]; then
  echo "=== refused owner"
  super_sql -d postgres -c "CREATE DATABASE monitor_test_refused OWNER monitor_test_refused"
  export DATABASE_URL="postgresql://monitor_test_refused:$OWNER_PW@$TEST_PGHOST:$TEST_PGPORT/monitor_test_refused"
  ADMIN_URL=$DATABASE_URL
  DB=monitor_test_refused
  export OPENKEY_MONITOR_PW=refused-test-pw
  unset OPENKEY_OWNER_STATS_ROLE
  run provision
  expect_status "refused owner: the default pg_read_all_stats fails when the owner may not grant it" nonzero
  expect_line "refused owner: the failure names the role it could not grant" "pg_read_all_stats"
  if [ "$(super_sql -d postgres -c "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'openkey_monitor%'")" = 0 ]; then
    ok "refused owner: it left no role behind and did not fall back"
  else
    bad "refused owner: it left a role behind"
  fi
  export OPENKEY_OWNER_STATS_ROLE=pg_monitor
  run provision
  expect_status "refused owner: asking for pg_monitor succeeds and its post-checks pass" 0
  expect_line "refused owner: the owner role joined pg_monitor" "the owner role joins: pg_monitor"
  expect_line "refused owner: the login role is outside pg_monitor" "$(printf 'ok    %-46s %s' monitor_is_pg_monitor false)"
  expect_line "refused owner: the login role is outside pg_read_all_stats" "$(printf 'ok    %-46s %s' monitor_is_pg_read_all_stats false)"
  run drop
  expect_status "refused owner: drop succeeds and nothing is left" 0
else
  echo "=== refused owner: skipped (PostgreSQL before 16)"
fi

# The age-encrypted URL: only the recipient can read it, and it is the monitor role's.
if command -v age >/dev/null && command -v age-keygen >/dev/null; then
  echo "=== encrypted URL"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  age-keygen -o "$tmp/key.txt" 2>/dev/null
  recipient=$(age-keygen -y "$tmp/key.txt")
  DB=monitor_test_super_url
  super_sql -d postgres -c "CREATE DATABASE $DB"
  export DATABASE_URL="postgresql://$TEST_PGUSER:$TEST_PGPASSWORD@$TEST_PGHOST:$TEST_PGPORT/$DB" ADMIN_URL="postgresql://$TEST_PGUSER:$TEST_PGPASSWORD@$TEST_PGHOST:$TEST_PGPORT/$DB"
  unset OPENKEY_OWNER_STATS_ROLE
  export OPENKEY_MONITOR_PW=url-test-pw OPENKEY_AGE_RECIPIENT=$recipient OPENKEY_MONITOR_URL_OUT=$tmp/url.age
  run provision
  expect_status "provision writes the encrypted URL" 0
  expect_line "the output says it wrote it" "age-encrypted"
  if [ -s "$tmp/url.age" ] && ! grep -qF -- "url-test-pw" "$tmp/url.age"; then ok "the file does not hold the password in clear"; else bad "the file is empty or holds the password in clear"; fi
  decrypted=$(age -d -i "$tmp/key.txt" "$tmp/url.age")
  if [ "$decrypted" = "postgresql://openkey_monitor:url-test-pw@$TEST_PGHOST:$TEST_PGPORT/$DB" ]; then
    ok "decrypted, it is the monitor role's URL for the same database"
  else
    bad "the decrypted URL is not the monitor role's"
  fi
  if PGPASSWORD=url-test-pw psql -X -q -At "$decrypted" -c 'SELECT count(*) FROM monitor.connection_counts()' >/dev/null 2>&1; then
    ok "the decrypted URL connects"
  else
    bad "the decrypted URL does not connect"
  fi
  unset OPENKEY_AGE_RECIPIENT OPENKEY_MONITOR_URL_OUT
  run drop
  expect_status "drop after the encrypted-URL run" 0
fi

reset_server

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
