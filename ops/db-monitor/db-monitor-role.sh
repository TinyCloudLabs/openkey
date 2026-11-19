#!/usr/bin/env bash
# Provision or drop the OpenKey connection-count monitor (TC-3067). What it creates is described in provision.sql.
#
#   db-monitor-role.sh provision   create or refresh both roles and the function, rotate the monitor password, run
#                                  the post-checks, and write the monitor connection URL, age-encrypted
#   db-monitor-role.sh verify      the post-checks only (needs OPENKEY_MONITOR_PW)
#   db-monitor-role.sh drop        remove everything, then check that nothing is left
#
# Environment
#   DATABASE_URL            the database owner's connection URL (required)
#   OPENKEY_MONITOR_PW      the monitor role's password; provision generates one when it is unset
#   OPENKEY_OWNER_STATS_ROLE the one statistics role the NOLOGIN owner role joins: pg_read_all_stats (default) or
#                           pg_monitor. Never the monitor login role, which the post-checks prove is in neither.
#   OPENKEY_AGE_RECIPIENT   provision: an age public key (age1...) to encrypt the monitor URL to
#   OPENKEY_MONITOR_URL_OUT provision: the file the encrypted URL is written to (with OPENKEY_AGE_RECIPIENT)
#
# The password and the database URL are only ever in the environment: never on a command line, and never
# printed. No `set -x`, no psql -a/-e. Output is booleans and counts.
set -euo pipefail
set +x
umask 077

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mode=${1:-}
case "$mode" in provision | verify | drop) ;; *)
  echo "usage: db-monitor-role.sh provision|verify|drop" >&2
  exit 2
  ;;
esac
: "${DATABASE_URL:?DATABASE_URL is required}"

export OPENKEY_OWNER_STATS_ROLE=${OPENKEY_OWNER_STATS_ROLE:-pg_read_all_stats}
case "$OPENKEY_OWNER_STATS_ROLE" in pg_read_all_stats | pg_monitor) ;; *)
  echo "OPENKEY_OWNER_STATS_ROLE must be pg_read_all_stats or pg_monitor" >&2
  exit 2
  ;;
esac

# psql 15 or later: \getenv.
psql_major=$(psql --version | sed -E 's/^[^0-9]*([0-9]+).*/\1/')
if [ "${psql_major:-0}" -lt 15 ]; then
  echo "psql 15 or later is required (found ${psql_major:-unknown}); provision.sql reads the password with \\getenv" >&2
  exit 2
fi

# The database owner's connection, as libpq environment variables.
# Captured first: a failure of conn.py inside eval's argument would not stop the script, which would then use
# whatever PG* variables the shell already holds.
if ! conn_env=$(python3 "$here/conn.py"); then
  echo "conn.py could not read DATABASE_URL; nothing was changed" >&2
  exit 2
fi
eval "$conn_env"
unset conn_env

psql_admin() { psql -X -q -v ON_ERROR_STOP=1 "$@"; }
psql_monitor() { PGUSER=openkey_monitor PGPASSWORD="$OPENKEY_MONITOR_PW" psql -X -q -v ON_ERROR_STOP=1 "$@"; }

canary_up=
cleanup() {
  if [ -n "$canary_up" ]; then
    # Closing its input ends the held-open session.
    local canary_stdin=${CANARY[1]}
    exec {canary_stdin}>&-
    wait "$CANARY_PID" 2>/dev/null || true
    canary_up=
  fi
}
trap cleanup EXIT

# Compare rows of `check|value` with an expected value for each; print one line per check.
compare_rows() {
  local -n want=$1
  local rows=$2 name value failed=0
  local -A seen=()
  while IFS='|' read -r name value; do
    [ -n "$name" ] || continue
    if [[ $name == info_* ]]; then
      printf '  info  %-46s %s\n' "$name" "$value"
      continue
    fi
    seen[$name]=1
    if [ -z "${want[$name]+x}" ]; then
      printf '  FAIL  %-46s unexpected check\n' "$name"
      failed=1
    elif [ "$value" = "${want[$name]}" ]; then
      printf '  ok    %-46s %s\n' "$name" "$value"
    else
      printf '  FAIL  %-46s %s (expected %s)\n' "$name" "$value" "${want[$name]}"
      failed=1
    fi
  done <<<"$rows"
  for name in "${!want[@]}"; do
    if [ -z "${seen[$name]+x}" ]; then
      printf '  FAIL  %-46s no row\n' "$name"
      failed=1
    fi
  done
  return $failed
}

verify() {
  : "${OPENKEY_MONITOR_PW:?OPENKEY_MONITOR_PW is required}"

  # A session the database owner's role holds open in a transaction stands in for the application: other roles'
  # sessions must be there for the checks below to mean anything.
  coproc CANARY { PGAPPNAME=openkey-db-monitor-canary exec psql -X -q -At -v ON_ERROR_STOP=1 >/dev/null 2>&1; }
  canary_up=1
  printf 'BEGIN;\nSELECT 1;\n' >&"${CANARY[1]}"
  local i ready=0
  for i in $(seq 1 60); do
    ready=$(psql_admin -At -c "SELECT count(*) FROM pg_stat_activity
      WHERE application_name = 'openkey-db-monitor-canary' AND state = 'idle in transaction'
        AND datname = current_database()")
    [ "$ready" -ge 1 ] && break
    sleep 0.5
  done

  echo "Post-checks, as openkey_monitor:"
  local -A expected=(
    [function_returns_one_row]=1
    [monitor_can_login]=true
    [monitor_superuser]=false
    [monitor_createdb]=false
    [monitor_createrole]=false
    [monitor_replication]=false
    [monitor_bypassrls]=false
    [monitor_connection_limit]=2
    [monitor_role_memberships]=0
    [monitor_is_pg_read_all_stats]=false
    [monitor_is_pg_monitor]=false
    [monitor_default_read_only]=on
    [monitor_statement_timeout]=5s
    [owner_can_login]=false
    [owner_superuser]=false
    [owner_memberships]=1
    [owner_member_of_stats_role_only]=true
    [owner_members_able_to_use_it]=0
    [schema_owned_by_owner]=true
    [schema_usage_for_public]=false
    [schema_create_for_public]=false
    [schema_usage_for_monitor]=true
    [schema_create_for_monitor]=false
    [schema_object_count]=1
    [function_owned_by_owner]=true
    [function_security_definer]=true
    [function_arguments]=0
    [function_search_path]=true
    [function_execute_for_public]=false
    [function_execute_for_monitor]=true
    [tables_with_any_privilege]=0
    [sequences_with_any_privilege]=0
    [functions_with_privilege_beyond_public]=0
    [database_create_for_monitor]=false
    [public_schema_create_for_monitor]=false
    [schemas_with_create_for_monitor]=0
    [public_executable_security_definer_functions]=0
    [other_sessions_showing_query_text]=0
    [other_sessions_seen]=true
  )
  local rows
  rows=$(psql_monitor -At -F'|' -f "$here/verify.sql")
  local failed=0
  compare_rows expected "$rows" || failed=1

  # The function must count what the database owner's own session counts, and must see the held-open session in
  # its idle-in-transaction count. If the owner role lacks its statistics role, every other role's state reads as
  # NULL and the function silently under-counts.
  echo "Cross-check against the database owner's own session counts:"
  if [ "$ready" -lt 1 ]; then
    echo "  FAIL  the held-open session did not appear"
    failed=1
  else
    local attempt conns active idle_in_tx first second tolerance low high ok=0
    for attempt in 1 2 3; do
      first=$(psql_admin -At -c "SELECT count(*) FROM pg_stat_activity
        WHERE datname = current_database() AND backend_type = 'client backend'")
      IFS=',' read -r conns active idle_in_tx < <(
        psql_monitor -At -F',' -c "SELECT conns, active, idle_in_tx FROM monitor.connection_counts()")
      second=$(psql_admin -At -c "SELECT count(*) FROM pg_stat_activity
        WHERE datname = current_database() AND backend_type = 'client backend'")
      tolerance=$(( (first > second ? first : second) / 10 ))
      [ "$tolerance" -ge 3 ] || tolerance=3
      low=$(( (first < second ? first : second) - tolerance ))
      high=$(( (first > second ? first : second) + tolerance ))
      if [ "$conns" -ge "$low" ] && [ "$conns" -le "$high" ] && [ "$conns" -ge 2 ] && [ "$idle_in_tx" -ge 1 ] && [ "$active" -ge 1 ]; then
        ok=1
        break
      fi
      sleep 1
    done
    if [ "$ok" = 1 ]; then
      printf '  ok    %-46s %s (owner session: %s to %s)\n' "function_conns_match_owner_count" "$conns" "$first" "$second"
      printf '  ok    %-46s %s\n' "function_sees_idle_in_transaction" "$idle_in_tx"
    else
      printf '  FAIL  %-46s function: conns=%s active=%s idle_in_tx=%s; owner session: %s to %s\n' \
        "function_conns_match_owner_count" "$conns" "$active" "$idle_in_tx" "$first" "$second"
      failed=1
    fi
  fi
  cleanup
  return $failed
}

if [ "$mode" = verify ]; then
  verify
  exit $?
fi

if [ "$mode" = provision ]; then
  if [ -z "${OPENKEY_MONITOR_PW:-}" ]; then
    OPENKEY_MONITOR_PW=$(openssl rand -hex 24)
  fi
  export OPENKEY_MONITOR_PW
  # Masked before anything else uses it.
  [ -z "${GITHUB_ACTIONS:-}" ] || echo "::add-mask::$OPENKEY_MONITOR_PW"

  if [ -n "${OPENKEY_AGE_RECIPIENT:-}" ] && [ -z "${OPENKEY_MONITOR_URL_OUT:-}" ]; then
    echo "OPENKEY_AGE_RECIPIENT needs OPENKEY_MONITOR_URL_OUT" >&2
    exit 2
  fi
  # A recipient that has the right shape can still be one age rejects. Found out here, before the password is
  # rotated, not after it, when the old password is already dead and there is no artifact.
  if [ -n "${OPENKEY_AGE_RECIPIENT:-}" ] && ! age -r "$OPENKEY_AGE_RECIPIENT" -o /dev/null </dev/null; then
    echo "age does not accept OPENKEY_AGE_RECIPIENT; nothing was changed" >&2
    exit 2
  fi

  is_super=$(psql_admin -At -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
  echo "Database owner is a superuser: $is_super; the owner role joins: $OPENKEY_OWNER_STATS_ROLE"
  # Whether the server logs the statement that sets the password. Either way only a SCRAM-SHA-256 verifier of it is sent.
  echo "Server log_statement: $(psql_admin -At -c 'SHOW log_statement'); the password is sent as a SCRAM-SHA-256 verifier."
  OPENKEY_MONITOR_PW_VERIFIER=$(python3 "$here/scram.py")
  export OPENKEY_MONITOR_PW_VERIFIER
  psql_admin --single-transaction -f "$here/provision.sql"
  echo "Provisioned: openkey_monitor_owner, schema monitor, monitor.connection_counts(), openkey_monitor."

  verify

  if [ -n "${OPENKEY_AGE_RECIPIENT:-}" ]; then
    python3 "$here/conn.py" --monitor-url | age -r "$OPENKEY_AGE_RECIPIENT" -o "$OPENKEY_MONITOR_URL_OUT"
    echo "Wrote the monitor connection URL, age-encrypted to the given recipient."
  fi
  exit 0
fi

# drop
psql_admin --single-transaction -f "$here/drop.sql"
echo "Dropped. Nothing-left check, as the database owner:"
declare -A gone=(
  [monitor_role_exists]=false
  [owner_role_exists]=false
  [schema_exists]=false
  [function_exists]=false
  [role_settings_left]=0
  [memberships_left]=0
)
rows=$(psql_admin -At -F'|' -f "$here/nothing-left.sql")
compare_rows gone "$rows"
