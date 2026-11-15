-- Provision the connection-count monitor (TC-3067, design B). Run by db-monitor-role.sh as the database
-- owner, in one transaction (psql --single-transaction) with ON_ERROR_STOP: any failure leaves nothing behind.
--
--   openkey_monitor_owner  NOLOGIN, member only of pg_read_all_stats. Owns schema `monitor` and the function.
--   openkey_monitor        LOGIN, two connections, no memberships. May use schema `monitor` and execute the
--                          one function in it. Nothing else.
--
-- Safe to run again: it enforces the same end state and rotates the monitor role's password.

\set ON_ERROR_STOP on
SET client_min_messages = warning;
-- The password comes from the environment, never from the command line.
\getenv pw OPENKEY_MONITOR_PW

SELECT current_setting('server_version_num')::int >= 160000 AS pg16,
       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super \gset

-- On PostgreSQL 16 the membership edge carries the inherit flag, so the owner can be NOINHERIT. Before 16 the
-- flag lives on the role, so the owner must be INHERIT to use pg_read_all_stats.
SELECT CASE WHEN :'pg16' = 't' THEN 'NOINHERIT' ELSE 'INHERIT' END AS owner_inherit \gset

-- Owner role.
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor_owner') AS owner_missing \gset
\if :owner_missing
  CREATE ROLE openkey_monitor_owner NOLOGIN :owner_inherit;
\else
  ALTER ROLE openkey_monitor_owner NOLOGIN :owner_inherit;
\endif

-- A database owner that is not a superuser (a managed Postgres) may create objects as the new role only while it
-- can act as that role. Taken for this transaction and removed again at the end.
\if :is_super
\else
  \if :pg16
    GRANT openkey_monitor_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  \else
    GRANT openkey_monitor_owner TO CURRENT_USER;
  \endif
\endif

-- pg_read_all_stats lets the function see state and xact_start of other roles' sessions.
\if :pg16
  GRANT pg_read_all_stats TO openkey_monitor_owner WITH INHERIT TRUE;
\else
  GRANT pg_read_all_stats TO openkey_monitor_owner;
\endif

-- Never take over a schema called monitor that something else owns.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_namespace n
    WHERE n.nspname = 'monitor'
      AND n.nspowner <> (SELECT oid FROM pg_roles WHERE rolname = 'openkey_monitor_owner')
  ) THEN
    RAISE EXCEPTION 'schema monitor exists and is not owned by openkey_monitor_owner; not touching it';
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS monitor AUTHORIZATION openkey_monitor_owner;

-- Monitor role (created before the owner's objects so its grants can follow in the same block).
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor') AS monitor_missing \gset
\if :monitor_missing
  CREATE ROLE openkey_monitor WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 2 PASSWORD :'pw';
\else
  -- SUPERUSER, REPLICATION and BYPASSRLS can only be altered by a superuser, so a re-run leaves them to the
  -- post-checks, which fail unless all three are off.
  ALTER ROLE openkey_monitor WITH LOGIN NOCREATEDB NOCREATEROLE CONNECTION LIMIT 2 PASSWORD :'pw';
\endif
ALTER ROLE openkey_monitor SET default_transaction_read_only = on;
ALTER ROLE openkey_monitor SET statement_timeout = '5s';

-- The schema's contents are created, and its privileges granted, as the owner.
SET LOCAL ROLE openkey_monitor_owner;

REVOKE ALL ON SCHEMA monitor FROM PUBLIC;

CREATE OR REPLACE FUNCTION monitor.connection_counts()
  RETURNS TABLE (conns int, active int, idle_in_tx int, lock_waiting int, max_conn int, oldest_xact_s int)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT count(*) FILTER (WHERE backend_type = 'client backend')::int,
         count(*) FILTER (WHERE state = 'active')::int,
         count(*) FILTER (WHERE state = 'idle in transaction')::int,
         count(*) FILTER (WHERE wait_event_type = 'Lock')::int,
         (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'),
         coalesce(max(extract(epoch FROM now() - xact_start)) FILTER (WHERE state <> 'idle'), 0)::int
  FROM pg_stat_activity WHERE datname = current_database();
$$;

REVOKE EXECUTE ON FUNCTION monitor.connection_counts() FROM PUBLIC;
REVOKE ALL ON SCHEMA monitor FROM openkey_monitor;
GRANT USAGE ON SCHEMA monitor TO openkey_monitor;
GRANT EXECUTE ON FUNCTION monitor.connection_counts() TO openkey_monitor;

RESET ROLE;

\if :is_super
\else
  REVOKE openkey_monitor_owner FROM CURRENT_USER;
\endif
