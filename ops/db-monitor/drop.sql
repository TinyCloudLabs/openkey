-- Remove the connection-count monitor (TC-3067), the rollback of provision.sql. Run by db-monitor-role.sh as the
-- database owner, in one transaction with ON_ERROR_STOP. Safe to run when nothing, or only part of it, exists.
-- It does not end a session the monitor role already has open: that session stays until it disconnects, and the
-- role can no longer log in.

\set ON_ERROR_STOP on
SET client_min_messages = warning;

SELECT current_setting('server_version_num')::int >= 160000 AS pg16,
       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super,
       EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor_owner') AS owner_exists \gset

-- A database owner that is not a superuser drops the owner role's objects only while it can act as that role.
-- The membership goes away with the role at the end.
\if :is_super
\else
  \if :owner_exists
    \if :pg16
      GRANT openkey_monitor_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    \else
      GRANT openkey_monitor_owner TO CURRENT_USER;
    \endif
  \endif
\endif

DROP FUNCTION IF EXISTS monitor.connection_counts();

-- Only an empty schema owned by the owner role is dropped, never a monitor schema that holds anything else.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'monitor') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
      WHERE n.nspname = 'monitor' AND r.rolname = 'openkey_monitor_owner'
    ) THEN
      RAISE EXCEPTION 'schema monitor is not owned by openkey_monitor_owner; not dropping it';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'monitor')
       OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'monitor') THEN
      RAISE EXCEPTION 'schema monitor still holds objects other than monitor.connection_counts(); not dropping it';
    END IF;
  END IF;
END
$$;

DROP SCHEMA IF EXISTS monitor;
DROP ROLE IF EXISTS openkey_monitor;

SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor_owner') AS owner_still \gset
\if :owner_still
  REVOKE pg_read_all_stats FROM openkey_monitor_owner;
  DROP ROLE openkey_monitor_owner;
\endif
