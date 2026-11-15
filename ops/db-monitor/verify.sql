-- Post-checks for the connection-count monitor (TC-3067). Run by db-monitor-role.sh as openkey_monitor, with
-- psql -At -F'|'. Each row is `check|value`: booleans (t/f) and counts, nothing else, so the output names no
-- identity and no query text. db-monitor-role.sh compares every row with its expected value.

\set ON_ERROR_STOP on
\getenv stats_role OPENKEY_OWNER_STATS_ROLE

SELECT 'function_returns_one_row', count(*)::text FROM monitor.connection_counts();

-- The monitor role.
SELECT 'monitor_can_login', rolcanlogin::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_superuser', rolsuper::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_createdb', rolcreatedb::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_createrole', rolcreaterole::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_replication', rolreplication::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_bypassrls', rolbypassrls::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_connection_limit', rolconnlimit::text FROM pg_roles WHERE rolname = 'openkey_monitor';
SELECT 'monitor_role_memberships', count(*)::text FROM pg_auth_members
  WHERE member = 'openkey_monitor'::regrole;
SELECT 'monitor_is_pg_read_all_stats', (pg_has_role('openkey_monitor', 'pg_read_all_stats', 'USAGE')
  OR pg_has_role('openkey_monitor', 'pg_read_all_stats', 'MEMBER'))::text;
SELECT 'monitor_is_pg_monitor', (pg_has_role('openkey_monitor', 'pg_monitor', 'USAGE')
  OR pg_has_role('openkey_monitor', 'pg_monitor', 'MEMBER'))::text;
SELECT 'monitor_default_read_only', current_setting('default_transaction_read_only');
SELECT 'monitor_statement_timeout', current_setting('statement_timeout');

-- The owner role.
SELECT 'owner_can_login', rolcanlogin::text FROM pg_roles WHERE rolname = 'openkey_monitor_owner';
SELECT 'owner_superuser', rolsuper::text FROM pg_roles WHERE rolname = 'openkey_monitor_owner';
SELECT 'owner_memberships', count(*)::text FROM pg_auth_members WHERE member = 'openkey_monitor_owner'::regrole;
SELECT 'owner_member_of_stats_role_only', (count(*) = 1)::text FROM pg_auth_members
  WHERE member = 'openkey_monitor_owner'::regrole AND roleid = :'stats_role'::regrole;
-- Nobody can use the owner role: no member inherits it or can SET ROLE to it. (On PostgreSQL 16 the role's creator,
-- when it is not a superuser, keeps a bare ADMIN membership, which neither inherits nor can SET ROLE; before 16
-- there are no such flags, so any member counts.)
SELECT 'owner_members_able_to_use_it', count(*)::text FROM pg_auth_members m
WHERE m.roleid = 'openkey_monitor_owner'::regrole
  AND (coalesce((to_jsonb(m) ->> 'inherit_option')::boolean, true)
       OR coalesce((to_jsonb(m) ->> 'set_option')::boolean, true));

-- The schema and the function.
SELECT 'schema_owned_by_owner', (nspowner = 'openkey_monitor_owner'::regrole)::text
  FROM pg_namespace WHERE nspname = 'monitor';
SELECT 'schema_usage_for_public', has_schema_privilege('public', 'monitor', 'USAGE')::text;
SELECT 'schema_create_for_public', has_schema_privilege('public', 'monitor', 'CREATE')::text;
SELECT 'schema_usage_for_monitor', has_schema_privilege('openkey_monitor', 'monitor', 'USAGE')::text;
SELECT 'schema_create_for_monitor', has_schema_privilege('openkey_monitor', 'monitor', 'CREATE')::text;
SELECT 'schema_object_count', (
  (SELECT count(*) FROM pg_class c WHERE c.relnamespace = 'monitor'::regnamespace)
  + (SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'monitor'::regnamespace))::text;
SELECT 'function_owned_by_owner', (proowner = 'openkey_monitor_owner'::regrole)::text
  FROM pg_proc WHERE oid = 'monitor.connection_counts()'::regprocedure;
SELECT 'function_security_definer', prosecdef::text
  FROM pg_proc WHERE oid = 'monitor.connection_counts()'::regprocedure;
SELECT 'function_arguments', pronargs::text
  FROM pg_proc WHERE oid = 'monitor.connection_counts()'::regprocedure;
SELECT 'function_search_path', (proconfig = ARRAY['search_path=pg_catalog, pg_temp'])::text
  FROM pg_proc WHERE oid = 'monitor.connection_counts()'::regprocedure;
SELECT 'function_execute_for_public', has_function_privilege('public', 'monitor.connection_counts()', 'EXECUTE')::text;
SELECT 'function_execute_for_monitor', has_function_privilege('openkey_monitor', 'monitor.connection_counts()', 'EXECUTE')::text;

-- What openkey_monitor can reach in every non-system schema, apart from monitor.connection_counts():
-- any privilege on a table, view or column, on a sequence, and on a function beyond what PUBLIC already has.
-- PUBLIC holds EXECUTE on every function by default, including the public.openkey_* guard functions the
-- migrations create; that is counted below as information, not as a privilege of the monitor role.
SELECT 'tables_with_any_privilege', count(*)::text
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  AND (has_table_privilege('openkey_monitor', c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
       OR has_any_column_privilege('openkey_monitor', c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'));
SELECT 'sequences_with_any_privilege', count(*)::text
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'S'
  AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('openkey_monitor', c.oid, 'USAGE, SELECT, UPDATE') END;
SELECT 'functions_with_privilege_beyond_public', count(*)::text
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  AND p.oid <> 'monitor.connection_counts()'::regprocedure
  AND has_function_privilege('openkey_monitor', p.oid, 'EXECUTE')
  AND NOT has_function_privilege('public', p.oid, 'EXECUTE');
SELECT 'database_create_for_monitor', has_database_privilege('openkey_monitor', current_database(), 'CREATE')::text;
-- The monitor role cannot create objects in the public schema, or in any other non-system schema.
SELECT 'public_schema_create_for_monitor', has_schema_privilege('openkey_monitor', 'public', 'CREATE')::text;
SELECT 'schemas_with_create_for_monitor', count(*)::text FROM pg_namespace n
WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  AND has_schema_privilege('openkey_monitor', n.oid, 'CREATE');
-- No function that runs with its owner's rights may be executable by PUBLIC.
SELECT 'public_executable_security_definer_functions', count(*)::text
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  AND p.prosecdef AND has_function_privilege('public', p.oid, 'EXECUTE');

-- Other sessions in this database show no query text to the monitor role. (Their backend_type and state read as
-- NULL too: the monitor role is in neither pg_read_all_stats nor pg_monitor; only the function, through its owner,
-- sees them.)
SELECT 'other_sessions_showing_query_text', count(*)::text FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()
  AND query IS DISTINCT FROM '<insufficient privilege>';
SELECT 'other_sessions_seen', (count(*) > 0)::text FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid();

-- Information only, not compared: whether the monitor role may create temporary tables (PUBLIC holds TEMPORARY on
-- a database by default; nothing persists, and no table it could create is readable by anyone else).
SELECT 'info_temporary_tables_for_monitor', has_database_privilege('openkey_monitor', current_database(), 'TEMPORARY')::text;

-- Information only, not compared: functions PUBLIC can execute in non-system schemas.
SELECT 'info_public_executable_functions', count(*)::text
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  AND p.oid <> 'monitor.connection_counts()'::regprocedure
  AND has_function_privilege('public', p.oid, 'EXECUTE');
