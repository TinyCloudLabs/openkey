-- After drop: nothing of the connection-count monitor remains (TC-3067). Run by db-monitor-role.sh as the database
-- owner, with psql -At -F'|'. Each row is `check|value`, a boolean or a count; all must be f or 0.

SELECT 'monitor_role_exists', EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor')::text;
SELECT 'owner_role_exists', EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openkey_monitor_owner')::text;
SELECT 'schema_exists', EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'monitor')::text;
SELECT 'function_exists', (to_regprocedure('monitor.connection_counts()') IS NOT NULL)::text;
SELECT 'role_settings_left', count(*)::text FROM pg_db_role_setting s
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = s.setrole) AND s.setrole <> 0;
SELECT 'memberships_left', count(*)::text FROM pg_auth_members m
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = m.roleid)
     OR NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = m.member);
