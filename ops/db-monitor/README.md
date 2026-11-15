# OpenKey database connection monitor

A read-only role that can run one function, `monitor.connection_counts()`, so something outside the API (the
saturation probe in another repository) can watch the database's connection use. The function returns six aggregate
numbers for the current database: connections, active, idle in transaction, waiting on a lock, `max_connections`,
and the oldest open transaction's age in seconds. It returns no query text and no identity.

| Role | What it is |
| --- | --- |
| `openkey_monitor_owner` | `NOLOGIN`, a member only of one statistics role (so the function can see other roles' session state): `pg_read_all_stats`, or `pg_monitor` when the workflow's `owner_stats_role` input asks for it. Owns schema `monitor` and the function. |
| `openkey_monitor` | `LOGIN`, `CONNECTION LIMIT 2`, no superuser, createdb, createrole, replication or bypassrls, no role memberships, `default_transaction_read_only = on`, `statement_timeout = 5s`. May use schema `monitor` and execute the one function. |

It is not a migration. Schema `monitor` is outside Prisma's managed `public` schema, so migrations and
`bun run db:migrate:verify-schema` ignore it (`test-migrated.sh` checks this), and it never rides an app deploy.

## Running it

Manual only: **Actions → Provision DB monitor role → Run workflow** on `main`, with the typed confirmation.

- `provision` creates or refreshes the roles and the function in one transaction, generates the monitor password in
  the runner, rotates it on every run, runs the post-checks as `openkey_monitor`, and only if they all pass writes
  the monitor connection URL, `age`-encrypted to the public key you give it, as the artifact
  `openkey-db-monitor-url` (kept one day). Decrypt it with the private key into `/dev/shm`, pipe it into
  `gh secret set`, and delete both.
- `drop` removes the function, the schema and both roles, then checks that nothing is left.

`owner_stats_role` has exactly two values and no automatic fallback. Use `pg_monitor` only when the default was refused:
a managed Postgres may let its owner role grant `pg_monitor` but not `pg_read_all_stats`. It applies to the `NOLOGIN` owner
role only; the post-checks prove the monitor login role is in neither.

The password reaches `psql` through the environment and `\getenv`, never a command line, and is never printed. What is
sent is a SCRAM-SHA-256 verifier of it, so a server that logs statements does not log the password; the run reports the
server's `log_statement` setting. Output is booleans and counts.

Locally: `DATABASE_URL=… ops/db-monitor/db-monitor-role.sh provision|verify|drop` (psql 15 or later).

## What the post-checks assert

As `openkey_monitor`: the function returns one row; the role has none of the dangerous attributes, one login, two
connections, no memberships, and is not in `pg_read_all_stats` or `pg_monitor`; the schema and the function belong to
the owner role, are closed to PUBLIC, and are open to the monitor role only; the monitor role has no privilege on any
table, view, column or sequence in any non-system schema, and none on any function beyond what PUBLIC already
has; no `SECURITY DEFINER` function PUBLIC can execute; no `CREATE` for the monitor role in the public schema or any other
non-system schema; other sessions' query text reads `<insufficient privilege>`; whether it may create temporary tables is
reported. Then a cross-check: a session held open in a
transaction by the database owner must be counted by the function, and the function's connection total must match the
owner session's own count, so a function that silently under-counts fails the run.

PUBLIC holds `EXECUTE` on every function by default, including the `openkey_*` guard functions the migrations create
in `public`; the post-checks print that count as information, because it is not a privilege of the monitor role.

## Tests

`test.sh` runs against real servers (`.github/workflows/db-monitor-role-test.yml`: PostgreSQL 15, 16 and 17): a
database owned by a superuser, and one owned by a role that is not (a managed Postgres owner). Each runs once for each statistics role. Each runs provision,
the post-checks, thirteen deliberate deviations that the post-checks must catch, a password rotation, drop, a second
drop, and nothing left. It also checks that a foreign schema called `monitor` is never taken over, that an owner who
may not grant `pg_read_all_stats` leaves nothing behind (and succeeds with `owner_stats_role = pg_monitor`), and that the encrypted URL decrypts to a working connection.
`test-migrated.sh` repeats provision and drop on the schema the Prisma migrations create, with the drift check clean.
