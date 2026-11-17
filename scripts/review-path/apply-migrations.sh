#!/usr/bin/env bash
# Applies the tracked migrations, in order, to the throwaway database named by DATABASE_URL (psql), and
# records each one in `_prisma_migrations` with the checksum Prisma stores (sha256 of migration.sql). The API's
# /health reports ready only when the rows it requires are there with those checksums.
#
# It mirrors production: `20260806_0002_remove_organization_key_custody` (TC-488) is parked there on
# purpose and `scripts/deploy-production-migrations.ts` never applies it, so this does not either.
# Every other migration runs in order and the first error stops the run. Some migrations carry their own
# BEGIN/COMMIT, so psql's --single-transaction is not used (it only warns about the nesting).
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
PARKED="20260806_0002_remove_organization_key_custody"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
sql() { psql "$DATABASE_URL" --quiet --set ON_ERROR_STOP=1 "$@" > /dev/null; }

sql --command 'CREATE TABLE IF NOT EXISTS "_prisma_migrations" (
  "id" VARCHAR(36) PRIMARY KEY NOT NULL,
  "checksum" VARCHAR(64) NOT NULL,
  "finished_at" TIMESTAMPTZ,
  "migration_name" VARCHAR(255) NOT NULL,
  "logs" TEXT,
  "rolled_back_at" TIMESTAMPTZ,
  "started_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
  "applied_steps_count" INTEGER NOT NULL DEFAULT 0
)'

count=0
for dir in "$root"/packages/db/prisma/migrations/*/; do
  name="$(basename "$dir")"
  [[ -f "$dir/migration.sql" ]] || continue
  if [[ "$name" == "$PARKED" ]]; then
    echo "skipping parked migration $name"
    continue
  fi
  sql --file "$dir/migration.sql"
  checksum="$(sha256sum "$dir/migration.sql" | cut -d' ' -f1)"
  sql --command "INSERT INTO \"_prisma_migrations\" (\"id\", \"checksum\", \"finished_at\", \"migration_name\", \"applied_steps_count\") VALUES (gen_random_uuid()::text, '$checksum', now(), '$name', 1)"
  count=$((count + 1))
done
echo "applied $count migrations"
