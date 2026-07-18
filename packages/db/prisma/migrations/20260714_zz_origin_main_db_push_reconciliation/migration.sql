-- A database created by `prisma db push` from origin/main uses Prisma's
-- shortened implicit name for this unique index. The historical SQL migration
-- used a longer explicit name that PostgreSQL truncated differently. Reconcile
-- the db-push database with the tracked migration/schema name before applying
-- managed-account migrations. This is a no-op for databases built from the
-- migration history.
DO $$
BEGIN
  IF to_regclass('"tinycloud_bootstrap_state_keyId_chainId_tinycloudHost_boots_key"') IS NOT NULL
     AND to_regclass('"tinycloud_bootstrap_state_keyId_chainId_tinycloudHost_bootstrap"') IS NULL THEN
    ALTER INDEX "tinycloud_bootstrap_state_keyId_chainId_tinycloudHost_boots_key"
      RENAME TO "tinycloud_bootstrap_state_keyId_chainId_tinycloudHost_bootstrap";
  END IF;

  IF to_regclass('"tinycloud_bootstrap_state_keyId_chainId_tinycloudHost_bootstrap"') IS NULL THEN
    RAISE EXCEPTION 'expected TinyCloud bootstrap unique index is missing';
  END IF;
END $$;
