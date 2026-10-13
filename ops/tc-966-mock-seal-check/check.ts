// TC-966: were any sealed keys in the database sealed with the *mock* TEE
// client instead of dstack?
//
// The mock client seals under sha256(DEV_SEALING_KEY || path), where
// DEV_SEALING_KEY falls back to a public default. This script tries every
// sealed blob against the public dev keys and the deployment's key, and prints
// COUNTS ONLY: per table, per sealing-path type, per result, plus the
// created_at range of any blob that decrypts. It never prints, logs or writes
// key material, plaintext, user IDs, sealing contexts or blobs.
//
// Read-only: one transaction, `SET TRANSACTION READ ONLY`, rolled back at the
// end.
//
// Environment (read, never echoed):
//   DATABASE_URL      the database to check (required)
//   DEV_SEALING_KEY   the deployment's DEV_SEALING_KEY, if it has one (optional)
//
// Usage: bun --no-env-file run ops/tc-966-mock-seal-check/check.ts
// (--no-env-file stops Bun loading a local .env in place of the real values.)
// See README.md for what each result means.
import { SQL } from 'bun';
import { createDecipheriv, createHash } from 'node:crypto';

/**
 * Every DEV_SEALING_KEY value published in this repository, so anyone could
 * have derived the key: the code's fallback (packages/tee/src/index.ts, since
 * 2026-01-04), docker-compose.yml and docs/development.md, the .env.example
 * placeholder, the README placeholder, the nostr route tests, and the
 * local-pglite-device-smoke script on branch skgbafa/tc-13-openkey-session-recovery.
 */
const PUBLIC_DEV_SEALING_KEYS = [
  'openkey-dev-sealing-key-32b!',
  'openkey-dev-sealing-key-32bytes!',
  '<32-byte-hex-key-for-local-dev>',
  '...',
  'test-sealing-key-for-nostr-route-tests',
  '0123456789abcdef0123456789abcdef',
];

type Result =
  | 'decrypts with a public dev key'
  | 'decrypts with the prod DEV_SEALING_KEY'
  | "doesn't decrypt"
  | 'malformed blob'
  | 'no sealing path';

interface SealedRow {
  table: string;
  pathType: string;
  /** null when the row's sealing path can't be reconstructed. */
  path: string | null;
  blob: string;
  createdAt: Date;
}

interface Tally {
  count: number;
  earliest?: Date;
  latest?: Date;
}

/** True when `blob` (base64 iv[12] || tag[16] || ciphertext) authenticates under the mock key. */
function opensWith(blob: Buffer, devKey: string, path: string): boolean {
  const key = createHash('sha256').update(devKey).update(path).digest();
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    const plaintext = Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
    plaintext.fill(0);
    return true;
  } catch {
    return false;
  } finally {
    key.fill(0);
  }
}

function classify(row: SealedRow, prodDevKey: string | undefined): Result {
  if (row.path === null) return 'no sealing path';
  const blob = Buffer.from(row.blob, 'base64');
  if (blob.length < 28) return 'malformed blob';
  const path = row.path;
  // Public keys first: a prod key that equals a published one is public.
  if (PUBLIC_DEV_SEALING_KEYS.some((devKey) => opensWith(blob, devKey, path))) return 'decrypts with a public dev key';
  if (prodDevKey && opensWith(blob, prodDevKey, path)) return 'decrypts with the prod DEV_SEALING_KEY';
  return "doesn't decrypt";
}

async function readSealedRows(tx: SQL): Promise<SealedRow[]> {
  const rows: SealedRow[] = [];

  // Managed Ethereum keys (external keys have no blob). Path: per-key context,
  // or the legacy per-user path when sealingContext is NULL.
  const ethereum = await tx`
    SELECT "userId", "sealingContext", "sealedBlob", "createdAt"
    FROM "ethereum_keys" WHERE "sealedBlob" IS NOT NULL`;
  for (const r of ethereum) {
    const perKey = r.sealingContext !== null;
    rows.push({
      table: 'ethereum_keys',
      pathType: perKey ? 'openkey/key/<context>' : 'openkey/user/<id>/keys',
      path: perKey ? `openkey/key/${r.sealingContext}` : r.userId === null ? null : `openkey/user/${r.userId}/keys`,
      blob: r.sealedBlob,
      createdAt: r.createdAt,
    });
  }

  const nostr = await tx`SELECT "sealingContext", "sealedSecret", "createdAt" FROM "nostr_keys"`;
  for (const r of nostr) {
    rows.push({
      table: 'nostr_keys',
      pathType: 'openkey/key/<context>',
      path: `openkey/key/${r.sealingContext}`,
      blob: r.sealedSecret,
      createdAt: r.createdAt,
    });
  }

  // Legacy RSA encryption keys (2026-03-03 to 2026-03-04 code path).
  const legacy = await tx`SELECT "userId", "sealedPrivateKey", "createdAt" FROM "user_encryption_key"`;
  for (const r of legacy) {
    rows.push({
      table: 'user_encryption_key',
      pathType: 'openkey/user/<id>/encryption',
      path: `openkey/user/${r.userId}/encryption`,
      blob: r.sealedPrivateKey,
      createdAt: r.createdAt,
    });
  }
  return rows;
}

async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL is not set. Export it in the runner environment; this script never prompts.');
    process.exit(2);
  }
  const prodDevKey = process.env.DEV_SEALING_KEY || undefined;

  const sql = new SQL({ url: databaseUrl, max: 1 });
  const tx = await sql.reserve();
  const tallies = new Map<string, Tally>();
  let total = 0;
  let databaseName = '';
  try {
    await tx`BEGIN`;
    await tx`SET TRANSACTION READ ONLY`;
    const [{ transaction_read_only: readOnly }] = await tx`SHOW transaction_read_only`;
    if (readOnly !== 'on') throw new Error('transaction is not read-only; refusing to continue');
    // A name, not a credential: lets the operator confirm the target database.
    [{ current_database: databaseName }] = await tx`SELECT current_database()`;

    for (const row of await readSealedRows(tx)) {
      total += 1;
      const result = classify(row, prodDevKey);
      const label = `${row.table}\t${row.pathType}\t${result}`;
      const tally = tallies.get(label) ?? { count: 0 };
      tally.count += 1;
      if (result.startsWith('decrypts')) {
        if (!tally.earliest || row.createdAt < tally.earliest) tally.earliest = row.createdAt;
        if (!tally.latest || row.createdAt > tally.latest) tally.latest = row.createdAt;
      }
      tallies.set(label, tally);
    }
  } finally {
    await tx`ROLLBACK`.catch(() => {});
    tx.release();
    await sql.close();
  }

  console.log(`TC-966 mock-seal check: ${total} sealed blobs checked in database "${databaseName}" (read-only transaction, rolled back)`);
  console.log(`public dev keys tried: ${PUBLIC_DEV_SEALING_KEYS.length} (every value published in the repository)`);
  const prodKeyNote = !prodDevKey
    ? 'NOT provided: only the public dev keys were tried'
    : PUBLIC_DEV_SEALING_KEYS.includes(prodDevKey)
      ? 'provided, but it EQUALS a published dev key, so it is public (check this is the intended value)'
      : 'provided';
  console.log(`prod DEV_SEALING_KEY ${prodKeyNote}`);
  console.log('table\tpath type\tresult\tcount\tcreated_at range');
  for (const [label, tally] of [...tallies].sort(([a], [b]) => a.localeCompare(b))) {
    const range = tally.earliest ? `${tally.earliest.toISOString()} .. ${tally.latest!.toISOString()}` : '';
    console.log(`${label}\t${tally.count}\t${range}`);
  }
  const countWhere = (match: string) =>
    [...tallies].filter(([label]) => label.includes(match)).reduce((n, [, t]) => n + t.count, 0);
  const affected = countWhere('\tdecrypts');
  if (affected > 0) {
    console.log(`VERDICT: AFFECTED: ${affected} blob(s) decrypt with a mock key`);
  } else {
    const tested = prodDevKey ? 'the public dev keys and the provided DEV_SEALING_KEY' : 'the public dev keys only';
    console.log(`VERDICT: no blob decrypts with the tested mock keys (${tested}).`);
    console.log(
      `  Not covered: blobs sealed under any other or earlier DEV_SEALING_KEY, deleted rows and backups, and ${countWhere('\tno sealing path')} row(s) with no sealing path.`,
    );
  }
  process.exitCode = affected === 0 ? 0 : 1;
}

if (import.meta.main) {
  await main().catch((error: unknown) => {
    // Error messages can carry connection details; print only the class/code.
    const name = error instanceof Error ? error.name : 'Error';
    const code =
      error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? ` (${error.code})` : '';
    console.error(`check failed: ${name}${code}`);
    process.exit(2);
  });
}
