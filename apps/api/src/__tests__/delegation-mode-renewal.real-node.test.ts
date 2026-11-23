// TC-3810 (R-reg Q5 caveat + Naomi 05:40Z ruling) on a real tinycloud-node 1.26.22+ (#717) binary (opt-in).
// Runs in the step-2 `@tinycloud/sdk-core` / `@tinycloud/share-sdk` bump commit (which also stamps
// `renewal-lease.ts` `"terminal"`); cannot pass on pinned `@tinycloud/sdk-core@3.12.0-beta.22`.
// Verifies BOTH real-node gates against one live node:
//   1. A `"terminal"` renewal lease renews a `"terminal"` original delegation, and the renewed/stamped
//      original keeps its `"terminal"` mode in `delegation_mode`.
//   2. A `"terminal"` renewal lease renews a non-terminal (`"attenuable"` and undeclared) original
//      delegation, and the renewed/stamped originals keep their non-terminal (`"attenuable"`) mode.
//
//   OPENKEY_TEST_TINYCLOUD_NODE_BINARY=/path/to/tinycloud bun test apps/api/src/__tests__/delegation-mode-renewal.real-node.test.ts
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { closeSync, mkdirSync, mkdtempSync, openSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Database } from 'bun:sqlite';
import { CID } from 'multiformats/cid';
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, prepareSession } from '@tinycloud/node-sdk-wasm';
import { prepareRenewalStage, signLease, admitLease } from '../services/renewal-lease';
import { parseStrictSiwe, withRecapDelegationMode, type DelegationMode } from '../services/signed-subset';

const nodeBinary = process.env.OPENKEY_TEST_TINYCLOUD_NODE_BINARY;
// Node's renewal scheduler runs every 5 minutes and renews at half-life;
// 16-minute original gives a comfortable window before original expiry.
const ORIGINAL_MS = 16 * 60_000;
const LEASE_SECONDS = 40 * 60;

async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  server.close();
  await once(server, 'close');
  return port;
}

if (!nodeBinary) {
  test.skip('terminal lease renews terminal and non-terminal originals on a real 1.26.22+ tinycloud-node and preserves each original mode', () => {});
} else {
  let nodeDir: string;
  let node: ChildProcess;
  let host: string;

  beforeAll(async () => {
    nodeDir = mkdtempSync(join(tmpdir(), 'openkey-tc3810-renewal-node-'));
    const dataDir = join(nodeDir, 'data');
    mkdirSync(dataDir, { mode: 0o700 });
    const port = await freePort();
    host = `http://127.0.0.1:${port}`;
    const config = join(nodeDir, 'tinycloud.toml');
    writeFileSync(
      config,
      [
        '[default]',
        'address = "127.0.0.1"',
        `port = ${port}`,
        'log_level = "critical"',
        '',
        '[default.storage]',
        `datadir = ${JSON.stringify(dataDir)}`,
        `database = ${JSON.stringify(`sqlite:${join(dataDir, 'caps.db')}?mode=rwc`)}`,
        '',
        '[default.keys]',
        'type = "Static"',
        `secret = ${JSON.stringify(randomBytes(32).toString('base64url'))}`,
        '',
        '[default.telemetry]',
        'enabled = false',
        '',
        '[default.epoch_head_backfill]',
        'enabled = false',
        '',
      ].join('\n'),
      { mode: 0o600 },
    );
    const log = openSync(join(nodeDir, 'node.log'), 'a', 0o600);
    node = spawn(nodeBinary, [], {
      cwd: nodeDir,
      env: {
        PATH: '/usr/bin:/bin',
        HOME: process.env.HOME,
        TC_HOME: process.env.HOME,
        TINYCLOUD_CONFIG_FILE: config,
        ROCKET_ADDRESS: '127.0.0.1',
        ROCKET_PORT: String(port),
      },
      stdio: ['ignore', log, log],
    });
    closeSync(log);
    let ready = false;
    for (let attempt = 0; attempt < 120; attempt++) {
      if (node.exitCode !== null) break;
      try {
        if ((await fetch(`${host}/.well-known/tinycloud/node-keys`)).ok) {
          ready = true;
          break;
        }
      } catch {
        /* wait for startup */
      }
      await delay(250);
    }
    if (!ready) {
      throw new Error(
        `real tinycloud-node failed to become ready at ${host}/.well-known/tinycloud/node-keys within 30s (exit=${node.exitCode})`,
      );
    }
  }, 60_000);

  afterAll(async () => {
    node?.kill('SIGCONT');
    node?.kill('SIGTERM');
    if (node) await Promise.race([once(node, 'exit'), delay(10_000)]);
    if (nodeDir) rmSync(nodeDir, { recursive: true, force: true });
  });

  async function queryCapsDb<T>(run: (db: Database) => T): Promise<T> {
    const dbPath = join(nodeDir, 'data', 'caps.db');
    let lastError: unknown;
    for (let attempt = 0; attempt < 5; attempt++) {
      const db = new Database(dbPath, { readonly: true });
      try {
        db.exec('PRAGMA busy_timeout = 5000');
        return run(db);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!/SQLITE_BUSY|database is locked/i.test(message) || attempt === 4) {
          throw err;
        }
        lastError = err;
        await delay(100 * (attempt + 1));
      } finally {
        db.close();
      }
    }
    throw lastError;
  }

  // `tinycloud-core` stores `original_canonical` and `delegation_id` as the 34-byte multihash (`Hash` BLOB).
  async function stampCount(originalCid: string): Promise<number> {
    const canonical = CID.parse(originalCid).multihash.bytes;
    return queryCapsDb((db) => {
      const row = db
        .prepare(
          `SELECT count(*) AS n
           FROM renewal_stamp s
           JOIN renewal_lease l
             ON l.lease_cid = s.lease_cid
            AND l.original_canonical = s.original_canonical
           WHERE s.original_canonical = ?`,
        )
        .get(canonical) as { n: number };
      return row.n;
    });
  }

  async function storedDelegationMode(cid: string): Promise<string | null> {
    const canonical = CID.parse(cid).multihash.bytes;
    return queryCapsDb((db) => {
      const row = db
        .prepare(
          `SELECT dm.mode AS mode
           FROM delegation_mode dm
           WHERE dm.delegation_id = ?
              OR dm.delegation_id IN (SELECT id FROM delegation_cid_alias WHERE canonical = ?)
           LIMIT 1`,
        )
        .get(canonical, canonical) as { mode: string } | null;
      return row?.mode ?? null;
    });
  }

  async function registerAndLeaseOriginal(label: string, originalMode: DelegationMode | undefined) {
    const privateKey = `0x${randomBytes(32).toString('hex')}` as const;
    const account = privateKeyToAccount(privateKey);
    const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as {
      kty: 'OKP';
      crv: 'Ed25519';
      x: string;
    };
    const spaceId = `tinycloud:pkh:eip155:1:${account.address}:default`;
    const now = new Date();
    const rawPrepared = prepareSession({
      address: account.address,
      chainId: 1,
      domain: 'openkey.so',
      issuedAt: new Date(now.getTime() - 1_000).toISOString(),
      expirationTime: new Date(now.getTime() + ORIGINAL_MS).toISOString(),
      spaceId,
      jwk,
      abilities: { kv: { 'notes/': ['tinycloud.kv/get'] } },
    });
    const originalSiwe = originalMode !== undefined ? withRecapDelegationMode(rawPrepared.siwe, originalMode) : rawPrepared.siwe;
    const originalSig = await account.signMessage({ message: originalSiwe });
    const original = completeSessionSetup({ ...rawPrepared, siwe: originalSiwe, signature: originalSig });

    const activate = await fetch(`${host}/delegate`, {
      method: 'POST',
      headers: original.delegationHeader,
    });
    expect(activate.ok).toBe(true);

    let stage = await prepareRenewalStage({
      userId: `tc3810-real-node-${label}`,
      host,
      leaseLifetimeSeconds: LEASE_SECONDS,
      delegation: {
        delegationHeader: original.delegationHeader,
        delegationCid: original.delegationCid,
        spaceId,
        siwe: originalSiwe,
        hostActivated: true,
      },
      now: new Date(),
    });
    // Naomi 05:40Z ruling: once the bump commit stamps renewal-lease.ts 'terminal', the lease itself carries terminal.
    const parsedLease = parseStrictSiwe(stage.leaseSiwe);
    expect(parsedLease.ok).toBe(true);
    if (!parsedLease.ok) throw new Error('unparseable lease SIWE');
    expect(parsedLease.siwe.recap?.delegationMode).toBe('terminal');

    stage = signLease(stage, await account.signMessage({ message: stage.leaseSiwe }));
    const receipt = await admitLease(stage, { nodeOrigin: host, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } });
    expect(receipt.receipt.originalCid).toBe(original.delegationCid);
    return {
      label,
      originalMode,
      originalCid: original.delegationCid,
      leaseCid: stage.leaseCid!,
    };
  }

  test(
    'terminal lease renews terminal and non-terminal originals on a real 1.26.22+ tinycloud-node and preserves each original mode',
    async () => {
      const cases = [
        await registerAndLeaseOriginal('terminal', 'terminal'),
        await registerAndLeaseOriginal('attenuable', 'attenuable'),
        await registerAndLeaseOriginal('undeclared', undefined),
      ];

      // Wait until the real node's renewal scheduler stamps at least one renewal for every grant.
      const deadline = Date.now() + ORIGINAL_MS - 30_000;
      for (;;) {
        const counts = await Promise.all(cases.map((entry) => stampCount(entry.originalCid)));
        if (counts.every((n) => n >= 1)) break;
        if (Date.now() > deadline) {
          throw new Error(`real tinycloud-node did not renew all grants in time: ${JSON.stringify(counts)}`);
        }
        await delay(10_000);
      }

      for (const entry of cases) {
        expect(await stampCount(entry.originalCid)).toBeGreaterThanOrEqual(1);
        // LOW (iii): the renewed/stamped grant preserves the original's mode (terminal stays terminal;
        // attenuable and undeclared stay non-terminal/attenuable), while the lease itself is terminal.
        const expectedOriginalMode = entry.originalMode === 'terminal' ? 'terminal' : 'attenuable';
        expect(await storedDelegationMode(entry.originalCid)).toBe(expectedOriginalMode);
        expect(await storedDelegationMode(entry.leaseCid)).toBe('terminal');
      }
    },
    25 * 60_000,
  );
}
