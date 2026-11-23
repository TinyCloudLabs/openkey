// TC-3810 (R-reg Q5 caveat) on a real tinycloud-node 1.26.22+ (#717) binary (opt-in):
// verifies that an owner renewal lease admitted by OpenKey for a `"terminal"`
// original delegation is actually renewed by the real node (stamping a renewal
// in `caps.db`), once `@tinycloud/sdk-core` is bumped past step 2 so
// `admitOwnerRenewalLease` tolerates `xyz.tinycloud.policy/delegationMode`.
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
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, prepareSession } from '@tinycloud/node-sdk-wasm';
import { prepareRenewalStage, signLease, admitLease } from '../services/renewal-lease';
import { withRecapDelegationMode } from '../services/signed-subset';

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
  test.skip('a renewal lease on a terminal original delegation renews on a real 1.26.22+ tinycloud-node', () => {});
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
    for (let attempt = 0; attempt < 120; attempt++) {
      try {
        if ((await fetch(`${host}/.well-known/tinycloud/node-keys`)).ok) break;
      } catch {
        /* wait for startup */
      }
      await delay(250);
    }
  }, 60_000);

  afterAll(async () => {
    node?.kill('SIGCONT');
    node?.kill('SIGTERM');
    if (node) await Promise.race([once(node, 'exit'), delay(10_000)]);
    if (nodeDir) rmSync(nodeDir, { recursive: true, force: true });
  });

  function stampCount(ownerAddress: string): number {
    const db = new Database(join(nodeDir, 'data', 'caps.db'), { readonly: true });
    try {
      const row = db
        .prepare(
          `SELECT count(*) AS n FROM renewal_stamp s JOIN renewal_lease l ON l.lease_cid = s.lease_cid
           WHERE lower(l.grantor) LIKE '%' || lower(?)`,
        )
        .get(ownerAddress) as { n: number };
      return row.n;
    } finally {
      db.close();
    }
  }

  test(
    'a renewal lease on a terminal original delegation renews on a real 1.26.22+ tinycloud-node',
    async () => {
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
      const terminalSiwe = withRecapDelegationMode(rawPrepared.siwe, 'terminal');
      const originalSig = await account.signMessage({ message: terminalSiwe });
      const original = completeSessionSetup({ ...rawPrepared, siwe: terminalSiwe, signature: originalSig });

      // Register the terminal original delegation with the real node first.
      const activate = await fetch(`${host}/delegate`, {
        method: 'POST',
        headers: original.delegationHeader,
      });
      expect(activate.ok).toBe(true);

      // Prepare, sign, and admit the owner renewal lease through OpenKey's service.
      let stage = await prepareRenewalStage({
        userId: 'tc3810-real-node-owner',
        host,
        leaseLifetimeSeconds: LEASE_SECONDS,
        delegation: {
          delegationHeader: original.delegationHeader,
          delegationCid: original.delegationCid,
          spaceId,
          siwe: terminalSiwe,
          hostActivated: true,
        },
        now: new Date(),
      });
      stage = signLease(stage, await account.signMessage({ message: stage.leaseSiwe }));
      const receipt = await admitLease(stage, { nodeOrigin: host, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } });
      expect(receipt.receipt.originalCid).toBe(original.delegationCid);

      // Wait until the real node's renewal scheduler stamps at least one renewal for this terminal original.
      const deadline = Date.now() + ORIGINAL_MS - 30_000;
      while (stampCount(account.address) === 0) {
        if (Date.now() > deadline) {
          throw new Error('real tinycloud-node did not renew the lease on the terminal original delegation in time');
        }
        await delay(10_000);
      }
      expect(stampCount(account.address)).toBeGreaterThanOrEqual(1);
    },
    25 * 60_000,
  );
}
