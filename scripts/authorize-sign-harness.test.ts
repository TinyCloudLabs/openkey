// Sol MAJOR-1 (final): standalone Hono authorize-sign harness.
//
// Runs as a `bun test` (so bun:test's `mock.module` works to intercept
// @openkey/db and @openkey/tee), boots the delegate router on a real
// HTTP port, and blocks the "test" indefinitely until SIGTERM. The
// js-sdk cross-repo test spawns this file as a subprocess, waits for
// the `HARNESS_READY <port>` line on stdout, and hits the real endpoints
// to obtain the actual Hono response body — no fabrication.
//
// Even though this file is named `.test.ts`, it is NOT part of the
// regular Bun test run:
//   1. `bunfig.toml` at the repo root lists it under `[test].ignore`
//      so a broad `bun test` walk skips it.
//   2. As defence-in-depth, the top of this file exits early unless
//      `OPENKEY_RUN_HARNESS=1` is set. The js-sdk cross-repo test that
//      spawns this file as a subprocess sets it explicitly.
if (!process.env.OPENKEY_RUN_HARNESS) {
  // eslint-disable-next-line no-console
  console.log(
    'authorize-sign-harness: skipping (OPENKEY_RUN_HARNESS not set). ' +
      'This file is a standalone harness for the js-sdk cross-repo contract test; ' +
      'it is intentionally excluded from broad bun-test discovery.',
  );
  process.exit(0);
}

import { test, mock } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';

const argPort = process.env.HARNESS_PORT ? Number(process.env.HARNESS_PORT) : 0;
const privateKey =
  (process.env.HARNESS_SIGNER_PRIVATE_KEY as `0x${string}` | undefined) ??
  ('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' as const);
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_harness', email: 'harness@example.test' };

const keyRecord = {
  id: 'key_harness',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return [];
      if (where.archivedAt !== null) return [];
      return [keyRecord];
    }),
    findUnique: mock(async () => keyRecord),
  },
  user: {
    findUnique: mock(async () => ({ autoSignEnabled: true })),
  },
  tinyCloudBootstrapState: {},
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));

mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  seal: mock(async () => 'sealed-blob'),
  unseal: mock(async () => privateKey),
  createWalletFromPrivateKey: (key: string) => {
    const wallet = privateKeyToAccount(key as `0x${string}`);
    return {
      ...wallet,
      signMessage: async (input: { message: string }) => wallet.signMessage(input),
    };
  },
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => address,
}));

mock.module('@tinycloud/sdk-core', () => ({
  activateSessionWithHost: mock(async () => ({ success: true })),
}));

// Path is relative to this file's location (scripts/), resolving to the
// real production delegate router module.
mock.module('../apps/api/src/middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', {
      id: 'session_' + user.id,
      userId: user.id,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await next();
  }),
}));

test(
  'authorize-sign harness — HTTP server for cross-repo tests (blocks until SIGTERM)',
  async () => {
    const { delegateRouter } = await import('../apps/api/src/routes/delegate');
    const { Hono } = await import('hono');
    const host = new Hono();
    host.route('/api/delegate', delegateRouter);
    host.get('/__harness/ping', (c) => c.text('ok'));

    const server = Bun.serve({ port: argPort, fetch: host.fetch });
    process.stdout.write(`HARNESS_READY ${server.port}\n`);

    // Block forever, exiting on signal.
    await new Promise<void>((resolve) => {
      process.on('SIGTERM', () => {
        server.stop();
        resolve();
      });
      process.on('SIGINT', () => {
        server.stop();
        resolve();
      });
    });
  },
  60 * 60 * 1000, // 60-minute cap
);
