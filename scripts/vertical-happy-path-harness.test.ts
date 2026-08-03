// Vertical happy-path harness — extends `authorize-sign-harness.test.ts` with
// the `keysRouter` mount and CORS so a real Playwright-driven vite widget can
// call the harness end to end and prove that the byte-for-byte "Approve exact
// bytes" pane matches what `signInWithOpenKey` ultimately consumes.
//
// Same runtime shape as authorize-sign-harness: standalone `bun test` process
// that boots a Hono host on a real HTTP port and blocks until SIGTERM. Guarded
// by `OPENKEY_RUN_HARNESS=1` and excluded from broad `bun test` walks via
// `bunfig.toml`.
//
// The differences from `authorize-sign-harness.test.ts`:
//   1. Also mounts `keysRouter` at `/api/keys` — the widget (`/widget/embed/sign`)
//      calls `api.getKey(keyId)` after the request lands, which hits
//      GET `/api/keys/:keyId`.
//   2. Fixes the `prisma.ethereumKey.findFirst` mock guard so `where.archivedAt`
//      being `undefined` (as `keysRouter.get('/:keyId')` sends it — it does not
//      pass an `archivedAt` filter) does NOT falsely reject the query.
//   3. Emits every key field the keysRouter response selects (id, userId,
//      address, keyType, keyPurpose, publicKey, keyIndex, label, archivedAt,
//      sealedBlob, sealingContext, createdAt) so both `/api/keys/:keyId` and
//      the delegate signing path find a fully-shaped record.
//   4. Adds a stub `GET /api/auth/get-session` returning `{ session: null,
//      user: null }` so better-auth's client (imported by the SvelteKit widget)
//      does not blow up on a 404.
//   5. Adds permissive CORS (widget runs on http://localhost:5778, harness on
//      127.0.0.1:<port>) with credentials disabled so the bearer-token path
//      the widget uses in embed context is served correctly.
if (!process.env.OPENKEY_RUN_HARNESS) {
  // eslint-disable-next-line no-console
  console.log(
    'vertical-happy-path-harness: skipping (OPENKEY_RUN_HARNESS not set). ' +
      'This file is a standalone harness for the js-sdk vertical browser e2e test; ' +
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
  keyPurpose: 'PERSONAL',
  publicKey: address, // For Ethereum, address is derived from the public key.
  keyIndex: 0,
  label: 'Harness Key',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
  createdAt: new Date().toISOString(),
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.keyPurpose !== undefined && where.keyPurpose !== keyRecord.keyPurpose) return null;
      // Only reject when the query EXPLICITLY filters archivedAt to a non-null
      // value. `undefined` means "no filter on archivedAt", not "must equal
      // undefined" — the harness previously rejected the widget's GET which
      // omits the archivedAt filter, causing a 404 that killed the flow.
      if (where.archivedAt !== undefined && where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return [];
      if (where.keyPurpose !== undefined && where.keyPurpose !== keyRecord.keyPurpose) return [];
      if (where.archivedAt !== undefined && where.archivedAt !== null) return [];
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
  // The real `@tinycloud/sdk-core` exports many symbols; the harness only
  // reaches ones that are consumed at import-side-effect level (nothing) or
  // at request time. Stubbing every top-level named import that reachable
  // modules use avoids a "Export named X not found" SyntaxError at load
  // when the keysRouter (via tinycloud-bootstrap) statically imports them.
  activateSessionWithHost: mock(async () => ({ success: true })),
  fetchPeerId: mock(async () => 'peer_harness_stub'),
  submitHostDelegation: mock(async () => ({ success: true })),
}));

// Path is relative to this file's location (scripts/), resolving to the real
// production session middleware module. Every mount below inherits this stub.
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
  'vertical-happy-path harness — HTTP server for cross-repo browser tests (blocks until SIGTERM)',
  async () => {
    const { delegateRouter } = await import('../apps/api/src/routes/delegate');
    const { keysRouter } = await import('../apps/api/src/routes/keys');
    const { Hono } = await import('hono');
    const { cors } = await import('hono/cors');
    const host = new Hono();
    // Permissive CORS — the widget origin (http://localhost:5778) differs
    // from the harness origin (http://127.0.0.1:<port>). Bearer-token auth
    // is used in embed context so credentials:false is safe.
    host.use(
      '*',
      cors({
        origin: (origin) => origin ?? '*',
        credentials: true,
        exposeHeaders: ['set-auth-token'],
        allowHeaders: ['Content-Type', 'Authorization'],
      }),
    );
    // No response mutation middleware — production routes now emit the
    // canonical `tinycloud.<short>` service on `permissions[].service`
    // themselves. The widget's `validatePreviewSelection` succeeds against
    // the real, unmodified route output.
    host.route('/api/delegate', delegateRouter);
    host.route('/api/keys', keysRouter);
    // Stub the better-auth get-session endpoint the SvelteKit widget hits on
    // load — a 404 here makes the SDK spin. Returning null explicitly matches
    // the "not signed in via cookie" branch the widget's `authClient.useSession()`
    // handles by falling through to embed-token authentication.
    host.get('/api/auth/get-session', (c) => c.json({ session: null, user: null }));
    host.get('/__harness/ping', (c) => c.text('ok'));

    const server = Bun.serve({ port: argPort, fetch: host.fetch });
    process.stdout.write(`HARNESS_READY ${server.port}\n`);

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
  60 * 60 * 1000,
);
