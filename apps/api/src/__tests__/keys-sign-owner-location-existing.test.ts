// TC-4082: an account whose bootstrap row is already `complete`. `/api/keys/:keyId/sign` hands the bootstrap an
// `onAlreadyComplete` hook only for a first-party origin that sent `publishOwnerLocation: true` (the shipped
// `required` consent). The hook runs after the sign, in the background: registry reads without the key, a fresh hosting
// probe against the node (the real probe, stubbed node), and only then the owner's signature over the canonical v1
// record and one create-only PUT.

import './tc1777-test-env';
import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { verifyLocationRecord } from '@tinycloud/sdk-core';
import { privateKeyToAccount } from 'viem/accounts';
import { resetOwnerLocationMemoForTests } from '../services/owner-location-record';
import { mockModules, replaceModules } from './mock-module';
import { createRouteConsent } from './owner-location-route-consent';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const ACCOUNT_SPACE = `tinycloud:pkh:eip155:1:${address}:account`;
const user = { id: 'user_1', email: 'test@example.com' };
const DEFAULT_NODE = 'https://node.tinycloud.xyz';
const TEE_NODE = 'https://tee.node.tinycloud.xyz';
const NOT_FOUND = '{"error":"location record not found"}';
const FIRST_PARTY = 'https://home.tinycloud.xyz';

type Hooks = {
  onFreshlyComplete?: (event: { host: string; chainId: number }) => void;
  onAlreadyComplete?: (event: { host: string; chainId: number }) => void;
};
let hooks: Hooks[] = [];
/** The host the stale `complete` row is on. */
let rowHost = DEFAULT_NODE;
const ensureTinyCloudBootstrapForApprovedSign = mock(async (input: Hooks) => {
  hooks.push({ onFreshlyComplete: input.onFreshlyComplete, onAlreadyComplete: input.onAlreadyComplete });
  input.onAlreadyComplete?.({ host: rowHost, chainId: 1 });
  return { status: 'complete' as const };
});
const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', sealedBlob: 'sealed-private-key', archivedAt: null };
const consent = await createRouteConsent(user.id);
const prisma = {
  ...consent.db,
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) =>
      where.userId === user.id && where.id === keyRecord.id && where.archivedAt === null ? keyRecord : null),
  },
};
let events: string[] = [];

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    seal: mock(async () => 'sealed-private-key'),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          events.push(
            args.message.startsWith('{') ? 'sign record' : args.message === 'Sign in to Example' ? 'sign' : 'sign probe',
          );
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  // Only the sign entry point is replaced; the real `probeAccountSpaceHosted` stays.
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign }),
});

interface Call { method: string; url: string; body?: string }
let calls: Call[] = [];
type Reply = (call: Call) => Response | Error;
let reply: Reply;
/** Resolves when the publish logs its outcome: the awaited signal, not a guessed delay. */
let done: Promise<void>;
let finish: () => void;
const originalFetch = globalThis.fetch;
const originalWrite = process.stdout.write;
const logLines: string[] = [];

const nodeReply = (call: Call): Response | undefined => {
  if (call.url.endsWith('/delegate')) return new Response(JSON.stringify({ activated: [ACCOUNT_SPACE], skipped: [] }), { status: 200 });
  if (call.url.endsWith('/invoke')) return new Response('[]', { status: 200 });
  return undefined;
};
const registryReply = (call: Call): Response =>
  call.method === 'PUT' ? new Response('{}', { status: 201 }) : new Response(NOT_FOUND, { status: 404 });
const label = (call: Call) =>
  call.url.includes('/v2/') ? 'GET v2' : call.url.includes('/v1/') ? `${call.method} v1` : `${call.method} ${new URL(call.url).pathname}`;

function armSignal() {
  ({ promise: done, resolve: finish } = Promise.withResolvers<void>());
}
const lastLog = () => JSON.parse(logLines.join('').trim().split('\n').pop()!);

beforeEach(() => {
  events = [];
  hooks = [];
  rowHost = DEFAULT_NODE;
  calls = [];
  logLines.length = 0;
  armSignal();
  resetOwnerLocationMemoForTests();
  reply = (call) => nodeReply(call) ?? registryReply(call);
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const call = { method: init.method ?? 'GET', url: String(input), body: init.body === undefined ? undefined : String(init.body) };
    calls.push(call);
    events.push(label(call));
    const response = reply(call);
    if (response instanceof Error) throw response;
    return response;
  }) as typeof fetch;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    logLines.push(String(chunk));
    if (String(chunk).includes('owner_location_record')) finish();
    return true;
  }) as typeof process.stdout.write;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  process.stdout.write = originalWrite;
});

/**
 * `required` consent: a request that says `publishOwnerLocation: true` also carries the passkey assertion the page
 * would fetch from `/owner-location/passkey`, unless the test sets `ownerLocationPasskeyAssertion` itself.
 */
async function sign(body: Record<string, unknown>) {
  const { keysRouter } = await import('../routes/keys?keys-sign-owner-location-existing' as string);
  const assertion = body.publishOwnerLocation === true && !('ownerLocationPasskeyAssertion' in body)
    ? await consent.assertionFor(keysRouter, 'key_1', body.requestOrigin as string | undefined)
    : {};
  return keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message: 'Sign in to Example', ...assertion, ...body }),
  });
}

describe('which sign requests get the hook for an existing account', () => {
  test('a first-party origin that asks to publish gets it, next to the transition hook', async () => {
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    await done;

    expect(res.status).toBe(200);
    expect(hooks.map((hook) => [typeof hook.onFreshlyComplete, typeof hook.onAlreadyComplete])).toEqual([['function', 'function']]);
  });

  test('required consent: a first-party origin without the field never probes, never signs for it, never calls anything', async () => {
    for (const body of [{}, { publishOwnerLocation: false }, { publishOwnerLocation: 'true' }, { publishOwnerLocation: 1 }]) {
      const res = await sign({ requestOrigin: FIRST_PARTY, ...body });
      expect(res.status).toBe(200);
    }

    expect(hooks.every((hook) => hook.onAlreadyComplete === undefined && hook.onFreshlyComplete === undefined)).toBe(true);
    expect(calls).toEqual([]);
    expect(events.filter((event) => event !== 'sign')).toEqual([]);
  });

  test('a third-party or unattributed origin never probes, even with the field', async () => {
    for (const requestOrigin of ['https://app.example.test', 'https://home.tinycloud.xyz.evil.example', 'http://home.tinycloud.xyz', undefined]) {
      const res = await sign({ ...(requestOrigin ? { requestOrigin } : {}), publishOwnerLocation: true });
      expect(res.status).toBe(200);
    }

    expect(hooks.every((hook) => hook.onAlreadyComplete === undefined)).toBe(true);
    expect(calls).toEqual([]);
    expect(events.filter((event) => event !== 'sign')).toEqual([]);
  });
});

describe('what the hook does for an existing account', () => {
  test('registry reads, the probe, then the record and one PUT; the sign is answered first', async () => {
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    const { signature } = (await res.json()) as { signature: string };
    await done;

    expect(res.status).toBe(200);
    expect(signature).toMatch(/^0x/);
    expect(events.filter((event) => event !== 'sign')).toEqual([
      'GET v2', 'GET v1', 'sign probe', 'POST /delegate', 'POST /invoke', 'sign record', 'PUT v1',
    ]);
    expect(lastLog()).toMatchObject({ event: 'owner_location_record', outcome: 'published' });
    const record = JSON.parse(calls.find((call) => call.method === 'PUT')!.body!);
    expect(record).toMatchObject({ version: 1, subject: `did:pkh:eip155:1:${address}`, sequence: 0 });
    expect(await verifyLocationRecord(record)).toBe(true);
    expect(calls.filter((call) => call.url.endsWith('/delegate'))).toHaveLength(1);
    expect(calls.every((call) => !call.url.startsWith(TEE_NODE))).toBe(true);
  });

  test('a node that does not confirm the space leaves the sign untouched and publishes nothing', async () => {
    const cases: Array<[string, Reply]> = [
      ['404 on the list', (call) => (call.url.endsWith('/invoke') ? new Response('{}', { status: 404 }) : nodeReply(call) ?? registryReply(call))],
      ['403 on the list', (call) => (call.url.endsWith('/invoke') ? new Response('{}', { status: 403 }) : nodeReply(call) ?? registryReply(call))],
      ['500 on /delegate', (call) => (call.url.endsWith('/delegate') ? new Response('{}', { status: 500 }) : nodeReply(call) ?? registryReply(call))],
      ['offline node', (call) => (call.url.startsWith(DEFAULT_NODE) ? new TypeError('fetch failed') : registryReply(call))],
    ];
    for (const [name, answer] of cases) {
      calls = [];
      events = [];
      logLines.length = 0;
      armSignal();
      resetOwnerLocationMemoForTests();
      reply = answer;

      const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
      await done;

      expect(res.status, name).toBe(200);
      expect(lastLog(), name).toMatchObject({ outcome: 'skipped_not_hosted' });
      expect(events, name).not.toContain('sign record');
      expect(calls.filter((call) => call.method === 'PUT'), name).toEqual([]);
    }
  });

  test('a registry record on either read ends it before any probe', async () => {
    for (const exists of ['/v2/', '/v1/']) {
      calls = [];
      events = [];
      logLines.length = 0;
      armSignal();
      resetOwnerLocationMemoForTests();
      reply = (call) => (call.url.includes(exists) ? new Response('{"record":{}}', { status: 200 }) : nodeReply(call) ?? registryReply(call));

      const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
      await done;

      expect(res.status, exists).toBe(200);
      expect(lastLog(), exists).toMatchObject({ outcome: 'skipped_registry_exists' });
      expect(events.filter((event) => event.startsWith('sign ') || event.includes('/delegate') || event.includes('/invoke')), exists).toEqual([]);
    }
  });

  test('a row on any host but the default node never reaches the node', async () => {
    rowHost = TEE_NODE;
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    await done;

    expect(res.status).toBe(200);
    expect(calls).toEqual([]);
    expect(lastLog()).toMatchObject({ outcome: 'skipped_not_default_node' });
  });

  test('a busy account is looked at once per five minutes', async () => {
    await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    await done;
    const firstRound = calls.length;

    armSignal();
    await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    await done;

    expect(calls).toHaveLength(firstRound);
    expect(lastLog()).toMatchObject({ outcome: 'skipped_checked_recently' });
  });

  test('the log holds the outcome code only', async () => {
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    const { signature } = (await res.json()) as { signature: string };
    await done;

    const logged = logLines.join('');
    for (const secret of [privateKey, privateKey.slice(2), signature, address, address.toLowerCase(), ACCOUNT_SPACE, 'multiaddrs']) {
      expect(logged).not.toContain(secret);
    }
  });
});
