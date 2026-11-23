// TC-4082: `/api/keys/:keyId/sign` hands the bootstrap an owner-location hook only for a first-party origin that sent
// `publishOwnerLocation: true` (the shipped `required` consent). The hook runs after the sign, in the background:
// registry reads without the key, then the owner's signature over the canonical v1 record, then one create-only PUT.

import './tc1777-test-env';
import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { verifyLocationRecord } from '@tinycloud/sdk-core';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';
import { createRouteConsent } from './owner-location-route-consent';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const DEFAULT_NODE = 'https://node.tinycloud.xyz';
const NOT_FOUND = '{"error":"location record not found"}';
const FIRST_PARTY = 'https://home.tinycloud.xyz';

const unseal = mock(async () => privateKey);
let hooks: Array<((event: { host: string; chainId: number }) => void) | undefined> = [];
/** What the bootstrap reports: the host it completed the account on. */
let completedHost = DEFAULT_NODE;
const ensureTinyCloudBootstrapForApprovedSign = mock(async (input: { onFreshlyComplete?: (event: { host: string; chainId: number }) => void }) => {
  hooks.push(input.onFreshlyComplete);
  input.onFreshlyComplete?.({ host: completedHost, chainId: 1 });
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
    unseal,
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          events.push(args.message.startsWith('{') ? 'sign record' : 'sign');
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign }),
});

interface RegistryCall { method: string; url: string; body?: string }
let registryCalls: RegistryCall[] = [];
/** Resolves when the publish logs its outcome: the awaited signal, not a guessed delay. */
let registryDone: Promise<void>;
let finish: () => void;
let gate: Promise<void> | undefined;
const originalFetch = globalThis.fetch;
const originalWrite = process.stdout.write;
const logLines: string[] = [];

type RegistryReply = (call: RegistryCall) => Response | Error;
let reply: RegistryReply;

beforeEach(() => {
  events = [];
  hooks = [];
  completedHost = DEFAULT_NODE;
  registryCalls = [];
  gate = undefined;
  logLines.length = 0;
  ({ promise: registryDone, resolve: finish } = Promise.withResolvers<void>());
  reply = (call) => (call.method === 'PUT' ? new Response('{}', { status: 201 }) : new Response(NOT_FOUND, { status: 404 }));
  unseal.mockClear();
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const call = { method: init.method ?? 'GET', url: String(input), body: init.body === undefined ? undefined : String(init.body) };
    registryCalls.push(call);
    events.push(`${call.method} ${call.url.includes('/v2/') ? 'v2' : 'v1'}`);
    await gate;
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
  const { keysRouter } = await import('../routes/keys?keys-sign-owner-location' as string);
  const assertion = body.publishOwnerLocation === true && !('ownerLocationPasskeyAssertion' in body)
    ? await consent.assertionFor(keysRouter, 'key_1', body.requestOrigin as string | undefined)
    : {};
  return keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message: 'Sign in to Example', ...assertion, ...body }),
  });
}

describe('which sign requests get the hook', () => {
  test('a first-party origin that asks to publish gets it', async () => {
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });

    expect(res.status).toBe(200);
    expect(hooks.map((hook) => typeof hook)).toEqual(['function']);
  });

  test('required consent: a first-party origin without the field gets none, and nothing reaches the registry', async () => {
    for (const body of [{}, { publishOwnerLocation: false }, { publishOwnerLocation: 'true' }, { publishOwnerLocation: 1 }]) {
      const res = await sign({ requestOrigin: FIRST_PARTY, ...body });
      expect(res.status).toBe(200);
    }

    expect(hooks).toEqual([undefined, undefined, undefined, undefined]);
    expect(registryCalls).toEqual([]);
  });

  test('a third-party or unattributed origin gets none, even with the field', async () => {
    for (const requestOrigin of ['https://app.example.test', 'https://home.tinycloud.xyz.evil.example', 'http://home.tinycloud.xyz', undefined]) {
      const res = await sign({ ...(requestOrigin ? { requestOrigin } : {}), publishOwnerLocation: true });
      expect(res.status).toBe(200);
    }

    expect(hooks).toEqual([undefined, undefined, undefined, undefined]);
    expect(registryCalls).toEqual([]);
  });
});

describe('what the hook does', () => {
  test('answers the sign first, then reads the registry without signing, then signs the v1 record and PUTs once', async () => {
    let release: () => void;
    gate = new Promise<void>((resolve) => { release = resolve; });

    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    const body = (await res.json()) as { signature: string };

    // The response is back while the first registry read is still waiting.
    expect(res.status).toBe(200);
    expect(body.signature).toMatch(/^0x/);
    expect(events).toEqual(['GET v2', 'sign']);
    release!();
    await registryDone;

    // The owner's key signs the record only after both registry reads, then the PUT follows.
    expect(events).toEqual(['GET v2', 'sign', 'GET v1', 'sign record', 'PUT v1']);
    const put = registryCalls.find((call) => call.method === 'PUT')!;
    const record = JSON.parse(put.body!);
    expect(record).toMatchObject({
      version: 1,
      subject: `did:pkh:eip155:1:${address}`,
      multiaddrs: ['/dns/node.tinycloud.xyz/tcp/443/tls/http'],
      sequence: 0,
    });
    expect(await verifyLocationRecord(record)).toBe(true);
    expect(registryCalls.filter((call) => call.method === 'PUT')).toHaveLength(1);
  });

  test('a run on any host but the default node publishes nothing', async () => {
    completedHost = 'https://tee.node.tinycloud.xyz';
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    await registryDone;

    expect(res.status).toBe(200);
    expect(registryCalls).toEqual([]);
    expect(JSON.parse(logLines.join('').trim().split('\n').pop()!)).toMatchObject({ outcome: 'skipped_not_default_node' });
  });

  test('an existing record, an unreadable registry or a refused PUT leaves the sign untouched and ends the publish', async () => {
    const cases: Array<[RegistryReply, string]> = [
      [() => new Response('{"record":{}}', { status: 200 }), 'skipped_registry_exists'],
      [() => new Response('{}', { status: 403 }), 'skipped_registry_unauthorized'],
      [() => new TypeError('fetch failed'), 'skipped_registry_unreachable'],
      [(call) => (call.method === 'PUT' ? new Response('{}', { status: 409 }) : new Response(NOT_FOUND, { status: 404 })), 'failed_409'],
    ];
    for (const [answer, outcome] of cases) {
      registryCalls = [];
      logLines.length = 0;
      ({ promise: registryDone, resolve: finish } = Promise.withResolvers<void>());
      reply = answer;
      const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
      await registryDone;

      expect(res.status, outcome).toBe(200);
      expect(JSON.parse(logLines.join('').trim().split('\n').pop()!), outcome).toMatchObject({ event: 'owner_location_record', outcome });
      expect(registryCalls.filter((call) => call.method === 'PUT').length, outcome).toBe(outcome === 'failed_409' ? 1 : 0);
    }
  });

  test('the log holds the outcome code only', async () => {
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true });
    const { signature } = (await res.json()) as { signature: string };
    await registryDone;

    const logged = logLines.join('');
    for (const secret of [privateKey, privateKey.slice(2), signature, address, address.toLowerCase(), 'multiaddrs']) {
      expect(logged).not.toContain(secret);
    }
  });
});
