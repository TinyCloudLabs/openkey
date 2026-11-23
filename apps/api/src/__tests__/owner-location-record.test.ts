// TC-4082: the owner's public v1 location record. Stubbed registry; no network.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { verifyLocationRecord } from '@tinycloud/sdk-core';
import { privateKeyToAccount } from 'viem/accounts';
import {
  OWNER_LOCATION_NODE_HOST,
  OWNER_LOCATION_PUBLISH_CONSENT,
  ensureOwnerLocationRecord,
  ownerLocationPublishAllowed,
  publishOwnerLocationInBackground,
} from '../services/owner-location-record';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const eip55 = account.address;
const lowercase = eip55.toLowerCase();
const DEFAULT_NODE = 'https://node.tinycloud.xyz';
const NOT_FOUND = '{"error":"location record not found"}';
const V2_URL = `https://registry.tinycloud.xyz/v2/locations/${eip55}`;
const V1_URL = `https://registry.tinycloud.xyz/v1/locations/${encodeURIComponent(`did:pkh:eip155:1:${eip55}`)}`;

type Reply = Response | Error;
const notFound = () => new Response(NOT_FOUND, { status: 404 });

interface Call { url: string; method: string; init: RequestInit }
let calls: Call[] = [];
let order: string[] = [];

/** A fetch that answers by URL and method, and records every call. */
function stubFetch(replies: { v2?: Reply; v1?: Reply; put?: Reply }): typeof fetch {
  return (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    calls.push({ url, method, init });
    order.push(`${method} ${url === V2_URL ? 'v2' : url === V1_URL ? 'v1' : url}`);
    const reply = method === 'PUT' ? replies.put : url === V2_URL ? replies.v2 : url === V1_URL ? replies.v1 : undefined;
    if (reply === undefined) throw new Error(`unexpected request ${method} ${url}`);
    if (reply instanceof Error) throw reply;
    return reply;
  }) as typeof fetch;
}

async function signMessage(message: string): Promise<string> {
  order.push('sign');
  return account.signMessage({ message });
}

function run(replies: Parameters<typeof stubFetch>[0], overrides: Partial<Parameters<typeof ensureOwnerLocationRecord>[0]> = {}) {
  return ensureOwnerLocationRecord({
    address: lowercase,
    hostedHost: DEFAULT_NODE,
    signMessage,
    fetchImpl: stubFetch(replies),
    now: () => new Date('2026-11-23T12:00:00.000Z'),
    ...overrides,
  });
}

const puts = () => calls.filter((call) => call.method === 'PUT');

beforeEach(() => {
  calls = [];
  order = [];
});

describe('the record', () => {
  test('is a v1 sequence-0 record for the EIP-55 did:pkh chain-1 subject, from a lower-case address, signed by the owner', async () => {
    const outcome = await run({ v2: notFound(), v1: notFound(), put: new Response('{}', { status: 201 }) });

    expect(outcome).toBe('published');
    expect(puts()).toHaveLength(1);
    const put = puts()[0]!;
    expect(put.url).toBe(V1_URL);
    const record = JSON.parse(String(put.init.body));
    expect(Object.keys(record).sort()).toEqual(['multiaddrs', 'sequence', 'signature', 'subject', 'updated_at', 'version']);
    expect(record).toMatchObject({
      version: 1,
      subject: `did:pkh:eip155:1:${eip55}`,
      multiaddrs: ['/dns/node.tinycloud.xyz/tcp/443/tls/http'],
      updated_at: '2026-11-23T12:00:00.000Z',
      sequence: 0,
    });
    expect(record.subject).toBe(`did:pkh:eip155:1:${eip55}`);
    expect(record.subject).not.toContain(lowercase);
    expect(await verifyLocationRecord(record)).toBe(true);
  });

  test('names exactly the SDK default node literal, whatever host the bootstrap used', async () => {
    expect(OWNER_LOCATION_NODE_HOST).toBe('https://node.tinycloud.xyz');

    for (const hostedHost of [
      'https://tee.node.tinycloud.xyz',
      'https://node.tinycloud.xyz/',
      'https://NODE.tinycloud.xyz',
      'http://node.tinycloud.xyz',
      'https://evil.example',
      '',
    ]) {
      calls = [];
      order = [];
      expect(await run({}, { hostedHost })).toBe('skipped_not_default_node');
      expect(calls).toEqual([]);
      expect(order).toEqual([]);
    }
  });

  test('uses the default registry, reads v2 then v1 before the key signs, and fails closed on redirects and slow answers', async () => {
    await run({ v2: notFound(), v1: notFound(), put: new Response('{}', { status: 200 }) });

    expect(order).toEqual(['GET v2', 'GET v1', 'sign', 'PUT v1']);
    for (const call of calls) {
      expect(call.url.startsWith('https://registry.tinycloud.xyz/')).toBe(true);
      expect(call.init.redirect).toBe('error');
      expect(call.init.signal).toBeInstanceOf(AbortSignal);
    }
  });

  test('signs the canonical payload text once', async () => {
    const signed: string[] = [];
    await run(
      { v2: notFound(), v1: notFound(), put: new Response('{}', { status: 201 }) },
      { signMessage: async (message) => { signed.push(message); return account.signMessage({ message }); } },
    );

    expect(signed).toEqual([
      JSON.stringify({
        version: 1,
        subject: `did:pkh:eip155:1:${eip55}`,
        multiaddrs: ['/dns/node.tinycloud.xyz/tcp/443/tls/http'],
        updated_at: '2026-11-23T12:00:00.000Z',
        sequence: 0,
      }),
    ]);
  });

  test('an invalid address publishes nothing', async () => {
    expect(await run({}, { address: '0x1234' })).toBe('failed_error');
    expect(calls).toEqual([]);
  });
});

describe('only a canonical 404 on both the v2 key and the v1 subject lets it publish', () => {
  // Each case builds its Response afresh: a body can be read once.
  const skipsV2: Array<[string, () => Reply, string]> = [
    ['200', () => new Response('{"record":{}}', { status: 200 }), 'skipped_registry_exists'],
    ['401', () => new Response('{}', { status: 401 }), 'skipped_registry_unauthorized'],
    ['403', () => new Response('{}', { status: 403 }), 'skipped_registry_unauthorized'],
    ['500', () => new Response('{}', { status: 500 }), 'skipped_registry_unexpected'],
    ['503', () => new Response('{}', { status: 503 }), 'skipped_registry_unexpected'],
    ['429', () => new Response('{}', { status: 429 }), 'skipped_registry_unexpected'],
    ['404 with another body', () => new Response('not found', { status: 404 }), 'skipped_registry_unexpected'],
    ['404 with an empty body', () => new Response('', { status: 404 }), 'skipped_registry_unexpected'],
    ['404 with an extra field', () => new Response('{"error":"location record not found","x":1}', { status: 404 }), 'skipped_registry_unexpected'],
    ['404 with an oversize body', () => new Response(' '.repeat(70 * 1024) + NOT_FOUND, { status: 404 }), 'skipped_registry_unexpected'],
    ['a timeout', () => new DOMException('timed out', 'TimeoutError'), 'skipped_registry_unreachable'],
    ['a network error', () => new TypeError('fetch failed'), 'skipped_registry_unreachable'],
  ];

  for (const [name, reply, code] of skipsV2) {
    test(`v2 ${name} skips: no v1 read, no signature, no PUT`, async () => {
      expect(await run({ v2: reply() })).toBe(code);
      expect(order).toEqual(['GET v2']);
    });

    test(`v1 ${name} skips after a v2 404: no signature, no PUT`, async () => {
      expect(await run({ v2: notFound(), v1: reply() })).toBe(code);
      expect(order).toEqual(['GET v2', 'GET v1']);
    });
  }

  test('a 404 whose body has surrounding whitespace is still canonical', async () => {
    const outcome = await run({
      v2: new Response(`\n${NOT_FOUND}\n`, { status: 404 }),
      v1: new Response(` ${NOT_FOUND}`, { status: 404 }),
      put: new Response('{}', { status: 201 }),
    });
    expect(outcome).toBe('published');
  });
});

describe('create-only', () => {
  for (const status of [400, 401, 403, 404, 409, 422, 500, 502, 503]) {
    test(`a ${status} on the PUT is final: one PUT, no retry, no re-read`, async () => {
      const outcome = await run({ v2: notFound(), v1: notFound(), put: new Response('{}', { status }) });

      expect(outcome).toBe(`failed_${status}`);
      expect(order).toEqual(['GET v2', 'GET v1', 'sign', 'PUT v1']);
      expect(puts()).toHaveLength(1);
    });
  }

  test('a PUT that throws is final too', async () => {
    const outcome = await run({ v2: notFound(), v1: notFound(), put: new TypeError('fetch failed') });

    expect(outcome).toBe('failed_error');
    expect(order).toEqual(['GET v2', 'GET v1', 'sign', 'PUT v1']);
  });

  test('a signing failure publishes nothing and does not throw', async () => {
    const outcome = await run(
      { v2: notFound(), v1: notFound() },
      { signMessage: async () => { throw new Error('boom'); } },
    );

    expect(outcome).toBe('failed_error');
    expect(puts()).toEqual([]);
  });

  for (const status of [200, 201, 204]) {
    test(`a ${status} on the PUT is published`, async () => {
      const reply = status === 204 ? new Response(null, { status }) : new Response('{}', { status });
      expect(await run({ v2: notFound(), v1: notFound(), put: reply })).toBe('published');
    });
  }
});

describe('logging', () => {
  const lines: string[] = [];
  const originalWrite = process.stdout.write;
  // Resolves when the code under test writes its outcome line: the awaited signal, not a guessed delay.
  let logged: Promise<void>;
  let resolve: () => void;
  beforeEach(() => {
    lines.length = 0;
    ({ promise: logged, resolve } = Promise.withResolvers<void>());
    process.stdout.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      if (String(chunk).includes('owner_location_record')) resolve();
      return true;
    }) as typeof process.stdout.write;
  });
  afterEach(() => {
    process.stdout.write = originalWrite;
  });

  const settled = () => logged;

  test('the background publish logs one short code, never the record, signature, address or key', async () => {
    let signature = '';
    publishOwnerLocationInBackground({
      address: lowercase,
      hostedHost: DEFAULT_NODE,
      signMessage: async (message) => (signature = await signMessage(message)),
      fetchImpl: stubFetch({ v2: notFound(), v1: notFound(), put: new Response('{}', { status: 409 }) }),
    });
    await settled();

    const logged = lines.join('');
    expect(JSON.parse(lines[0]!)).toMatchObject({ event: 'owner_location_record', level: 'info', outcome: 'failed_409' });
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/);
    for (const secret of [signature, privateKey, privateKey.slice(2), eip55, lowercase, 'multiaddrs', 'tinycloud.xyz']) {
      expect(logged).not.toContain(secret);
    }
  });

  test('a skip logs its code', async () => {
    publishOwnerLocationInBackground({
      address: lowercase,
      hostedHost: 'https://tee.node.tinycloud.xyz',
      signMessage,
      fetchImpl: stubFetch({}),
    });
    await settled();

    expect(JSON.parse(lines[0]!)).toMatchObject({ event: 'owner_location_record', outcome: 'skipped_not_default_node' });
  });

  test('a signer that throws never rejects the background publish', async () => {
    publishOwnerLocationInBackground({
      address: lowercase,
      hostedHost: DEFAULT_NODE,
      signMessage: async () => { throw new Error(`secret ${privateKey}`); },
      fetchImpl: stubFetch({ v2: notFound(), v1: notFound() }),
    });
    await settled();

    expect(JSON.parse(lines[0]!)).toMatchObject({ outcome: 'failed_error' });
    expect(lines.join('')).not.toContain(privateKey);
  });
});

describe('the consent switch', () => {
  const FIRST_PARTY = [
    'https://home.tinycloud.xyz',
    'https://secrets.tinycloud.xyz',
    'https://share.tinycloud.xyz',
    'https://tinycloud.one',
  ];
  const OTHERS = [
    'https://app.example.test',
    'https://evil.tinycloud.xyz',
    'https://tinycloud.xyz',
    'https://home.tinycloud.xyz/',
    'http://home.tinycloud.xyz',
    'HTTPS://HOME.TINYCLOUD.XYZ',
    '',
    undefined,
    null,
    42,
  ];
  // The origin and field checks come first: none of these requests reads the database.
  const untouched = new Proxy({}, { get: () => { throw new Error('the database must not be read'); } });
  const context = { db: untouched as never, subject: { userId: 'user_1', sessionId: 'session_1' }, keyId: 'key_1', address: eip55 };

  test('ships as required', () => {
    expect(OWNER_LOCATION_PUBLISH_CONSENT).toBe('required');
  });

  test('required: a first-party origin without the boolean true and a passkey assertion does not publish', async () => {
    for (const requestOrigin of FIRST_PARTY) {
      expect(await ownerLocationPublishAllowed({ requestOrigin, publishOwnerLocation: true }, context, 'required')).toBe(false);
      expect(await ownerLocationPublishAllowed({ requestOrigin }, context, 'required')).toBe(false);
      for (const value of [false, 'true', 1, null, {}, []]) {
        expect(await ownerLocationPublishAllowed({ requestOrigin, publishOwnerLocation: value }, context, 'required')).toBe(false);
      }
    }
  });

  test('silent: a first-party origin publishes without the field, and with it', async () => {
    for (const requestOrigin of FIRST_PARTY) {
      expect(await ownerLocationPublishAllowed({ requestOrigin }, context, 'silent')).toBe(true);
      expect(await ownerLocationPublishAllowed({ requestOrigin, publishOwnerLocation: false }, context, 'silent')).toBe(true);
      expect(await ownerLocationPublishAllowed({ requestOrigin, publishOwnerLocation: true }, context, 'silent')).toBe(true);
    }
  });

  test('a third-party or unattributed origin never publishes, in either mode, with or without the field', async () => {
    for (const requestOrigin of OTHERS) {
      for (const consent of ['required', 'silent'] as const) {
        for (const publishOwnerLocation of [true, undefined]) {
          expect(await ownerLocationPublishAllowed({ requestOrigin, publishOwnerLocation }, context, consent)).toBe(false);
        }
      }
    }
    expect(await ownerLocationPublishAllowed({}, context)).toBe(false);
    expect(await ownerLocationPublishAllowed({ publishOwnerLocation: true }, context)).toBe(false);
  });
});
