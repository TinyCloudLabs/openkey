// TC-4082: `probeAccountSpaceHosted`, the fresh hosting proof for an account whose bootstrap row is already `complete`.
// One `/delegate` for a short session that can only list the account space, one `/invoke` of `tinycloud.kv/list`.
// Stubbed node; nothing is sent anywhere.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { parseTinyCloudSiwe } from '../services/tinycloud-siwe';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const ACCOUNT_SPACE = `tinycloud:pkh:eip155:1:${address}:account`;
const DEFAULT_NODE = 'https://node.tinycloud.xyz';

let probeAccountSpaceHosted: (input: {
  address: string;
  chainId: number;
  tinycloudHost: string;
  signMessage: (message: string) => Promise<string>;
}) => Promise<boolean>;
let setHostingProbeAbilitiesForTests: (abilities?: Record<string, Record<string, string[]>>) => void;

interface NodeCall { url: string; method: string; headers: Record<string, string> }
type Reply = Response | Error;
let calls: NodeCall[] = [];
let signed: string[] = [];
const originalFetch = globalThis.fetch;

const delegated = () => new Response(JSON.stringify({ activated: [ACCOUNT_SPACE], skipped: [] }), { status: 200 });
const listed = () => new Response('[]', { status: 200 });

function stubNode(replies: { delegate?: () => Reply; invoke?: () => Reply }) {
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, method: init.method ?? 'GET', headers: Object.fromEntries(new Headers(init.headers).entries()) });
    const make = url.endsWith('/delegate') ? replies.delegate : url.endsWith('/invoke') ? replies.invoke : undefined;
    if (!make) throw new Error(`unexpected request ${url}`);
    const reply = make();
    if (reply instanceof Error) throw reply;
    return reply;
  }) as typeof fetch;
}

const signMessage = async (message: string) => {
  signed.push(message);
  return account.signMessage({ message });
};
const probe = (overrides: Partial<Parameters<typeof probeAccountSpaceHosted>[0]> = {}) =>
  probeAccountSpaceHosted({ address, chainId: 1, tinycloudHost: DEFAULT_NODE, signMessage, ...overrides });

beforeEach(async () => {
  ({ probeAccountSpaceHosted, setHostingProbeAbilitiesForTests } = await import(
    '../services/tinycloud-bootstrap.ts?owner-location-probe' as string
  ));
  calls = [];
  signed = [];
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  setHostingProbeAbilitiesForTests();
});

describe('what the probe sends', () => {
  test('one /delegate for a short kv/list-only session, then one /invoke of kv/list with limit 1, and nothing else', async () => {
    stubNode({ delegate: delegated, invoke: listed });

    expect(await probe()).toBe(true);

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `POST ${DEFAULT_NODE}/delegate`,
      `POST ${DEFAULT_NODE}/invoke`,
    ]);
    expect(calls[1]!.headers['x-tinycloud-limit']).toBe('1');
    // The invocation is a UCAN whose only capability is the account space's kv/list.
    const invocation = JSON.parse(Buffer.from(calls[1]!.headers.authorization!.split('.')[1]!, 'base64url').toString());
    expect(invocation.att).toEqual({ [`${ACCOUNT_SPACE}/kv/`]: { 'tinycloud.kv/list': [{}] } });
    expect(calls[1]!.headers.authorization).toBeTruthy();
    expect(calls.some((call) => call.url.includes('/peer/'))).toBe(false);

    // The owner signed exactly one message: the session, with one ability.
    expect(signed).toHaveLength(1);
    const session = parseTinyCloudSiwe(signed[0]!)!;
    expect(session.entries).toEqual([
      { service: 'kv', space: ACCOUNT_SPACE, path: '', actions: ['tinycloud.kv/list'] },
    ]);
    const lifetimeMs = session.expirationTime!.getTime() - Date.now();
    expect(lifetimeMs).toBeGreaterThan(0);
    expect(lifetimeMs).toBeLessThanOrEqual(5 * 60 * 1000);
  });
});

describe('true only on an affirmative 2xx kv/list', () => {
  for (const status of [200, 204]) {
    test(`${status} on the list is hosted`, async () => {
      stubNode({ delegate: delegated, invoke: () => new Response(status === 204 ? null : '[]', { status }) });
      expect(await probe()).toBe(true);
    });
  }

  for (const status of [301, 400, 401, 403, 404, 429, 500, 502, 503]) {
    test(`${status} on the list is not hosted`, async () => {
      stubNode({ delegate: delegated, invoke: () => new Response('{}', { status }) });
      expect(await probe()).toBe(false);
      expect(calls).toHaveLength(2);
    });
  }

  for (const status of [400, 401, 403, 404, 500, 503]) {
    test(`${status} on /delegate is not hosted and nothing is invoked`, async () => {
      stubNode({ delegate: () => new Response('{}', { status }) });
      expect(await probe()).toBe(false);
      expect(calls.map((call) => call.url)).toEqual([`${DEFAULT_NODE}/delegate`]);
    });
  }

  test('a /delegate that lists the account space as skipped is not hosted and nothing is invoked', async () => {
    stubNode({ delegate: () => new Response(JSON.stringify({ activated: [], skipped: [ACCOUNT_SPACE] }), { status: 200 }) });
    expect(await probe()).toBe(false);
    expect(calls).toHaveLength(1);
  });

  test('a /delegate answer that is not readable is unconfirmed and nothing is invoked', async () => {
    for (const body of ['not json', '']) {
      calls = [];
      stubNode({ delegate: () => new Response(body, { status: 200 }) });
      expect(await probe()).toBe(false);
      expect(calls).toHaveLength(1);
    }
  });

  test('a timeout or network error is not hosted', async () => {
    stubNode({ delegate: () => new DOMException('timed out', 'TimeoutError') });
    expect(await probe()).toBe(false);
    stubNode({ delegate: delegated, invoke: () => new TypeError('fetch failed') });
    expect(await probe()).toBe(false);
  });
});

describe('the guards, all before the owner signs', () => {
  for (const host of [
    'https://tee.node.tinycloud.xyz',
    'https://node.tinycloud.xyz/',
    'http://node.tinycloud.xyz',
    'https://evil.example',
    '',
  ]) {
    test(`host ${JSON.stringify(host)} is never probed`, async () => {
      stubNode({ delegate: delegated, invoke: listed });
      expect(await probe({ tinycloudHost: host })).toBe(false);
      expect(calls).toEqual([]);
      expect(signed).toEqual([]);
    });
  }

  const withSpaceAction: Array<[string, Record<string, Record<string, string[]>>]> = [
    ['host', { kv: { '': ['tinycloud.kv/list'] }, space: { '': ['tinycloud.space/host'] } }],
    ['create', { space: { '': ['tinycloud.space/create'] } }],
    ['info', { space: { '': ['tinycloud.space/info'] } }],
    ['a space action under another service', { kv: { '': ['tinycloud.kv/list', 'tinycloud.space/host'] } }],
    ['any other space action', { space: { '': ['tinycloud.space/list'] } }],
  ];
  for (const [name, abilities] of withSpaceAction) {
    test(`a tinycloud.space/* ability (${name}) refuses: the signer is never called and nothing is sent`, async () => {
      stubNode({ delegate: delegated, invoke: listed });
      setHostingProbeAbilitiesForTests(abilities);

      expect(await probe()).toBe(false);
      expect(signed).toEqual([]);
      expect(calls).toEqual([]);
    });
  }

  test('the shipped abilities pass the guard (the refusals above are the guard, not a broken probe)', async () => {
    stubNode({ delegate: delegated, invoke: listed });
    expect(await probe()).toBe(true);
    expect(signed).toHaveLength(1);
  });

  test('a signer that throws ends the probe before anything is sent', async () => {
    stubNode({ delegate: delegated, invoke: listed });
    expect(await probe({ signMessage: async () => { throw new Error('refused'); } })).toBe(false);
    expect(calls).toEqual([]);
  });
});
