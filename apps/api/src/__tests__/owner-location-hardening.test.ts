// TC-4082: two checks that stand between the owner's key and the network. The hosting probe signs a session that is
// positively exactly `tinycloud.kv/list` on the account space (and its test seam is locked outside tests), and the
// signed v1 record is verified locally, by the SDK's own verifier, before the PUT.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { ensureOwnerLocationRecord } from '../services/owner-location-record';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const stranger = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');
const address = account.address;
const ACCOUNT_SPACE = `tinycloud:pkh:eip155:1:${address}:account`;
const DEFAULT_NODE = 'https://node.tinycloud.xyz';
const NOT_FOUND = '{"error":"location record not found"}';

let probeAccountSpaceHosted: (input: {
  address: string;
  chainId: number;
  tinycloudHost: string;
  signMessage: (message: string) => Promise<string>;
}) => Promise<boolean>;
let setHostingProbeAbilitiesForTests: (abilities?: Record<string, Record<string, string[]>>) => void;
let requests: string[] = [];
let signed: string[] = [];
const originalFetch = globalThis.fetch;
const originalNodeEnv = process.env.NODE_ENV;

beforeEach(async () => {
  ({ probeAccountSpaceHosted, setHostingProbeAbilitiesForTests } = await import(
    '../services/tinycloud-bootstrap.ts?owner-location-hardening' as string
  ));
  requests = [];
  signed = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    requests.push(`${init.method ?? 'GET'} ${String(input)}`);
    return String(input).endsWith('/delegate')
      ? new Response(JSON.stringify({ activated: [ACCOUNT_SPACE], skipped: [] }), { status: 200 })
      : new Response('[]', { status: 200 });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  process.env.NODE_ENV = originalNodeEnv;
  setHostingProbeAbilitiesForTests();
});

const probe = () => probeAccountSpaceHosted({
  address,
  chainId: 1,
  tinycloudHost: DEFAULT_NODE,
  signMessage: async (message) => {
    signed.push(message);
    return account.signMessage({ message });
  },
});

describe('the probe signs exactly one ability, positively', () => {
  const widened: Array<[string, Record<string, Record<string, string[]>>]> = [
    ['another kv action', { kv: { '': ['tinycloud.kv/get'] } }],
    ['kv/list and another kv action', { kv: { '': ['tinycloud.kv/list', 'tinycloud.kv/get'] } }],
    ['kv/list on a second path', { kv: { '': ['tinycloud.kv/list'], 'vault/': ['tinycloud.kv/list'] } }],
    ['kv/list on a path other than the root', { kv: { 'vault/': ['tinycloud.kv/list'] } }],
    ['kv/list and a second service', { kv: { '': ['tinycloud.kv/list'] }, capabilities: { '': ['tinycloud.capabilities/read'] } }],
    ['a different service', { capabilities: { '': ['tinycloud.capabilities/read'] } }],
    ['nothing at all', {}],
  ];
  for (const [name, abilities] of widened) {
    test(`${name} is refused before the owner signs: no signature, no request`, async () => {
      setHostingProbeAbilitiesForTests(abilities);

      expect(await probe()).toBe(false);
      expect(signed).toEqual([]);
      expect(requests).toEqual([]);
    });
  }

  test('the shipped session passes: one signature, one /delegate, one /invoke', async () => {
    expect(await probe()).toBe(true);
    expect(signed).toHaveLength(1);
    expect(requests).toEqual([`POST ${DEFAULT_NODE}/delegate`, `POST ${DEFAULT_NODE}/invoke`]);
  });
});

describe('the test seam is locked outside tests', () => {
  test('it throws unless NODE_ENV is test, and changes nothing', async () => {
    for (const mode of ['production', 'development', undefined]) {
      if (mode === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = mode;
      expect(() => setHostingProbeAbilitiesForTests({ kv: { '': ['tinycloud.kv/get'] } })).toThrow('tests only');
      expect(() => setHostingProbeAbilitiesForTests()).toThrow('tests only');
    }
    process.env.NODE_ENV = 'test';

    expect(await probe()).toBe(true);
  });
});

describe('the signed record is verified locally before the PUT', () => {
  const put = (log: string[]) => log.filter((entry) => entry.startsWith('PUT '));
  const publish = (signMessage: (message: string) => Promise<string>) => ensureOwnerLocationRecord({
    address,
    hostedHost: DEFAULT_NODE,
    signMessage,
    fetchImpl: (async (input: RequestInfo | URL, init: RequestInit = {}) => {
      requests.push(`${init.method ?? 'GET'} ${String(input)}`);
      return init.method === 'PUT' ? new Response('{}', { status: 201 }) : new Response(NOT_FOUND, { status: 404 });
    }) as typeof fetch,
  });

  test('a record signed by the owner verifies and is sent', async () => {
    expect(await publish((message) => account.signMessage({ message }))).toBe('published');
    expect(put(requests)).toHaveLength(1);
  });

  test('a signature from any other key does not verify: skipped, nothing is sent', async () => {
    expect(await publish((message) => stranger.signMessage({ message }))).toBe('skipped_record_invalid');
    expect(put(requests)).toEqual([]);
  });

  test('a signature that is not a signature is never sent either', async () => {
    for (const signature of ['0x', '0x00', 'not a signature', `0x${'00'.repeat(65)}`]) {
      requests = [];
      const outcome = await publish(async () => signature);

      expect(['skipped_record_invalid', 'failed_error']).toContain(outcome);
      expect(put(requests)).toEqual([]);
    }
  });
});
