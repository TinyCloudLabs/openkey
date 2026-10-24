import { afterAll, afterEach, describe, expect, test, vi } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import {
  abbreviateDid,
  abbreviateSpaceId,
  parseCapabilityReview,
  readSpaceHostFacts,
  recognizeHostPeer,
  samePeerDid,
  type CapabilityReviewModel,
} from '@openkey/capability-review';

// These tests touch no files. HOME is still pointed at a private dir (and put
// back) so a regression cannot reach a real profile; the cleanup is registered
// before anything else runs.
const PRIOR_HOME = process.env.HOME;
const HOME = mkdtempSync(join('/var/tmp', 'tc1950.'));
afterAll(() => {
  process.env.HOME = PRIOR_HOME;
  rmSync(HOME, { recursive: true, force: true });
});
process.env.HOME = HOME;

const OWNER = '0x1111111111111111111111111111111111111111';
const OTHER_OWNER = '0x2222222222222222222222222222222222222222';
const PEER = 'did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25';
const OTHER_PEER = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const space = (name: string, owner = OWNER) => `tinycloud:pkh:eip155:1:${owner}:${name}`;
const NODE = 'https://node.tinycloud.xyz';
const TEE = 'https://tee.node.tinycloud.xyz';

function recap(att: Record<string, Record<string, unknown[]>>): string {
  return `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;
}

// The wire shape tinycloud-node's host SIWE has: no statement, no expiry, the
// node key as the URI, one ReCap entry `<space>/space -> tinycloud.space/host`.
function hostSiwe(opts: { uri?: string | string[]; spaces?: string[]; expiry?: string; abilities?: string[]; domain?: string } = {}): string {
  const spaces = opts.spaces ?? [space('default')];
  const abilities = opts.abilities ?? ['tinycloud.space/host'];
  const att = Object.fromEntries(
    spaces.map((id) => [`${id}/space`, Object.fromEntries(abilities.map((a) => [a, [{}]]))]),
  );
  const uris = Array.isArray(opts.uri) ? opts.uri : [opts.uri ?? PEER];
  const domain = opts.domain ?? 'app.example';
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    OWNER,
    '',
    ...uris.map((uri) => `URI: ${uri}`),
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    'Issued At: 2026-10-24T00:00:00.000Z',
    ...(opts.expiry ? [`Expiration Time: ${opts.expiry}`] : []),
    'Resources:',
    `- ${recap(att)}`,
  ].join('\n');
}

function review(message: string, editable = false): CapabilityReviewModel {
  return parseCapabilityReview({
    message,
    signer: { label: 'Selected key', address: OWNER, chainId: 1, provenance: 'managed' },
    editable,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'app.example',
      verifiedOrigin: 'https://app.example',
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
}

describe('readSpaceHostFacts', () => {
  test('home is the private dir', () => {
    expect(process.env.HOME).toBe(HOME);
  });

  test('reads the space and the node key of a host SIWE', () => {
    const facts = readSpaceHostFacts(review(hostSiwe()));
    expect(facts).toEqual({
      spaces: [{ spaceId: space('default'), spaceName: 'default' }],
      peerDid: PEER,
    });
  });

  test('a `#fragment` on the node key is kept as written', () => {
    const facts = readSpaceHostFacts(review(hostSiwe({ uri: `${PEER}#z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25` })));
    expect(facts?.peerDid).toBe(`${PEER}#z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25`);
  });

  test('a request that does not ask to host a space has no facts', () => {
    expect(readSpaceHostFacts(review(hostSiwe({ abilities: ['tinycloud.kv/get'] })))).toBeNull();
    expect(readSpaceHostFacts(review(hostSiwe({ abilities: ['tinycloud.space/info'] })))).toBeNull();
    expect(readSpaceHostFacts(review('not a sign-in message'))).toBeNull();
  });

  test("another owner's space has no facts", () => {
    expect(readSpaceHostFacts(review(hostSiwe({ spaces: [space('default', OTHER_OWNER)] })))).toBeNull();
  });

  test('a URI that is not exactly one node key gives no node key but keeps the space', () => {
    for (const uri of ['https://app.example/', 'did:web:example.com', 'did:key:abc', 'did:key:z6Mk bad']) {
      expect(readSpaceHostFacts(review(hostSiwe({ uri })))?.peerDid).toBeNull();
    }
    const twice = readSpaceHostFacts(review(hostSiwe({ uri: [PEER, OTHER_PEER] })));
    expect(twice?.peerDid).toBeNull();
    expect(twice?.spaces).toHaveLength(1);
  });

  test('a time-limited SIWE is read the same way (the key may then be a session key)', () => {
    const facts = readSpaceHostFacts(review(hostSiwe({ expiry: '2026-10-31T00:00:00.000Z' }), true));
    expect(facts?.peerDid).toBe(PEER);
  });

  test('only selected host actions count', () => {
    const model = review(hostSiwe(), true);
    expect(readSpaceHostFacts(model, new Set())).toBeNull();
    const ids = new Set(model.permissions.flatMap((grant) => grant.actions.map((action) => action.id)));
    expect(readSpaceHostFacts(model, ids)?.spaces).toHaveLength(1);
  });

  test('lists every hosted space', () => {
    const facts = readSpaceHostFacts(review(hostSiwe({ spaces: [space('default'), space('notes')] })));
    expect(facts?.spaces.map((s) => s.spaceName).sort()).toEqual(['default', 'notes']);
  });

  test('a space name outside the plain charset has no short name', () => {
    const facts = readSpaceHostFacts(review(hostSiwe({ spaces: [space('My.Space_1')] })));
    expect(facts?.spaces[0]).toEqual({ spaceId: space('My.Space_1'), spaceName: null });
  });

  test('reads the bytes that are signed, not the original request', () => {
    const model = review(hostSiwe());
    const swapped = { ...model, rawMessage: hostSiwe({ uri: OTHER_PEER }) };
    expect(readSpaceHostFacts(swapped)?.peerDid).toBe(OTHER_PEER);
  });
});

describe('display helpers', () => {
  test('abbreviateSpaceId keeps the prefix and the name', () => {
    expect(abbreviateSpaceId(space('default'))).toBe('tinycloud:pkh:eip155:1:0x1111…1111:default');
    expect(abbreviateSpaceId('not-a-space')).toBe('not-a-space');
  });

  test('abbreviateDid keeps the head and drops a fragment', () => {
    expect(abbreviateDid(`${PEER}#frag`)).toBe('did:key:z6Mkj8Zn…rPteD25');
    expect(abbreviateDid('did:key:z6Mkshort')).toBe('did:key:z6Mkshort');
  });
});

describe('samePeerDid', () => {
  test('ignores a fragment, nothing else', () => {
    expect(samePeerDid(PEER, `${PEER}#x`)).toBe(true);
    expect(samePeerDid(`${PEER}\n`, PEER)).toBe(true);
    expect(samePeerDid(PEER, OTHER_PEER)).toBe(false);
    expect(samePeerDid(PEER, PEER.toLowerCase().replace('z6mk', 'Z6MK'))).toBe(false);
    expect(samePeerDid(PEER, PEER.slice(0, -1))).toBe(false);
    expect(samePeerDid('', '')).toBe(false);
    expect(samePeerDid('x', 'x')).toBe(false);
  });
});

describe('recognizeHostPeer', () => {
  const never = (_origin: string, _spaceId: string, signal: AbortSignal) =>
    new Promise<string | null>((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted'))));

  function run(fetchPeer: (origin: string, spaceId: string, signal: AbortSignal) => Promise<string | null>, extra: { spaces?: string[]; peerDid?: string; origins?: string[]; timeoutMs?: number } = {}) {
    return recognizeHostPeer({
      spaces: extra.spaces ?? [space('default')],
      peerDid: extra.peerDid ?? PEER,
      nodeOrigins: extra.origins ?? [NODE, TEE],
      fetchPeer,
      timeoutMs: extra.timeoutMs ?? 200,
    });
  }

  test('a configured node answering with the same key is known, reported as the configured origin', async () => {
    const calls: string[] = [];
    const result = await run(async (origin, spaceId) => {
      calls.push(`${origin} ${spaceId}`);
      return PEER;
    });
    expect(result).toEqual({ kind: 'known', origin: NODE });
    expect(calls.sort()).toEqual([`${NODE} ${space('default')}`, `${TEE} ${space('default')}`]);
  });

  test('the second configured origin can be the match', async () => {
    const result = await run(async (origin) => (origin === TEE ? PEER : OTHER_PEER));
    expect(result).toEqual({ kind: 'known', origin: TEE });
  });

  test('a different key, a refusal, an error and a non-key answer are all not confirmed', async () => {
    expect(await run(async () => OTHER_PEER)).toEqual({ kind: 'other' });
    expect(await run(async () => null)).toEqual({ kind: 'other' });
    expect(await run(async () => { throw new Error('network'); })).toEqual({ kind: 'other' });
    expect(await run(async () => '<html>nope</html>')).toEqual({ kind: 'other' });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('a node that never answers is not confirmed once the timeout passes', async () => {
    vi.useFakeTimers();
    const pending = run(never, { timeoutMs: 5_000 });
    vi.advanceTimersByTime(4_999);
    let settled = false;
    void pending.then(() => { settled = true; });
    await Promise.resolve();
    expect(settled).toBe(false);
    vi.advanceTimersByTime(1);
    expect(await pending).toEqual({ kind: 'other' });
  });

  test('the timeout aborts requests still waiting', async () => {
    vi.useFakeTimers();
    let aborted = false;
    const pending = run(
      (_origin, _space, signal) => new Promise<string | null>(() => signal.addEventListener('abort', () => { aborted = true; })),
      { timeoutMs: 5_000 },
    );
    vi.advanceTimersByTime(5_000);
    await pending;
    expect(aborted).toBe(true);
  });

  test('only the configured origins are contacted', async () => {
    const seen = new Set<string>();
    await run(async (origin) => { seen.add(origin); return null; }, { origins: [NODE] });
    expect([...seen]).toEqual([NODE]);
  });

  test('a malformed space id or node key is not confirmed and nothing is fetched', async () => {
    let calls = 0;
    const count = async () => { calls += 1; return PEER; };
    expect(await run(count, { spaces: ['default'] })).toEqual({ kind: 'other' });
    expect(await run(count, { spaces: [`${space('default')}/../x`] })).toEqual({ kind: 'other' });
    expect(await run(count, { spaces: [] })).toEqual({ kind: 'other' });
    expect(await run(count, { peerDid: 'https://node.example' })).toEqual({ kind: 'other' });
    expect(calls).toBe(0);
  });

  test('every hosted space must match the same node', async () => {
    const two = [space('default'), space('notes')];
    expect(await run(async () => PEER, { spaces: two })).toEqual({ kind: 'known', origin: NODE });
    expect(await run(async (_origin, spaceId) => (spaceId.endsWith(':notes') ? OTHER_PEER : PEER), { spaces: two })).toEqual({ kind: 'other' });
  });
});
