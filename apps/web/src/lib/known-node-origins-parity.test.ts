// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import type { SpaceHostFacts } from '@openkey/capability-review';
import { TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from '../../../api/src/services/tinycloud-hosts';
import { KNOWN_NODE_ORIGINS } from './delegate-link-policy';
import {
  fetchNodePeer,
  knownNodeOrigins,
  watchHostPeer,
  type PeerRecognitionState,
} from './host-peer-recognition';

// No files are touched. HOME is pointed at a private dir (and put back); the
// cleanup is registered first.
const PRIOR_HOME = process.env.HOME;
const HOME = mkdtempSync(join('/var/tmp', 'tc1950.'));
const realFetch = globalThis.fetch;
// A stand-in `fetch`; the real type carries fields a stub does not need.
const stubFetch = (stub: (url: string, init: RequestInit) => Promise<Response>) => {
  globalThis.fetch = stub as unknown as typeof fetch;
};
afterAll(() => {
  globalThis.fetch = realFetch;
  if (PRIOR_HOME === undefined) delete process.env.HOME;
  else process.env.HOME = PRIOR_HOME;
  rmSync(HOME, { recursive: true, force: true });
});
afterEach(() => {
  globalThis.fetch = realFetch;
});
process.env.HOME = HOME;

const PEER = 'did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25';
const SPACE = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
const FACTS: SpaceHostFacts = { spaces: [{ spaceId: SPACE, spaceName: 'default' }], peerDid: PEER };

// The API's trusted bootstrap hosts are the source. The page's known-node list
// is a copy it cannot import, so this test keeps the two from drifting.
describe('known node origins', () => {
  test('home is the private dir', () => {
    expect(process.env.HOME).toBe(HOME);
  });

  test('the page list equals the API trusted bootstrap hosts', () => {
    expect([...KNOWN_NODE_ORIGINS].sort()).toEqual([...TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS].sort());
  });

  test('the configured extras are added after the built-in list, invalid ones are dropped', () => {
    expect(knownNodeOrigins(undefined)).toEqual([...KNOWN_NODE_ORIGINS]);
    expect(knownNodeOrigins('https://node.example, http://plain.example, https://node.example/path')).toEqual([
      ...KNOWN_NODE_ORIGINS,
      'https://node.example',
    ]);
  });
});

describe('fetchNodePeer', () => {
  test('asks the node for the key for the encoded space, without credentials or redirects', async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    stubFetch(async (url, init) => {
      seen = { url, init };
      return new Response(`${PEER}\n`, { status: 200 });
    });
    const controller = new AbortController();
    expect(await fetchNodePeer('https://node.tinycloud.xyz', SPACE, controller.signal)).toBe(PEER);
    expect(seen!.url).toBe(`https://node.tinycloud.xyz/peer/generate/${encodeURIComponent(SPACE)}`);
    expect(seen!.init.credentials).toBe('omit');
    expect(seen!.init.redirect).toBe('error');
    expect(seen!.init.signal).toBe(controller.signal);
  });

  test('a non-200 or an oversized answer is no key', async () => {
    stubFetch(async () => new Response('nope', { status: 404 }));
    expect(await fetchNodePeer('https://node.tinycloud.xyz', SPACE, new AbortController().signal)).toBeNull();
    stubFetch(async () => new Response('x'.repeat(5_000), { status: 200 }));
    expect(await fetchNodePeer('https://node.tinycloud.xyz', SPACE, new AbortController().signal)).toBeNull();
  });
});

describe('watchHostPeer', () => {
  function collect() {
    const states: Array<PeerRecognitionState | null> = [];
    return { states, report: (next: PeerRecognitionState | null) => states.push(next) };
  }
  // Let the already-resolved stub answers flow through the promise chain.
  const settle = async () => {
    for (let turn = 0; turn < 20; turn += 1) await Promise.resolve();
  };

  test('checking, then known with the configured origin that matched', async () => {
    stubFetch(async () => new Response(PEER, { status: 200 }));
    const { states, report } = collect();
    watchHostPeer(FACTS, undefined, report);
    expect(states).toEqual([{ state: 'checking' }]);
    await settle();
    expect(states).toEqual([{ state: 'checking' }, { state: 'known', origin: KNOWN_NODE_ORIGINS[0]! }]);
  });

  test('another key, or a failing node, is other', async () => {
    stubFetch(async () => new Response('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH', { status: 200 }));
    const first = collect();
    watchHostPeer(FACTS, undefined, first.report);
    await settle();
    expect(first.states.at(-1)).toEqual({ state: 'other' });

    stubFetch(async () => {
      throw new TypeError('Failed to fetch');
    });
    const second = collect();
    watchHostPeer(FACTS, undefined, second.report);
    await settle();
    expect(second.states.at(-1)).toEqual({ state: 'other' });
  });

  test('a request with no node key reports nothing to check', () => {
    const { states, report } = collect();
    watchHostPeer({ ...FACTS, peerDid: null }, undefined, report);
    watchHostPeer(null, undefined, report);
    expect(states).toEqual([null, null]);
  });

  test('cleanup drops a late answer', async () => {
    stubFetch(async () => new Response(PEER, { status: 200 }));
    const { states, report } = collect();
    const stop = watchHostPeer(FACTS, undefined, report);
    stop();
    await settle();
    expect(states).toEqual([{ state: 'checking' }]);
  });
});
