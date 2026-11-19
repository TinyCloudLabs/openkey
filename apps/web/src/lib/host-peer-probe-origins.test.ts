// TC-2309: the node recognition on a host approval asks only the node the request names, never every known node
// and never a host the page does not already trust. These tests spy on fetch, so a wrong origin is a failure.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, describe, expect, test } from 'bun:test';
import type { SpaceHostFacts } from '@openkey/capability-review';
import { probeOriginsFor, watchHostPeer, type PeerRecognitionState } from './host-peer-recognition';

const PEER = 'did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25';
const SPACE = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
const FACTS: SpaceHostFacts = { spaces: [{ spaceId: SPACE, spaceName: 'default' }], peerDid: PEER };
const NODE = 'https://node.tinycloud.xyz';
const TEE = 'https://tee.node.tinycloud.xyz';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

describe('probeOriginsFor', () => {
  test('no host: the one default node', () => {
    expect(probeOriginsFor(undefined, undefined)).toEqual([NODE]);
    expect(probeOriginsFor('', undefined)).toEqual([NODE]);
  });

  test.each([
    [NODE, NODE],
    [`${NODE}/`, NODE],
    [TEE, TEE],
    ['HTTPS://NODE.TINYCLOUD.XYZ', NODE],
    ['https://Tee.Node.TinyCloud.xyz/', TEE],
  ])('a known origin (%s) probes only that origin', (host: string, expected: string) => {
    expect(probeOriginsFor(host, undefined)).toEqual([expected]);
  });

  test('a configured extra origin is trusted like a built-in one, and only that one is probed', () => {
    expect(probeOriginsFor('https://node.example', 'https://node.example')).toEqual(['https://node.example']);
    expect(probeOriginsFor('https://node.example', undefined)).toEqual([]);
    expect(probeOriginsFor(NODE, 'https://node.example')).toEqual([NODE]);
  });

  test.each([
    ['loopback http', 'http://127.0.0.1:8000'],
    ['loopback localhost', 'http://localhost:8000'],
    ['loopback https', 'https://localhost'],
    ['ipv6 loopback', 'http://[::1]:8000'],
    ['an unknown https host', 'https://node.example'],
    ['a look-alike suffix', 'https://node.tinycloud.xyz.evil.example'],
    ['a look-alike prefix', 'https://evilnode.tinycloud.xyz'],
    ['a look-alike with userinfo', 'https://node.tinycloud.xyz@evil.example'],
    ['userinfo naming a known host', 'https://user:pw@node.tinycloud.xyz'],
    ['a known host on another port', 'https://node.tinycloud.xyz:8443'],
    ['a known host over http', 'http://node.tinycloud.xyz'],
    ['a known host with a path', 'https://node.tinycloud.xyz/peer'],
    ['a known host with a query', 'https://node.tinycloud.xyz?x=1'],
    ['a known host with a fragment', 'https://node.tinycloud.xyz#x'],
    ['two trailing slashes', 'https://node.tinycloud.xyz//'],
    ['a backslash variant', 'https://node.tinycloud.xyz\\@evil.example'],
    ['a protocol-relative url', '//node.tinycloud.xyz'],
    ['a bare hostname', 'node.tinycloud.xyz'],
    ['a javascript url', 'javascript:alert(1)'],
    ['a data url', 'data:text/plain,node.tinycloud.xyz'],
    ['surrounding spaces', ' https://node.tinycloud.xyz '],
    ['an embedded newline', 'https://node.tinycloud.xyz\n'],
    ['a Cyrillic look-alike', 'https://n\u043ede.tinycloud.xyz'],
    ['an encoded dot', 'https://node%2Etinycloud.xyz'],
    ['garbage', ':::'],
  ])('%s makes no probe at all', (_label: string, host: string) => {
    expect(probeOriginsFor(host, undefined)).toEqual([]);
  });

  test('a non-ASCII look-alike never matches after lowercasing (Kelvin sign is not k)', () => {
    expect(probeOriginsFor('https://kelvin.example', 'https://kelvin.example')).toEqual(['https://kelvin.example']);
    expect(probeOriginsFor('https://\u212aelvin.example', 'https://kelvin.example')).toEqual([]);
  });

  test('a host that is not text names nothing it may probe', () => {
    expect(probeOriginsFor(42 as never, undefined)).toEqual([]);
    expect(probeOriginsFor({} as never, undefined)).toEqual([]);
    expect(probeOriginsFor(null as never, undefined)).toEqual([NODE]);
  });
});

describe('watchHostPeer with the request\'s host', () => {
  const settle = async () => { for (let turn = 0; turn < 30; turn += 1) await Promise.resolve(); };
  function spy(answer: () => Response = () => new Response(PEER, { status: 200 })) {
    const urls: string[] = [];
    globalThis.fetch = (async (url: string) => { urls.push(url); return answer(); }) as unknown as typeof fetch;
    return urls;
  }
  function collect() {
    const states: Array<PeerRecognitionState | null> = [];
    return { states, report: (next: PeerRecognitionState | null) => states.push(next) };
  }
  const peerUrl = (origin: string) => `${origin}/peer/generate/${encodeURIComponent(SPACE)}`;

  test('no host asks only the default node, and a match is known', async () => {
    const urls = spy();
    const { states, report } = collect();
    watchHostPeer(FACTS, undefined, report);
    await settle();
    expect(urls).toEqual([peerUrl(NODE)]);
    expect(states).toEqual([{ state: 'checking' }, { state: 'known', origin: NODE }]);
  });

  test('a named known origin is the only one asked', async () => {
    const urls = spy();
    const { states, report } = collect();
    watchHostPeer(FACTS, undefined, report, TEE);
    await settle();
    expect(urls).toEqual([peerUrl(TEE)]);
    expect(states.at(-1)).toEqual({ state: 'known', origin: TEE });
  });

  test.each([
    'http://127.0.0.1:8000',
    'http://localhost:9000',
    'https://node.example',
    'https://node.tinycloud.xyz.evil.example',
    'https://node.tinycloud.xyz@evil.example',
  ])('%s: no fetch at all and the label is other at once', async (host: string) => {
    const urls = spy();
    const { states, report } = collect();
    watchHostPeer(FACTS, undefined, report, host);
    expect(states).toEqual([{ state: 'other' }]);
    await settle();
    expect(urls).toEqual([]);
    expect(states).toEqual([{ state: 'other' }]);
  });

  test('another key from the named node is other; a failing node is other', async () => {
    spy(() => new Response('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH', { status: 200 }));
    const first = collect();
    watchHostPeer(FACTS, undefined, first.report, TEE);
    await settle();
    expect(first.states.at(-1)).toEqual({ state: 'other' });
    spy(() => { throw new TypeError('Failed to fetch'); });
    const second = collect();
    watchHostPeer(FACTS, undefined, second.report, NODE);
    await settle();
    expect(second.states.at(-1)).toEqual({ state: 'other' });
  });

  test('a request with no node key still reports nothing to check, host or not', () => {
    const { states, report } = collect();
    watchHostPeer({ ...FACTS, peerDid: null }, undefined, report, NODE);
    watchHostPeer(null, undefined, report, 'http://127.0.0.1:8000');
    expect(states).toEqual([null, null]);
  });
});
