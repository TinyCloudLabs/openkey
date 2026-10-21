import { describe, expect, it } from 'bun:test';
import { createOrgSpaceHostDidResolver, ORG_SPACE_HOST_DID_TTL_MS } from '../services/org-space-host-did';

const DID_KEY = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const DID_PKH = 'did:pkh:eip155:1:0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const HOST = 'https://node.example';
const SPACE = 'space-a';

function harness(respond: (call: number) => Promise<string> | string) {
  let clock = 1_000_000;
  let calls = 0;
  const resolver = createOrgSpaceHostDidResolver({
    now: () => clock,
    fetchPeerId: async () => {
      calls += 1;
      return respond(calls);
    },
  });
  return {
    resolve: (space = SPACE) => resolver(HOST, space),
    advance: (ms: number) => {
      clock += ms;
    },
    calls: () => calls,
  };
}

describe('org-space host DID resolver', () => {
  it('returns the node-staged ed25519 DID on success', async () => {
    const h = harness(() => DID_KEY);
    expect(await h.resolve()).toBe(DID_KEY);
  });

  it('trims surrounding whitespace from the node body', async () => {
    const h = harness(() => `  ${DID_KEY}\n`);
    expect(await h.resolve()).toBe(DID_KEY);
  });

  it('maps a fetch error to null', async () => {
    const h = harness(() => {
      throw new Error('node unreachable');
    });
    expect(await h.resolve()).toBeNull();
  });

  it('maps a non-ed25519 body to null', async () => {
    const h = harness(() => DID_PKH);
    expect(await h.resolve()).toBeNull();
  });

  it('maps a malformed body to null', async () => {
    const h = harness(() => 'not-a-did');
    expect(await h.resolve()).toBeNull();
  });

  it('never caches a failure: the next call refetches and can succeed', async () => {
    const h = harness((call) => {
      if (call === 1) throw new Error('transient');
      return DID_KEY;
    });
    expect(await h.resolve()).toBeNull();
    expect(await h.resolve()).toBe(DID_KEY);
    expect(h.calls()).toBe(2);
  });

  it('never caches an invalid body: the next call refetches', async () => {
    const h = harness((call) => (call === 1 ? DID_PKH : DID_KEY));
    expect(await h.resolve()).toBeNull();
    expect(await h.resolve()).toBe(DID_KEY);
    expect(h.calls()).toBe(2);
  });

  it('serves a success from cache within the TTL', async () => {
    const h = harness(() => DID_KEY);
    await h.resolve();
    h.advance(ORG_SPACE_HOST_DID_TTL_MS - 1);
    expect(await h.resolve()).toBe(DID_KEY);
    expect(h.calls()).toBe(1);
  });

  it('refetches once the cached success is past the TTL', async () => {
    const h = harness(() => DID_KEY);
    expect(await h.resolve()).toBe(DID_KEY);
    h.advance(ORG_SPACE_HOST_DID_TTL_MS);
    expect(await h.resolve()).toBe(DID_KEY);
    expect(h.calls()).toBe(2);
  });

  it('shares one in-flight fetch across concurrent callers', async () => {
    const gate = Promise.withResolvers<string>();
    const h = harness(() => gate.promise);
    const pending = [h.resolve(), h.resolve(), h.resolve()];
    gate.resolve(DID_KEY);
    expect(await Promise.all(pending)).toEqual([DID_KEY, DID_KEY, DID_KEY]);
    expect(h.calls()).toBe(1);
  });

  it('caches each space independently', async () => {
    const h = harness(() => DID_KEY);
    await h.resolve('space-a');
    await h.resolve('space-b');
    expect(h.calls()).toBe(2);
  });
});
