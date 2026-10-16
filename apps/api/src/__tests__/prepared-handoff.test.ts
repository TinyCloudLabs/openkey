import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import {
  PreparedHandoffService,
  MemoryPreparedHandoffStore,
  type PreparedHandoffRequest,
} from '../services/prepared-handoff';

const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const spaceId = `tinycloud:pkh:eip155:1:${address}:default`;
const siwe = prepareSession({
  address,
  chainId: 1,
  domain: 'cli.tinycloud.xyz',
  issuedAt: '2026-10-16T17:00:00.000Z',
  expirationTime: '2026-10-23T17:00:00.000Z',
  spaceId,
  jwk,
  abilities: { kv: { [spaceId]: ['tinycloud.kv/get', 'tinycloud.kv/sync'] } },
}).siwe;
const callback = 'http://127.0.0.1:42317/callback/AAAAAAAAAAAAAAAAAAAAAA';
const state = Buffer.alloc(32, 1).toString('base64url');
const cancelSecret = Buffer.alloc(32, 2).toString('base64url');
const request: PreparedHandoffRequest = {
  protocolVersion: 1,
  siwe,
  jwk,
  host,
  sessionDid: 'did:key:session-cli',
  keyId: 'key-one',
};

function setup() {
  let now = Date.parse('2026-10-16T17:00:00.000Z');
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now });
  const create = (override: Partial<PreparedHandoffRequest> = {}, delivery = { callback, state, cancelSecret }) =>
    service.start({ transportVersion: 2, request: { ...request, ...override }, delivery }, '198.51.100.10');
  return { service, create, advance: (ms: number) => { now += ms; } };
}

describe('prepared CLI handoff', () => {
  test('claim binds the first authenticated user and never discloses delivery secrets or signed results', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    const claimed = await service.resolve(ticket, 'owner');
    expect(claimed.request.siwe).toBe(siwe);
    expect(claimed.request.jwk).toEqual(jwk);
    expect(claimed.delivery).toEqual({ callback });
    expect(JSON.stringify(claimed)).not.toContain(state);
    expect(JSON.stringify(claimed)).not.toContain(cancelSecret);
    expect(await service.resolve(ticket, 'owner')).toEqual(claimed);
    expect(service.resolve(ticket, 'stranger')).rejects.toMatchObject({ code: 'handoff_claimed' });
  });

  test('rejects tampered SIWE, JWK, keyId and host at context binding', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await service.resolve(ticket, 'owner');
    const bind = (overrides: Record<string, unknown>) => service.bindContext(ticket, 'owner', {
      keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context-one', ...overrides,
    });
    await expect(bind({ siwe: siwe.replace('cli.tinycloud.xyz', 'evil.example') })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await expect(bind({ jwk: { ...jwk, x: 'B'.repeat(43) } })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await expect(bind({ keyId: 'key-two' })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await expect(bind({ host: 'https://evil.example' })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await bind({});
    await expect(service.reserveSigning(ticket, 'owner', 'different-context', 'key-one')).rejects.toMatchObject({ code: 'binding_mismatch' });
    expect(await service.reserveSigning(ticket, 'owner', 'context-one', 'key-one')).toBeUndefined();
    await expect(service.reserveSigning(ticket, 'owner', 'context-one', 'key-one')).rejects.toMatchObject({ code: 'handoff_consumed' });
    expect(await service.completeSigning(ticket, 'owner', 'context-one', 'key-one')).toEqual({ deliveryState: state, selectedKeyId: 'key-one' });
  });

  test('prepare rejects changed original bytes, JWK, requested key, host and presentation before issuing a context', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await service.resolve(ticket, 'owner');
    const prepare = (override: Record<string, unknown>) => service.assertRequest(ticket, 'owner', {
      keyId: 'key-one', siwe, jwk, host, ...override,
    });
    for (const altered of [
      { siwe: siwe.replace('cli.tinycloud.xyz', 'evil.example') },
      { jwk: { ...jwk, x: 'B'.repeat(43) } },
      { keyId: 'key-two' },
      { host: 'https://evil.example' },
      { presentation: { reason: 'injected' } },
    ]) {
      await expect(prepare(altered)).rejects.toMatchObject({ code: 'binding_mismatch' });
    }
    await expect(prepare({})).resolves.toBeTruthy();
  });

  test('cancellation needs the CLI secret, survives a browser claim, and wins against signing', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await service.resolve(ticket, 'owner');
    await service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context' });
    await expect(service.cancel(ticket, 'wrong-secret')).rejects.toMatchObject({ code: 'invalid_cancel_secret' });
    await service.cancel(ticket, cancelSecret);
    await expect(service.reserveSigning(ticket, 'owner', 'context', 'key-one')).rejects.toMatchObject({ code: 'handoff_cancelled' });
    await expect(service.resolve(ticket, 'owner')).rejects.toMatchObject({ code: 'handoff_cancelled' });
  });

  test('claimed user can cancel before signing but another user cannot', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await service.resolve(ticket, 'owner');
    await expect(service.cancelClaimed(ticket, 'stranger')).rejects.toMatchObject({ code: 'handoff_claimed' });
    await service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context' });
    await service.cancelClaimed(ticket, 'owner');
    await expect(service.reserveSigning(ticket, 'owner', 'context', 'key-one')).rejects.toMatchObject({ code: 'handoff_cancelled' });
  });

  test('only one authorization context can bind a ticket', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await service.resolve(ticket, 'owner');
    const attempts = await Promise.allSettled(['context-1', 'context-2'].map((authorizationContextToken) =>
      service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken })));
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(1);
    const winner = attempts[0]?.status === 'fulfilled' ? 'context-1' : 'context-2';
    const loser = winner === 'context-1' ? 'context-2' : 'context-1';
    await expect(service.reserveSigning(ticket, 'owner', loser, 'key-one')).rejects.toMatchObject({ code: 'binding_mismatch' });
    await service.reserveSigning(ticket, 'owner', winner, 'key-one');
  });

  test('enforces expiry, per-IP rate limits, public JWK and exact loopback callback', async () => {
    const { service, create, advance } = setup();
    const first = await create();
    for (let n = 1; n < 5; n++) await create();
    await expect(create()).rejects.toMatchObject({ code: 'rate_limited' });
    advance(5 * 60_000 + 1);
    await expect(service.resolve(first.ticket, 'owner')).rejects.toMatchObject({ code: 'handoff_expired' });
    await expect(create({ jwk: { ...jwk, d: 'private' } })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(create({ siwe: siwe.replace(/^URI: .+$/m, 'URI: did:key:tampered') })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(create({ host: `${host}/unexpected` })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(create({ sessionDid: 'display-only-value' })).resolves.toMatchObject({ transportVersion: 2 });
    for (const unsafe of [
      'http://localhost:42317/callback/AAAAAAAAAAAAAAAAAAAAAA',
      'http://127.0.0.1:42317/callback/AAAAAAAAAAAAAAAAAAAAAA?next=evil',
      'http://127.0.0.1:80/callback/AAAAAAAAAAAAAAAAAAAAAA',
      'https://evil.example/callback/AAAAAAAAAAAAAAAAAAAAAA',
    ]) {
      await expect(create({}, { callback: unsafe, state, cancelSecret })).rejects.toMatchObject({ code: 'invalid_request' });
    }
  });
});
