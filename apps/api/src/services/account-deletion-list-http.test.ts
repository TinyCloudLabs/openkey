import { expect, test } from 'bun:test';
import { Wallet } from 'ethers';
import { listOwnerSpacesOverHttp } from './account-deletion-list-http';

test('HTTP listing sends raw direct-owner UCAN and fresh page authorization', async () => {
  const wallet = Wallet.createRandom();
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  const nonces = new Set<string>();
  const transport = (async (url: string, options: RequestInit) => {
    expect(url).toBe('https://node.example.test/space/list');
    expect(options.redirect).toBe('error');
    expect(options.signal).toBeInstanceOf(AbortSignal);
    const headers = new Headers(options.headers);
    const token = headers.get('Authorization')!;
    expect(token.startsWith('Bearer ')).toBe(false);
    const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString());
    expect(payload.iss).toBe(`${owner}#blockchainAccountId`);
    expect(payload.att).toEqual({ [owner]: { 'tinycloud.space/list': [{}] } });
    expect(payload.fct[0].idempotency_key).toBe(headers.get('Idempotency-Key'));
    nonces.add(payload.nnc);
    const body = JSON.parse(options.body as string);
    expect(body.ownerDid).toBe(owner);
    const lastPage = body.cursor !== null;
    return Response.json({ version: 1, hostId: 'registered-node', ownerDid: owner, spaces: [lastPage ? 'tinycloud:synthetic:b' : 'tinycloud:synthetic:a'], nextCursor: lastPage ? null : 'opaque+/=', lastPage });
  });
  expect(await listOwnerSpacesOverHttp({ hostId: 'registered-node', url: 'https://node.example.test' }, wallet.privateKey, transport)).toHaveLength(2);
  expect(nonces.size).toBe(2);
});

test('HTTP error never becomes a successful empty listing', async () => {
  await expect(listOwnerSpacesOverHttp({ hostId: 'registered-node', url: 'https://node.example.test' }, Wallet.createRandom().privateKey, (async () => new Response(null, { status: 503 })))).rejects.toThrow();
});
