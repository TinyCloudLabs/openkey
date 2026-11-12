import { test, expect } from 'bun:test';
import { Wallet } from 'ethers';
import { retireOwnerOverHttp } from './account-deletion-retire-http';
import type { DeletionHttpTransport } from './account-deletion-list-http';
const host = { hostId: 'registered-node', url: 'https://node.example.test' };

test('retirement accepts first and repeated acknowledgements with stable key and fresh nonce', async () => {
  const wallet = Wallet.createRandom();
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  const key = crypto.randomUUID();
  const nonces = new Set<string>();
  for (const status of [202, 200]) {
    const transport: DeletionHttpTransport = async (url, options) => {
      expect(url).toBe('https://node.example.test/space/retire-owner');
      expect(options.redirect).toBe('error');
      expect(JSON.parse(options.body as string)).toEqual({ version: 1, owner_did: owner });
      const headers = new Headers(options.headers);
      expect(headers.get('Idempotency-Key')).toBe(key);
      const payload = JSON.parse(Buffer.from(headers.get('Authorization')!.split('.')[1]!, 'base64url').toString());
      expect(payload.att).toEqual({ [owner]: { 'tinycloud.space/retire-owner': [{}] } });
      expect(payload.fct).toEqual([{ idempotency_key: key }]);
      nonces.add(payload.nnc);
      return Response.json({ version: 1, hostId: 'registered-node', state: 'retired' }, { status });
    };
    await retireOwnerOverHttp(host, wallet.privateKey, key, transport);
  }
  expect(nonces.size).toBe(2);
});

test('errors and malformed acknowledgements never retire a host', async () => {
  const wallet = Wallet.createRandom();
  for (const response of [
    Response.json({ version: 1, state: 'retired' }),
    Response.json({ version: 1, hostId: 'wrong', state: 'retired' }),
    Response.json({ error: { code: 'unavailable_retryable' } }, { status: 503 }),
    Response.json({ error: { code: 'idempotency_conflict' } }, { status: 409 }),
    Response.json({ version: 1, state: 'pending' }, { status: 202 }),
    Response.json({ state: 'retired' }, { status: 200 }),
  ]) await expect(retireOwnerOverHttp(host, wallet.privateKey, crypto.randomUUID(), async () => response)).rejects.toThrow();
});
