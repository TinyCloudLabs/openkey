import { test, expect } from 'bun:test';
import { Wallet } from 'ethers';
import { requestSpacePurge } from './account-deletion-purge-http';
import type { DeletionHttpTransport } from './account-deletion-list-http';
const host = { hostId: 'registered-node', url: 'https://node.example.test' };
const purgeId = crypto.randomUUID();
const space = 'tinycloud:synthetic:openkey';
const result = { version: 1, purge_id: purgeId, state: 'purging', accepted_at: '2026-11-12T00:00:00Z', updated_at: '2026-11-12T00:00:00Z' };

test('purge retries keep operation key; status uses fresh keys and nonces', async () => {
  const wallet = Wallet.createRandom();
  const operationKey = crypto.randomUUID();
  const keys: string[] = [];
  const nonces = new Set<string>();
  const transport: DeletionHttpTransport = async (url, options) => {
    const headers = new Headers(options.headers);
    keys.push(headers.get('Idempotency-Key')!);
    const payload = JSON.parse(Buffer.from(headers.get('Authorization')!.split('.')[1]!, 'base64url').toString());
    nonces.add(payload.nnc);
    expect(payload.att).toEqual({ [`${space}/space`]: { 'tinycloud.space/delete': [{}] } });
    expect(payload.fct).toEqual([{ idempotency_key: keys[keys.length - 1] }]);
    const isStatus = url.endsWith('/status');
    expect(JSON.parse(options.body as string)).toEqual({ version: 1, space_id: space, ...(isStatus ? { purge_id: purgeId } : {}) });
    return Response.json({ ...result, state: isStatus ? 'complete' : 'purging' }, { status: isStatus ? 200 : 202 });
  };
  for (let i = 0; i < 2; i++) expect((await requestSpacePurge(host, wallet.privateKey, space, { idempotencyKey: operationKey }, transport)).complete).toBe(false);
  for (let i = 0; i < 2; i++) expect((await requestSpacePurge(host, wallet.privateKey, space, { purgeId }, transport)).complete).toBe(true);
  expect(keys.slice(0, 2)).toEqual([operationKey, operationKey]);
  expect(new Set(keys.slice(2)).size).toBe(2);
  expect(nonces.size).toBe(4);
});

test('unknown, unavailable, mismatched and malformed status stays pending', async () => {
  const wallet = Wallet.createRandom();
  for (const response of [
    Response.json({ error: { code: 'not_found' } }, { status: 404 }),
    Response.json({}, { status: 503 }),
    Response.json({ ...result, purge_id: crypto.randomUUID(), state: 'complete' }),
    Response.json({ ...result, state: 'unknown' }),
  ]) await expect(requestSpacePurge(host, wallet.privateKey, space, { purgeId }, async () => response)).rejects.toThrow();
});
