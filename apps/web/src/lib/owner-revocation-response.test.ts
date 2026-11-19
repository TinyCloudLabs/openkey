// @ts-expect-error bun:test is supplied by the web test runner
import { describe, expect, test } from 'bun:test';
import { deliverOwnerRevocation } from './owner-revocation-response';

const siwe = 'openkey.so wants you to sign in with your Ethereum account:\n0x1111111111111111111111111111111111111111\n\n\nURI: ucan:bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const signature = `0x${'ab'.repeat(65)}`;
const state = Buffer.alloc(32, 4).toString('base64url');
const callback = 'http://127.0.0.1:54321/callback/AAAAAAAAAAAAAAAAAAAAAA';

describe('owner revocation tv2 response', () => {
  test('callback and paste use identical envelope with exact signed SIWE and signature', async () => {
    let posted: unknown;
    const response = await deliverOwnerRevocation({ state, siwe, signature, callback }, async (_url, init) => {
      posted = JSON.parse(init!.body as string);
      return Response.json({ accepted: true });
    });
    const pasted = JSON.parse(Buffer.from(response.code, 'base64url').toString());
    expect(response.delivered).toBe(true);
    expect(posted).toEqual(pasted);
    expect(pasted).toEqual({ transportVersion: 2, state, result: { siwe, signature } });
  });
  test('a failed callback leaves the same paste response available', async () => {
    const response = await deliverOwnerRevocation({ state, siwe, signature, callback }, async () => { throw new Error('offline'); });
    expect(response.delivered).toBe(false);
    expect(JSON.parse(Buffer.from(response.code, 'base64url').toString()).result.siwe).toBe(siwe);
  });
});
