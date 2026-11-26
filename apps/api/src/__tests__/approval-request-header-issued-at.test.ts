// POST /approval-requests/:id/result reads the issuer-signed header of a request the server has not saved yet. The
// header's length cap is Expires At minus Issued At, so an Issued At ahead of the clock by more than the skew is
// refused with the route's `invalid_request` code (HTTP 400) before the requester proof is read.
import { beforeAll, describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { openLinkRecord, prepareLinkRecord, signHeader, signerFromJwk } from '@tinycloud/share-envelope/links';
import { mockModules, replaceModules } from './mock-module';
import type { approvalRequestRouter } from '../routes/approval-requests';

const ID = 'abcdefghijklmnopqrstuvwxyz';
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const apiOrigin = process.env.BETTER_AUTH_URL ?? 'http://localhost:3001';
const RESULT_PATH = `/approval-requests/${ID}/result`;

const pair = generateKeyPairSync('ed25519');
const publicJwk = pair.publicKey.export({ format: 'jwk' });
const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: publicJwk.x })).digest('base64url');

// No request is saved: the route takes the header path for an unsaved request.
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', { id: 'user_1' });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
  '../services/approval-request-store': () => ({ createPrismaApprovalRequestStore: () => ({ findById: async () => null }) }),
});

const sealed = await prepareLinkRecord({
  type: 'openkey-approval-request', issuerKey: signer, apiOrigin: 'https://api.tinycloud.xyz',
  expiresAt: new Date(Date.now() + HOUR_MS), plaintext: new TextEncoder().encode(JSON.stringify({ issuer: signer.did })),
});
const opened = await openLinkRecord(sealed.record, sealed.key);

let route: typeof approvalRequestRouter;

beforeAll(async () => {
  // Static import cannot work: the route captures the database client when it loads.
  ({ approvalRequestRouter: route } = await import('../routes/approval-requests?approval-request-header-issued-at' as string));
});

function proof() {
  const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: jkt, typ: 'openkey-session-proof+jwt' })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({
    client_id: 'openkey-approval-result-v1',
    cred_hash: createHash('sha256').update(JSON.stringify(['discover', ID, opened.header.bodyCid, '', ''])).digest('base64url'),
    htm: 'POST', htu: `${apiOrigin}/api/approval-requests/${ID}/result`, iat: Math.floor(Date.now() / 1000),
    jti: randomBytes(24).toString('base64url'),
  })).toString('base64url');
  return `${head}.${claims}.${sign(null, Buffer.from(`${head}.${claims}`), pair.privateKey).toString('base64url')}`;
}

/** The request as the requester posts it, its header signed with an Issued At `issuedAtOffsetMs` from the clock. */
async function discover(issuedAtOffsetMs: number, lifeMs: number) {
  const issuedAt = Date.now() + issuedAtOffsetMs;
  const header = { ...opened.header, issuedAt: new Date(issuedAt).toISOString(), expiresAt: new Date(issuedAt + lifeMs).toISOString() };
  const response = await route.request(RESULT_PATH, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'OpenKey-Session-Proof': proof() },
    body: JSON.stringify({ bodyCid: header.bodyCid, header, signature: await signHeader(header, signer) }),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

describe('POST /approval-requests/:id/result reads the header Issued At', () => {
  test('refuses an Issued At 6 days ahead with a one day life', async () => {
    const result = await discover(6 * DAY_MS, DAY_MS);

    expect(result.status).toBe(400);
    expect(result.body).toEqual({
      error: 'The signed approval request header Issued At is in the future. Set Issued At to the current time and send the request.',
      code: 'invalid_request',
    });
  });

  test('refuses an Issued At 6 minutes ahead', async () => {
    const result = await discover(6 * MINUTE_MS, HOUR_MS);

    expect(result.status).toBe(400);
    expect(result.body.code).toBe('invalid_request');
  });

  test('accepts an Issued At 4 minutes ahead', async () => {
    const result = await discover(4 * MINUTE_MS, HOUR_MS);

    expect(result.status).toBe(202);
    expect(result.body).toEqual({ status: 'pending' });
  });

  test('accepts an Issued At at the current time', async () => {
    const result = await discover(0, HOUR_MS);

    expect(result.status).toBe(202);
    expect(result.body).toEqual({ status: 'pending' });
  });
});
