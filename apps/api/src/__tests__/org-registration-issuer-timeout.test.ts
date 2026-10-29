import { expect, test } from 'bun:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createOrgRegistrationIntentVerifier } from '../services/org-registration';
import { OrgKeyRefusal } from '../services/org-keys';

test('a stalled issuer body is bounded and does not prevent the next verified intent', async () => {
  const issuer = 'did:web:issuer.credentials.org';
  const kid = `${issuer}#controller`;
  const pair = await generateKeyPair('EdDSA', { extractable: true });
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, aud: 'https://api.openkey.so', registrationId: randomUUID(), orgId: `o${'a'.repeat(26)}`, nonce: randomBytes(32).toString('base64url'), handle: 'issuer-timeout', displayName: 'Issuer timeout fixture', purpose: 'org-registration/v1', iat: now, exp: now + 600 };
  const token = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'org-registration-intent+jwt' }).sign(pair.privateKey);
  const did = { id: issuer, assertionMethod: [kid], verificationMethod: [{ id: kid, controller: issuer, publicKeyJwk: await exportJWK(pair.publicKey) }] };
  let stalled = true;
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch() {
    if (stalled) return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')); } }), { headers: { 'content-type': 'application/json' } });
    return Response.json(did);
  } });
  const verify = createOrgRegistrationIntentVerifier((_url, init) => fetch(`http://127.0.0.1:${server.port}/did.json`, init));
  try {
    const refused = await verify(token).catch((error: unknown) => error);
    expect(refused instanceof OrgKeyRefusal && refused.code).toBe('registration_issuer_unavailable');
    stalled = false;
    expect((await verify(token)).registrationId).toBe(claims.registrationId);
  } finally { await server.stop(true); }
}, 20_000);
