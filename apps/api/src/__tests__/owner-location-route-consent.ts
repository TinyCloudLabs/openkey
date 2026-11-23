// TC-4082: what a route test needs to give the owner-location publish its passkey consent. An in-memory approval
// database holding one software passkey (step-up capable) for the test user, and a way to do what the web page will:
// ask `/:keyId/owner-location/passkey` for the challenge, answer it with the passkey, and hand back the assertion for
// the `/sign` body. Call `createRouteConsent` at the top level of the test file: it sets the relying party that is read
// when a challenge is issued, for that file only.

import { afterAll } from 'bun:test';
import { createFakeApprovalDb } from './fake-approval-db';
import { createSoftPasskey, type SoftPasskey } from './soft-passkey';

export const TEST_RP_ID = 'openkey.test';
export const TEST_RP_ORIGIN = 'https://openkey.test';

/** Points the relying party at the test one for the calling test file, and puts the old values back when it ends. */
function useTestRelyingParty(): void {
  const saved = { id: process.env.WEBAUTHN_RP_ID, origin: process.env.WEBAUTHN_ORIGIN };
  process.env.WEBAUTHN_RP_ID = TEST_RP_ID;
  process.env.WEBAUTHN_ORIGIN = TEST_RP_ORIGIN;
  afterAll(() => {
    if (saved.id === undefined) delete process.env.WEBAUTHN_RP_ID;
    else process.env.WEBAUTHN_RP_ID = saved.id;
    if (saved.origin === undefined) delete process.env.WEBAUTHN_ORIGIN;
    else process.env.WEBAUTHN_ORIGIN = saved.origin;
  });
}

export interface TestRouter {
  request: (path: string, init: RequestInit) => Response | Promise<Response>;
}

export interface RouteConsent {
  /** The `user`, `passkey`, `verification` delegates and `$transaction` to spread into the route's Prisma stand-in. */
  db: object;
  passkey: SoftPasskey;
  /** The `ownerLocationPasskeyAssertion` for a fresh challenge, or `{}` when the route offers none. */
  assertionFor: (router: TestRouter, keyId: string, requestOrigin: string | undefined) => Promise<Record<string, unknown>>;
}

export async function createRouteConsent(userId: string): Promise<RouteConsent> {
  useTestRelyingParty();
  const fake = createFakeApprovalDb('NEVER');
  const passkey = await createSoftPasskey(fake.db as Parameters<typeof createSoftPasskey>[0], userId, true, TEST_RP_ORIGIN);
  return {
    db: fake.db,
    passkey,
    assertionFor: async (router, keyId, requestOrigin) => {
      const res = await router.request(`/${keyId}/owner-location/passkey`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
        body: JSON.stringify(requestOrigin === undefined ? {} : { requestOrigin }),
      });
      const offer = (await res.json()) as { required?: boolean; challengeToken?: string; options?: Parameters<SoftPasskey['assert']>[0] };
      if (!offer.required || !offer.challengeToken || !offer.options) return {};
      return { ownerLocationPasskeyAssertion: { challengeToken: offer.challengeToken, response: passkey.assert(offer.options) } };
    },
  };
}
