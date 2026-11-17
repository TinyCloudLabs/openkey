#!/usr/bin/env bun
/**
 * Seeds the hermetic "Review path" stack: one synthetic app-review account, its OAuth client and its
 * review code, against a throwaway database and the API under test.
 *
 * It does what an operator's provisioning does, minus the TinyCloud node: the admin route
 * `POST /api/admin/review-accounts/<store>/provision` hosts spaces and writes fixtures on a real node, which
 * a hermetic run must not reach. So the client is registered through the real dynamic-registration route, the
 * user, its sealed key and the reviewer binding are written to the database, and the review code is
 * installed through the real admin route (`PUT .../code`), exactly as production does.
 *
 * Env (all required):
 *   DATABASE_URL              the throwaway database the API under test uses
 *   TEE_MODE=development      with the same DEV_SEALING_KEY / NODE_ENV the API runs with
 *   REVIEW_PATH_API           the API under test, as this script reaches it (e.g. http://127.0.0.1:3001)
 *   REVIEW_PATH_ORIGIN        the web origin the browser uses; sent as Origin, and the API's WEBAUTHN_ORIGIN
 *   ADMIN_API_KEY             the API's admin key (a throwaway value chosen by the workflow)
 *   REVIEW_PATH_FIXTURE       where to write the fixture JSON the browser spec reads
 *   REVIEW_PATH_NODE_HOST     the node address recorded on the binding (a local stub; never a real node)
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { createPrismaClient } from '../../packages/db/src/index';
import { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } from '../../packages/tee/src/index';
import { createSealingContext } from '../../apps/api/src/services/key-sealing';
import { reviewerSessionDid } from '../../apps/api/src/services/reviewer-delegation';

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    console.error(`${name} is required`);
    process.exit(1);
  }
  return value;
}

const api = required('REVIEW_PATH_API').replace(/\/$/, '');
const webOrigin = required('REVIEW_PATH_ORIGIN').replace(/\/$/, '');
const admin = required('ADMIN_API_KEY');
const fixturePath = required('REVIEW_PATH_FIXTURE');
const nodeHost = required('REVIEW_PATH_NODE_HOST');
required('DATABASE_URL');

const STORE = 'openai';
const EMAIL = 'openai-review@tinycloud.xyz';
const REDIRECT_URI = 'https://chatgpt.com/connector_platform_oauth_redirect';
const RESOURCE = 'https://mcp.tinycloud.xyz/chatgpt/mcp';
const CALLBACK_URI = 'https://mcp.tinycloud.xyz/chatgpt/connect/callback';

async function waitForApi(): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      if ((await fetch(`${api}/health`)).ok) return;
    } catch { /* not up yet */ }
    await Bun.sleep(1000);
  }
  throw new Error(`API at ${api} did not become healthy`);
}

async function main() {
  await waitForApi();
  const prisma = createPrismaClient();
  try {
    // The reviewer binding rows are reserved by migration 20261111_0001_reviewer_accounts.
    const binding = await prisma.reviewerAccount.findUnique({ where: { store: STORE } });
    if (!binding) throw new Error('reviewer binding row missing: migrations did not apply');

    const registration = await fetch(`${api}/api/auth/oauth2/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: webOrigin },
      body: JSON.stringify({
        client_name: 'Review path fixture', redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      }),
    });
    if (!registration.ok) throw new Error(`client registration failed: HTTP ${registration.status}`);
    const registered: { client_id?: unknown } = await registration.json();
    if (typeof registered.client_id !== 'string') throw new Error('client registration returned no client id');
    const clientId = registered.client_id;

    // Held until the code is installed (the admin route lifts the hold), as in production.
    await prisma.user.create({
      data: { id: 'review-path-owner', email: EMAIL, emailVerified: true, name: 'App review', reviewerHoldAt: new Date() },
    });
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = createSealingContext();
    const sealedBlob = await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`));
    await prisma.ethereumKey.create({
      data: {
        id: 'review-path-key', userId: 'review-path-owner', address, publicKey: address, sealedBlob,
        sealingContext, isCanonicalTinyCloud: true, keyIndex: 0,
      },
    });

    // The session key the hosted MCP would pin; the browser spec delegates to it.
    const session = generateKeyPairSync('ed25519');
    const publicJwk = session.publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
    const sessionDid = reviewerSessionDid(publicJwk);
    if (!sessionDid) throw new Error('session key is not a valid did:key');

    await prisma.reviewerAccount.update({
      where: { store: STORE },
      data: {
        userId: 'review-path-owner', clientId, redirectUri: REDIRECT_URI, resource: RESOURCE, callbackUri: CALLBACK_URI,
        nodeHost, sessionDid, keyId: 'review-path-key',
        spaceId: `tinycloud:pkh:eip155:1:${address}:applications`, seededAt: new Date(),
      },
    });

    const code = randomBytes(32).toString('base64url');
    const install = await fetch(`${api}/api/admin/review-accounts/${STORE}/code`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
      body: JSON.stringify({ code }),
    });
    if (!install.ok) throw new Error(`review code install failed: HTTP ${install.status}`);

    writeFileSync(fixturePath, JSON.stringify({
      email: EMAIL, code, clientId, redirectUri: REDIRECT_URI, resource: RESOURCE, callbackUri: CALLBACK_URI, nodeHost, address,
      sessionDid, sessionPublicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x },
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
    }), { mode: 0o600 });
    console.log('review path seeded');
  } finally {
    await prisma.$disconnect();
  }
}

await main();
