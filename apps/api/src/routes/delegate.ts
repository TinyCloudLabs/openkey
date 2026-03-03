// Delegate route - creates TinyCloud delegation for CLI auth flow
import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { createTeeClient, unseal } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import type { Hex } from 'viem';
import {
  prepareSession,
  completeSessionSetup,
  ensureEip55,
  makeSpaceId,
} from '@tinycloud/node-sdk-wasm';
import { activateSessionWithHost } from '@tinycloud/sdk-core';

const prisma = new PrismaClient();
const tee = createTeeClient();

export const delegateRouter = new Hono<SessionContext>();

// The SIWE domain identifies the requestor (the CLI), not the storage node
const SIWE_DOMAIN = 'cli.tinycloud.xyz';

// Require authentication
delegateRouter.use('*', requireSession);

// Default abilities (same as NodeUserAuthorization)
const DEFAULT_ABILITIES = {
  kv: {
    '': [
      'tinycloud.kv/put',
      'tinycloud.kv/get',
      'tinycloud.kv/del',
      'tinycloud.kv/list',
      'tinycloud.kv/metadata',
    ],
  },
  sql: {
    '': [
      'tinycloud.sql/read',
      'tinycloud.sql/write',
      'tinycloud.sql/admin',
      'tinycloud.sql/export',
    ],
  },
  capabilities: {
    '': ['tinycloud.capabilities/read'],
  },
};

/**
 * POST /api/delegate
 *
 * Creates a TinyCloud delegation for the CLI using a MANAGED key.
 * The server unseals the private key via TEE and signs the SIWE message.
 */
delegateRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    jwk: { kty: string; crv: string; x: string };
    host: string;
    prefix?: string;
  }>();

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({ error: 'Only managed keys can be used with this endpoint. Use /api/delegate/prepare + /api/delegate/complete for external keys.' }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ error: 'Key has no sealed data' }, 400);
  }

  // Unseal the private key
  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as Hex;

  // Import viem account for signing
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;

  const spaceId = makeSpaceId(address, chainId, prefix);

  const now = new Date();
  const expirationTime = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour

  const prepared = prepareSession({
    abilities: DEFAULT_ABILITIES,
    address,
    chainId,
    domain: SIWE_DOMAIN,
    issuedAt: now.toISOString(),
    expirationTime: expirationTime.toISOString(),
    spaceId,
    jwk: body.jwk,
  });

  const signature = await account.signMessage({
    message: prepared.siwe,
  });

  const session = completeSessionSetup({
    ...prepared,
    signature,
  });

  const activationResult = await activateSessionWithHost(host, session.delegationHeader);

  if (!activationResult.success) {
    console.warn(`[Delegate] Session activation warning: ${activationResult.error}`);
  }

  const primaryDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId,
    primaryDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
  });
});

/**
 * POST /api/delegate/prepare
 *
 * Prepares a SIWE delegation message for an external key to sign.
 * Returns the SIWE message and prepared session data. The client
 * signs the SIWE message with their browser wallet, then calls
 * POST /api/delegate/complete with the signature.
 */
delegateRouter.post('/prepare', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    jwk: { kty: string; crv: string; x: string };
    host: string;
    prefix?: string;
  }>();

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;

  const spaceId = makeSpaceId(address, chainId, prefix);

  const now = new Date();
  const expirationTime = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour

  const prepared = prepareSession({
    abilities: DEFAULT_ABILITIES,
    address,
    chainId,
    domain: SIWE_DOMAIN,
    issuedAt: now.toISOString(),
    expirationTime: expirationTime.toISOString(),
    spaceId,
    jwk: body.jwk,
  });

  const primaryDid = `did:pkh:eip155:${chainId}:${address}`;

  // Ensure JWK is preserved as a plain object through JSON round-trip.
  // The WASM prepareSession may return JWK as a special object that
  // doesn't serialize correctly, so we merge the original JWK back in.
  const preparedData = {
    ...prepared,
    jwk: body.jwk,
  };

  return c.json({
    prepared: preparedData,
    spaceId,
    primaryDid,
    address,
    chainId,
    host,
    jwk: body.jwk,
  });
});

/**
 * POST /api/delegate/complete
 *
 * Completes a delegation using a wallet-signed SIWE message.
 * Takes the prepared session data from /prepare plus the signature,
 * calls completeSessionSetup, activates the session, and returns
 * the delegation data.
 */
delegateRouter.post('/complete', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    prepared: any;
    signature: string;
    host: string;
    jwk: { kty: string; crv: string; x: string };
  }>();

  if (!body.prepared || !body.signature || !body.host || !body.jwk) {
    return c.json({ error: 'prepared, signature, host, and jwk are required' }, 400);
  }

  // Ensure JWK is a proper object with kty for WASM deserialization
  const session = completeSessionSetup({
    ...body.prepared,
    jwk: body.jwk,
    signature: body.signature,
  });

  const activationResult = await activateSessionWithHost(body.host, session.delegationHeader);

  if (!activationResult.success) {
    console.warn(`[Delegate] Session activation warning: ${activationResult.error}`);
  }

  // Extract address/chainId from the prepared data
  const address = body.prepared.address || '';
  const chainId = body.prepared.chainId || 1;
  const spaceId = body.prepared.spaceId || '';
  const primaryDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId,
    primaryDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
  });
});
