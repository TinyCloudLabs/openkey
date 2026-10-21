// Key management routes
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { createTeeClient, seal, unseal, generatePrivateKey, getAddressFromPrivateKey, type TeeQuote } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import { validateTypedData, verifyMessage } from 'viem';
import type { Hex } from 'viem';
import {
  ensureTinyCloudBootstrapForApprovedSign,
} from '../services/tinycloud-bootstrap';
import { awaitTinyCloudBootstrapWithinBudget } from '../services/tinycloud-bootstrap-budget';
import { personalKeyWhere } from '../services/primary-key';
import { createSealingContext, deriveKeyForRecord } from '../services/key-sealing';
import { deviceTransactionUnsupportedError } from './device-delegation-window';
import { isPrimaryKey, PrimaryKeyConflictError, setPrimaryKey } from '../services/primary-key';
import { checkSignableMessage } from '../services/siwe-origin';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';

import { log, logError } from '../log';
const prisma = createPrismaClient();
const tee = createTeeClient();

// In-memory challenge nonce store with 5-minute TTL
const challengeStore = new Map<string, { message: string; expiresAt: number }>();

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function cleanExpiredChallenges() {
  const now = Date.now();
  for (const [nonce, entry] of challengeStore) {
    if (entry.expiresAt <= now) {
      challengeStore.delete(nonce);
    }
  }
}

export const keysRouter = new Hono<SessionContext>();

// All routes require authentication. A bearer session token is accepted only
// from an OpenKey web origin, where the embedded widgets run (TC-688).
keysRouter.use('*', requireOpenKeyOriginForBearer);
keysRouter.use('*', requireSession);

// Generate a verification challenge for wallet linking
keysRouter.post('/link/challenge', async (c) => {
  cleanExpiredChallenges();

  const nonce = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const message = `OpenKey Wallet Verification\nNonce: ${nonce}\nTimestamp: ${timestamp}`;

  challengeStore.set(nonce, {
    message,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });

  return c.json({ message, nonce });
});

// Link an external wallet address to the user's account
keysRouter.post('/link', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    address: string;
    signature: string;
    message: string;
    label?: string;
  }>();

  if (!body.address || !body.signature || !body.message) {
    return c.json({ error: 'address, signature, and message are required' }, 400);
  }

  // Verify the signature matches the address
  const isValid = await verifyMessage({
    address: body.address as `0x${string}`,
    message: body.message,
    signature: body.signature as `0x${string}`,
  });

  if (!isValid) {
    return c.json({ error: 'Invalid signature' }, 400);
  }

  // Extract nonce from message and validate against challenge store
  const nonceMatch = body.message.match(/Nonce: ([0-9a-f-]+)/);
  if (!nonceMatch) {
    return c.json({ error: 'Invalid message format: missing nonce' }, 400);
  }

  const nonce = nonceMatch[1]!;
  const challenge = challengeStore.get(nonce);

  if (!challenge) {
    return c.json({ error: 'Challenge not found or expired' }, 400);
  }

  if (challenge.expiresAt <= Date.now()) {
    challengeStore.delete(nonce);
    return c.json({ error: 'Challenge expired' }, 400);
  }

  // Delete the nonce after use (one-time use)
  challengeStore.delete(nonce);

  // Check if address is already linked to any user
  const existingKey = await prisma.ethereumKey.findUnique({
    where: { address: body.address },
  });

  if (existingKey) {
    return c.json({ error: 'Address already linked to an account' }, 409);
  }

  // Get next key index for this user
  const lastKey = await prisma.ethereumKey.findFirst({
    where: personalKeyWhere(user.id),
    orderBy: { keyIndex: 'desc' },
  });
  const keyIndex = (lastKey?.keyIndex ?? -1) + 1;

  // Create external key record
  const key = await prisma.ethereumKey.create({
    data: {
      userId: user.id,
      custody: 'PERSONAL',
      address: body.address,
      publicKey: body.address,
      keyType: 'EXTERNAL',
      sealedBlob: null,
      keyIndex,
      label: body.label || `External Key ${keyIndex}`,
    },
    select: {
      id: true,
      address: true,
      publicKey: true,
      keyType: true,
      keyIndex: true,
      label: true,
      createdAt: true,
    },
  });

  return c.json({ key }, 201);
});

async function listKeysWithPrimary(userId: string, includeArchived: boolean) {
  const keys = await prisma.ethereumKey.findMany({
    where: {
      ...personalKeyWhere(userId),
      ...(includeArchived ? {} : { archivedAt: null }),
    },
    select: {
      id: true,
      address: true,
      publicKey: true,
      keyType: true,
      keyIndex: true,
      label: true,
      archivedAt: true,
      createdAt: true,
      isCanonicalTinyCloud: true,
    },
    orderBy: { keyIndex: 'asc' },
  });

  return keys.map(({ isCanonicalTinyCloud, ...key }) => ({
    ...key,
    isPrimary: isPrimaryKey({ ...key, isCanonicalTinyCloud }),
  }));
}

// List user's keys (excludes archived by default)
keysRouter.get('/', async (c) => {
  const user = c.get('user');
  const includeArchived = c.req.query('archived') === 'true';

  return c.json({ keys: await listKeysWithPrimary(user.id, includeArchived) });
});

// Generate a new key
keysRouter.post('/generate', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{ label?: string }>();

  // Get next key index for this user
  const lastKey = await prisma.ethereumKey.findFirst({
    where: personalKeyWhere(user.id),
    orderBy: { keyIndex: 'desc' },
  });
  const keyIndex = (lastKey?.keyIndex ?? -1) + 1;

  // Generate new private key
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);

  const sealingContext = createSealingContext();
  const sealingKey = await tee.deriveKey(`openkey/key/${sealingContext}`);

  // Seal the private key
  const sealedBlob = await seal(privateKey, sealingKey);

  // Store in database
  const key = await prisma.ethereumKey.create({
    data: {
      userId: user.id,
      custody: 'PERSONAL',
      address,
      publicKey: address, // For Ethereum, address is derived from public key
      sealedBlob,
      sealingContext,
      keyIndex,
      label: body.label || `Key ${keyIndex}`,
    },
    select: {
      id: true,
      address: true,
      publicKey: true,
      keyIndex: true,
      label: true,
      createdAt: true,
    },
  });

  return c.json({ key }, 201);
});

// Get key details
keysRouter.get('/:keyId', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');

  const key = await prisma.ethereumKey.findFirst({
    where: { id: keyId, ...personalKeyWhere(user.id) },
    select: {
      id: true,
      address: true,
      publicKey: true,
      keyType: true,
      keyIndex: true,
      label: true,
      archivedAt: true,
      createdAt: true,
      isCanonicalTinyCloud: true,
    },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  const { isCanonicalTinyCloud, ...publicKey } = key;
  return c.json({ key: { ...publicKey, isPrimary: isPrimaryKey(key) } });
});

// Update key label
keysRouter.patch('/:keyId', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const body = await c.req.json<{ label: string }>();

  const key = await prisma.ethereumKey.updateMany({
    where: { id: keyId, ...personalKeyWhere(user.id), archivedAt: null },
    data: { label: body.label },
  });

  if (key.count === 0) {
    return c.json({ error: 'Key not found' }, 404);
  }

  return c.json({ success: true });
});

// Sign a message (internal - will be called by SDK widget)
// Supports both raw signing and EIP-191 (personal_sign) format
keysRouter.post('/:keyId/sign', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const body = await c.req.json<{
    message: string;
    format?: 'raw' | 'personal_sign'; // default: personal_sign
    /** Verified origin of the requesting site; required for SIWE-shaped messages. */
    requestOrigin?: string;
  }>();
  const deviceUnsupported = deviceTransactionUnsupportedError(body);
  if (deviceUnsupported) return c.json(deviceUnsupported, 400);
  // TC-1486: a SIWE-shaped message is signable only for the origin it names.
  // `requestOrigin` is the postMessage sender the widget verified; absent
  // means unattributed, which is refused. Checked before the key is unsealed.
  // The guard must see exactly what the signer will cover, so the shape is
  // validated first: `message` is a string, and `raw` input is even-length
  // `0x` hex (decoded for the guard below).
  if (typeof body.message !== 'string') {
    return c.json({ error: 'message must be a string' }, 400);
  }
  if (body.format === 'raw' && !/^0x(?:[0-9a-fA-F]{2})*$/.test(body.message)) {
    return c.json({ error: 'raw message must be even-length 0x hex' }, 400);
  }
  const siweCheck = checkSignableMessage(body.message, body.requestOrigin);
  if (siweCheck.siwe && !siweCheck.ok) {
    return c.json({ error: siweCheck.message, code: 'siwe_origin_refused', reason: siweCheck.code }, 403);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: keyId, ...personalKeyWhere(user.id), archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType === 'EXTERNAL') {
    return c.json({ error: 'External keys must be signed client-side' }, 400);
  }

  const sealingKey = await deriveKeyForRecord(tee, key);
  const privateKey = await unseal(key.sealedBlob!, sealingKey) as Hex;

  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);

  // personal_sign adds EIP-191 prefix, raw signs the message directly
  const format = body.format || 'personal_sign';
  // Bound bootstrap's synchronous wait; background work keeps its existing lock/heartbeat.
  const bootstrap = await awaitTinyCloudBootstrapWithinBudget(
    ensureTinyCloudBootstrapForApprovedSign({ prisma, userId: user.id, key, privateKey, message: body.message, format }),
  );
  if (bootstrap.status === 'failed') {
    log('error', 'tinycloud_bootstrap_failed', bootstrap.errorCode);
  }

  const signature = await account.signMessage({
    message: format === 'raw' ? { raw: body.message as Hex } : body.message,
  });

  return c.json({
    signature,
    address: key.address,
    format,
    tinycloudBootstrap: bootstrap.status === 'failed'
      ? { status: 'failed', errorCode: bootstrap.errorCode }
      : { status: bootstrap.status },
  });
});

// Sign typed data (EIP-712)
keysRouter.post('/:keyId/sign-typed-data', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const body = await c.req.json<{
    domain: any;
    types: any;
    primaryType: string;
    message: any;
  }>();

  const key = await prisma.ethereumKey.findFirst({
    where: { id: keyId, ...personalKeyWhere(user.id), archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType === 'EXTERNAL') {
    return c.json({ error: 'External keys must be signed client-side' }, 400);
  }

  // viem rejects malformed typed data (e.g. `uint`/`int` aliases instead of
  // `uint256`/`int256`); that is a client error, not a server failure.
  try {
    validateTypedData({
      domain: body.domain,
      types: body.types,
      primaryType: body.primaryType,
      message: body.message,
    });
  } catch (error) {
    return c.json({ error: `Invalid typed data: ${error instanceof Error ? error.message.split('\n')[0] : 'validation failed'}` }, 400);
  }

  // Unseal and sign
  const sealingKey = await deriveKeyForRecord(tee, key);
  const privateKey = await unseal(key.sealedBlob!, sealingKey) as Hex;

  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);

  const signature = await account.signTypedData({
    domain: body.domain,
    types: body.types,
    primaryType: body.primaryType,
    message: body.message,
  });

  return c.json({
    signature,
    address: key.address,
  });
});

// Get an attestation quote binding a managed key's address to this TEE. The
// quote is issued only after the TEE unseals the key and finds the recorded
// address, so it means: code with this measurement holds the key (TC-1193).
keysRouter.get('/:keyId/quote', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  // Optional verifier challenge: 16-64 bytes as lowercase hex.
  const nonce = c.req.query('nonce') ?? null;
  if (nonce !== null && !/^[0-9a-f]{32,128}$/.test(nonce)) {
    return c.json({ error: 'invalid_nonce' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: keyId, ...personalKeyWhere(user.id), archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType === 'EXTERNAL') {
    return c.json({ error: 'External keys are not held in the TEE' }, 400);
  }

  let binding: string;
  let quote: TeeQuote;
  try {
    const privateKey = await unseal(key.sealedBlob!, await deriveKeyForRecord(tee, key)) as Hex;
    if (getAddressFromPrivateKey(privateKey).toLowerCase() !== key.address.toLowerCase()) {
      log('error', 'key_quote_failed', 'quote_key_custody_mismatch');
      return c.json({ error: 'quote_unavailable' }, 503);
    }
    // The quote's REPORTDATA carries SHA-256 of this exact string; it is
    // returned so a verifier can recompute the digest (docs/tee-overview.md).
    binding = JSON.stringify({
      type: 'openkey.key-quote',
      version: 1,
      nonce,
      address: key.address,
      timestamp: Date.now(),
    });
    quote = await tee.getQuote(binding);
  } catch (error) {
    logError('error', 'key_quote_failed', error);
    return c.json({ error: 'quote_unavailable' }, 503);
  }

  return c.json({
    quote: quote.quote,
    eventLog: quote.eventLog,
    binding,
    bindingSha256: quote.reportDataSha256,
    address: key.address,
    inTee: tee.isInTee(),
  });
});

// Make a key the user's primary key: the canonical TinyCloud key that
// `tinycloud:manage-key` signs with and the OAuth canonical identity claim
// names. A TinyCloud signing control, so it takes the same cookie-session,
// OpenKey-origin boundary as the account signing controls.
const PRIMARY_KEY_ERRORS = {
  not_found: { status: 404, message: 'Key not found' },
  external_key: {
    status: 400,
    message: 'An external wallet cannot be your primary key because OpenKey cannot sign with it',
  },
  archived: { status: 400, message: 'Restore this key before making it your primary key' },
  unavailable: { status: 400, message: 'OpenKey cannot sign with this key, so it cannot be your primary key' },
} as const;
const PRIMARY_KEY_ERROR_CODES = {
  not_found: 'key_not_found',
  external_key: 'external_key_not_eligible',
  archived: 'key_archived',
  unavailable: 'key_unavailable',
} as const;

keysRouter.post('/:keyId/primary', async (c) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  const user = c.get('user');
  const keyId = c.req.param('keyId');

  let result;
  try {
    result = await setPrimaryKey(prisma, user.id, keyId);
  } catch (error) {
    if (error instanceof PrimaryKeyConflictError) {
      return c.json({
        error: { code: 'primary_key_conflict', message: 'Your primary key changed at the same time. Reload and try again.' },
      }, 409);
    }
    throw error;
  }

  if (result.kind !== 'changed' && result.kind !== 'unchanged') {
    const failure = PRIMARY_KEY_ERRORS[result.kind];
    return c.json({ error: { code: PRIMARY_KEY_ERROR_CODES[result.kind], message: failure.message } }, failure.status);
  }

  if (result.kind === 'changed') {
    log('info', 'primary_key_changed');
  }

  return c.json({
    changed: result.kind === 'changed',
    key: result.key,
  });
});

// Archive a key (soft delete)
keysRouter.post('/:keyId/archive', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');

  const archivedAt = new Date();
  const key = await prisma.ethereumKey.updateMany({
    where: { id: keyId, ...personalKeyWhere(user.id), archivedAt: null },
    data: { archivedAt },
  });

  if (key.count === 0) {
    return c.json({ error: 'Key not found or already archived' }, 404);
  }

  return c.json({ success: true, archivedAt: archivedAt.toISOString() });
});

// Unarchive a key
keysRouter.post('/:keyId/unarchive', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');

  const key = await prisma.ethereumKey.updateMany({
    where: { id: keyId, ...personalKeyWhere(user.id), archivedAt: { not: null } },
    data: { archivedAt: null },
  });

  if (key.count === 0) {
    return c.json({ error: 'Key not found or not archived' }, 404);
  }

  return c.json({ success: true });
});
