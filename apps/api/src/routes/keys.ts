// Key management routes
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { createTeeClient, seal, unseal, generatePrivateKey, getAddressFromPrivateKey } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import { verifyMessage } from 'viem';
import type { Hex } from 'viem';

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

// All routes require authentication
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
    where: { userId: user.id },
    orderBy: { keyIndex: 'desc' },
  });
  const keyIndex = (lastKey?.keyIndex ?? -1) + 1;

  // Create external key record
  const key = await prisma.ethereumKey.create({
    data: {
      userId: user.id,
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

// List user's keys (excludes archived by default)
keysRouter.get('/', async (c) => {
  const user = c.get('user');
  const includeArchived = c.req.query('archived') === 'true';

  const keys = await prisma.ethereumKey.findMany({
    where: {
      userId: user.id,
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
    },
    orderBy: { keyIndex: 'asc' },
  });

  return c.json({ keys });
});

// Generate a new key
keysRouter.post('/generate', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{ label?: string }>();

  // Get next key index for this user
  const lastKey = await prisma.ethereumKey.findFirst({
    where: { userId: user.id },
    orderBy: { keyIndex: 'desc' },
  });
  const keyIndex = (lastKey?.keyIndex ?? -1) + 1;

  // Generate new private key
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);

  // Derive sealing key from TEE for this user
  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);

  // Seal the private key
  const sealedBlob = await seal(privateKey, sealingKey);

  // Store in database
  const key = await prisma.ethereumKey.create({
    data: {
      userId: user.id,
      address,
      publicKey: address, // For Ethereum, address is derived from public key
      sealedBlob,
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
    where: { id: keyId, userId: user.id, archivedAt: null },
    select: {
      id: true,
      address: true,
      publicKey: true,
      keyType: true,
      keyIndex: true,
      label: true,
      archivedAt: true,
      createdAt: true,
    },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  return c.json({ key });
});

// Update key label
keysRouter.patch('/:keyId', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const body = await c.req.json<{ label: string }>();

  const key = await prisma.ethereumKey.updateMany({
    where: { id: keyId, userId: user.id, archivedAt: null },
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
  }>();

  const key = await prisma.ethereumKey.findFirst({
    where: { id: keyId, userId: user.id, archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType === 'EXTERNAL') {
    return c.json({ error: 'External keys must be signed client-side' }, 400);
  }

  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
  const privateKey = await unseal(key.sealedBlob!, sealingKey) as Hex;

  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);

  // personal_sign adds EIP-191 prefix, raw signs the message directly
  const format = body.format || 'personal_sign';
  const signature = await account.signMessage({
    message: format === 'raw' ? { raw: body.message as Hex } : body.message,
  });

  return c.json({
    signature,
    address: key.address,
    format,
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
    where: { id: keyId, userId: user.id, archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType === 'EXTERNAL') {
    return c.json({ error: 'External keys must be signed client-side' }, 400);
  }

  // Unseal and sign
  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
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

// Get attestation quote for a key
keysRouter.get('/:keyId/quote', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');

  const key = await prisma.ethereumKey.findFirst({
    where: { id: keyId, userId: user.id, archivedAt: null },
    select: { address: true },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  // Generate attestation quote proving key is in TEE
  const quote = await tee.getQuote(JSON.stringify({
    address: key.address,
    userId: user.id,
    timestamp: Date.now(),
  }));

  return c.json({
    quote,
    address: key.address,
    inTee: tee.isInTee(),
  });
});

// Archive a key (soft delete)
keysRouter.post('/:keyId/archive', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');

  const archivedAt = new Date();
  const key = await prisma.ethereumKey.updateMany({
    where: { id: keyId, userId: user.id, archivedAt: null },
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
    where: { id: keyId, userId: user.id, archivedAt: { not: null } },
    data: { archivedAt: null },
  });

  if (key.count === 0) {
    return c.json({ error: 'Key not found or not archived' }, 404);
  }

  return c.json({ success: true });
});
