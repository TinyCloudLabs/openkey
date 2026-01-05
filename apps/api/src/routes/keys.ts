// Key management routes
import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { createTeeClient, seal, unseal, generatePrivateKey, getAddressFromPrivateKey } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import type { Hex } from 'viem';

const prisma = new PrismaClient();
const tee = createTeeClient();

export const keysRouter = new Hono<SessionContext>();

// All routes require authentication
keysRouter.use('*', requireSession);

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
    where: { id: keyId, userId: user.id },
    select: {
      id: true,
      address: true,
      publicKey: true,
      keyIndex: true,
      label: true,
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
    where: { id: keyId, userId: user.id },
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
    where: { id: keyId, userId: user.id },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as Hex;

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
    where: { id: keyId, userId: user.id },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  // Unseal and sign
  const sealingKey = await tee.deriveKey(`openkey/user/${user.id}/keys`);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as Hex;

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
    where: { id: keyId, userId: user.id },
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

  const key = await prisma.ethereumKey.updateMany({
    where: { id: keyId, userId: user.id, archivedAt: null },
    data: { archivedAt: new Date() },
  });

  if (key.count === 0) {
    return c.json({ error: 'Key not found or already archived' }, 404);
  }

  return c.json({ success: true, archivedAt: new Date().toISOString() });
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
