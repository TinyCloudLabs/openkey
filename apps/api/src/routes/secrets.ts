// Secrets CRUD routes - encrypted storage via TinyCloud vault
import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { createTeeClient, unseal } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import { tinyCloudService } from '../services/tinycloud-service';

const prisma = new PrismaClient();
const tee = createTeeClient();

// Name validation: must start with letter, contain only letters/numbers/underscores, max 256 chars
const NAME_REGEX = /^[A-Za-z][A-Za-z0-9_]*$/;
const MAX_NAME_LENGTH = 256;
const MAX_VALUE_SIZE = 10 * 1024; // 10KB

function validateName(name: string): string | null {
  if (!name || name.length > MAX_NAME_LENGTH) {
    return 'Name must be 1-256 characters';
  }
  if (!NAME_REGEX.test(name)) {
    return 'Name must start with a letter and contain only letters, numbers, and underscores';
  }
  return null;
}

async function getUserPrivateKey(userId: string): Promise<string | null> {
  const key = await prisma.ethereumKey.findFirst({
    where: { userId, keyIndex: 0, keyType: 'MANAGED' },
  });

  if (!key || !key.sealedBlob) {
    return null;
  }

  const sealingKey = await tee.deriveKey(`openkey/user/${userId}/keys`);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as string;
  // Strip 0x prefix if present
  return privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
}

export const secretsRouter = new Hono<SessionContext>();

// All routes require authentication
secretsRouter.use('*', requireSession);

// POST /enable - Enable TinyCloud for the user
secretsRouter.post('/enable', async (c) => {
  const user = c.get('user');

  const privateKey = await getUserPrivateKey(user.id);
  if (!privateKey) {
    return c.json({ error: 'No managed key found for user' }, 400);
  }

  const result = await tinyCloudService.enableForUser(user.id, privateKey);
  return c.json(result);
});

// GET /status - Check if TinyCloud is enabled
secretsRouter.get('/status', async (c) => {
  const user = c.get('user');

  const enabled = await tinyCloudService.isEnabledForUser(user.id);
  if (!enabled) {
    return c.json({ enabled: false });
  }

  // Get counts
  let secretCount = 0;
  let variableCount = 0;
  try {
    const secrets = await tinyCloudService.listSecrets(user.id);
    secretCount = secrets.length;
  } catch { /* ignore */ }
  try {
    const variables = await tinyCloudService.listVariables(user.id);
    variableCount = variables.length;
  } catch { /* ignore */ }

  return c.json({ enabled: true, secretCount, variableCount });
});

// GET / - List secrets (names + metadata only, NO values)
secretsRouter.get('/', async (c) => {
  const user = c.get('user');

  const secrets = await tinyCloudService.listSecrets(user.id);
  return c.json({ secrets });
});

// POST / - Create a secret
secretsRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{ name: string; value: string }>();

  const nameError = validateName(body.name);
  if (nameError) {
    return c.json({ error: nameError }, 400);
  }

  if (!body.value || body.value.length === 0) {
    return c.json({ error: 'Value is required' }, 400);
  }

  if (body.value.length > MAX_VALUE_SIZE) {
    return c.json({ error: 'Value exceeds maximum size of 10KB' }, 400);
  }

  const result = await tinyCloudService.putSecret(user.id, body.name, body.value);
  return c.json(result, 201);
});

// PUT /:name - Update a secret
secretsRouter.put('/:name', async (c) => {
  const user = c.get('user');
  const name = c.req.param('name');
  const body = await c.req.json<{ value: string }>();

  const nameError = validateName(name);
  if (nameError) {
    return c.json({ error: nameError }, 400);
  }

  if (!body.value || body.value.length === 0) {
    return c.json({ error: 'Value is required' }, 400);
  }

  if (body.value.length > MAX_VALUE_SIZE) {
    return c.json({ error: 'Value exceeds maximum size of 10KB' }, 400);
  }

  const result = await tinyCloudService.putSecret(user.id, name, body.value);
  return c.json(result);
});

// DELETE /:name - Delete a secret
secretsRouter.delete('/:name', async (c) => {
  const user = c.get('user');
  const name = c.req.param('name');

  const nameError = validateName(name);
  if (nameError) {
    return c.json({ error: nameError }, 400);
  }

  await tinyCloudService.deleteSecret(user.id, name);
  return c.json({ success: true });
});
