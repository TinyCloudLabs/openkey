// Variables CRUD routes - plaintext KV storage via TinyCloud
import { Hono } from 'hono';
import { requireSession, type SessionContext } from '../middleware/session';
import { tinyCloudService } from '../services/tinycloud-service';

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

export const variablesRouter = new Hono<SessionContext>();

// All routes require authentication
variablesRouter.use('*', requireSession);

// GET / - List variables (with values)
variablesRouter.get('/', async (c) => {
  const user = c.get('user');

  const variables = await tinyCloudService.listVariables(user.id);
  return c.json({ variables });
});

// POST / - Create a variable
variablesRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{ name: string; value: string }>();

  const nameError = validateName(body.name);
  if (nameError) {
    return c.json({ error: nameError }, 400);
  }

  if (body.value !== undefined && body.value.length > MAX_VALUE_SIZE) {
    return c.json({ error: 'Value exceeds maximum size of 10KB' }, 400);
  }

  const result = await tinyCloudService.putVariable(user.id, body.name, body.value ?? '');
  return c.json(result, 201);
});

// PUT /:name - Update a variable
variablesRouter.put('/:name', async (c) => {
  const user = c.get('user');
  const name = c.req.param('name');
  const body = await c.req.json<{ value: string }>();

  const nameError = validateName(name);
  if (nameError) {
    return c.json({ error: nameError }, 400);
  }

  if (body.value !== undefined && body.value.length > MAX_VALUE_SIZE) {
    return c.json({ error: 'Value exceeds maximum size of 10KB' }, 400);
  }

  const result = await tinyCloudService.putVariable(user.id, name, body.value ?? '');
  return c.json(result);
});

// DELETE /:name - Delete a variable
variablesRouter.delete('/:name', async (c) => {
  const user = c.get('user');
  const name = c.req.param('name');

  const nameError = validateName(name);
  if (nameError) {
    return c.json({ error: nameError }, 400);
  }

  await tinyCloudService.deleteVariable(user.id, name);
  return c.json({ success: true });
});
