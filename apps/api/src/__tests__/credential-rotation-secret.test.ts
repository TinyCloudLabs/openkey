// Focused tests for credential rotation plaintext-secret non-persistence.
//
// Sol review requirement: the managedAccountOperation.response column must NEVER
// durably persist the plaintext issued management secret. The secret is a
// one-time value returned only in the HTTP response; the operation record stores
// only { credentialId, rotated: true } for idempotency tracking.
//
// These tests prove:
// 1. The DB record stored during rotation contains no plaintext secret.
// 2. An idempotency replay does NOT return the secret.
// 3. The first HTTP response DOES return the credential and secret.
// 4. The timeout/retry behavior is specified: a second call with the same key
//    returns alreadyRotated=true without a secret (callers must re-rotate).

import { afterAll, beforeAll, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { createHash } from 'node:crypto';
import { authenticateOrganizationCredential } from '../services/organization-credentials';

// ─── captured DB writes ─────────────────────────────────────────────────────
let storedOperationResponse: unknown = undefined;
let replayMode = false;  // When true, findUnique returns the stored operation.
let actorCredentialId = 'actor-cred-1';
const targetSecret = `oksk_abcdefghijklmnop.${'a'.repeat(43)}`;

const targetCredential = {
  id: 'target-cred-1',
  organizationId: 'org-1',
  name: 'Management Credential',
  subjectUserId: 'user-1',
  kind: 'MANAGEMENT' as const,
  revokedAt: null,
  secretPrefix: 'abcdefghijklmnop',
  secretHash: createHash('sha256').update('a'.repeat(43), 'utf8').digest('hex'),
};

const prisma = {
  $transaction: mock(async (fn: any) => fn(prisma)),
  organizationServerCredential: {
    findFirst: mock(async ({ where }: any) => {
      // Actor's own credential lookup (for management auth)
      if (where?.id === actorCredentialId && !where?.revokedAt) return actorCredentialId === targetCredential.id
        ? targetCredential
        : { id: 'actor-cred-1', organizationId: 'org-1', subjectUserId: 'user-1', kind: 'MANAGEMENT', revokedAt: null };
      // Target credential lookup
      if (where?.id === 'target-cred-1') return targetCredential;
      return null;
    }),
    create: mock(async ({ data }: any) => ({
      id: 'new-cred-1',
      organizationId: 'org-1',
      name: data.name,
      kind: 'MANAGEMENT',
      secretPrefix: 'oksk_newprefix',
      subjectUserId: 'user-1',
      createdAt: new Date(),
      lastUsedAt: null,
      revokedAt: null,
    })),
    update: mock(async () => ({})),
    updateMany: mock(async () => ({ count: 1 })),
    findUnique: mock(async ({ where }: any) => where?.secretPrefix === targetCredential.secretPrefix ? targetCredential : null),
  },
  organizationMembership: {
    findFirst: mock(async () => ({ id: 'membership-1' })),
  },
  managedAccountOperation: {
    create: mock(async ({ data }: any) => {
      storedOperationResponse = data.response;
      return { id: 'op-1', ...data };
    }),
    findUnique: mock(async () => {
      if (!replayMode) return null;
      return {
        id: 'op-1',
        requestHash: JSON.stringify({ credentialId: 'target-cred-1', name: 'Management Credential', subjectUserId: 'user-1' }),
        response: storedOperationResponse,
      };
    }),
  },
};

let managementCredentialsRouter: typeof import('../routes/management-credentials')['managementCredentialsRouter'];

beforeAll(async () => {
  // The API suite shares Bun's module registry between files. Clear factories
  // before installing this test's boundary fakes, then load a fresh route and
  // production service graph so another route test cannot supply a stale
  // tenant-managed-account implementation.
  mock.restore();
  mock.module('@openkey/db', () => ({
    createPrismaClient: () => prisma,
    Prisma: { JsonNull: null },
  }));

  mock.module('../middleware/organization', () => ({
    requireOrganizationCredential: createMiddleware(async (c, next) => {
      c.set('organizationActor', {
        credentialId: actorCredentialId,
        organizationId: 'org-1',
        subjectUserId: 'user-1',
        kind: 'MANAGEMENT',
      });
      await next();
    }),
  }));

  const servicePath = '../services/tenant-managed-accounts?__fresh=credential-rotation';
  const service = await import(servicePath);
  mock.module('../services/tenant-managed-accounts', () => ({ ...service }));
  const routePath = '../routes/management-credentials?__fresh=credential-rotation';
  const route = await import(routePath);
  managementCredentialsRouter = route.managementCredentialsRouter;
});

afterAll(() => { mock.restore(); });

async function getRouter() {
  return managementCredentialsRouter;
}

describe('credential rotation — plaintext secret not persisted', () => {
  test('rejects self-rotation before mutation and leaves the authenticating credential valid', async () => {
    replayMode = false;
    actorCredentialId = targetCredential.id;
    const router = await getRouter();
    const createsBefore = prisma.organizationServerCredential.create.mock.calls.length;
    const updatesBefore = prisma.organizationServerCredential.updateMany.mock.calls.length;

    const res = await router.request('/target-cred-1/rotate', {
      method: 'POST',
      headers: { Authorization: 'Bearer oksk_actor', 'Idempotency-Key': 'self-rotate-idem' },
    });

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: { code: 'OPERATION_NOT_ALLOWED' } });
    expect(prisma.organizationServerCredential.create.mock.calls.length).toBe(createsBefore);
    expect(prisma.organizationServerCredential.updateMany.mock.calls.length).toBe(updatesBefore);
    await expect(authenticateOrganizationCredential(prisma as any, targetSecret)).resolves.toMatchObject({
      credentialId: targetCredential.id,
      organizationId: targetCredential.organizationId,
    });
    actorCredentialId = 'actor-cred-1';
  });

  test('DB operation record does not contain the plaintext secret', async () => {
    storedOperationResponse = undefined;
    replayMode = false;

    const router = await getRouter();
    const res = await router.request('/target-cred-1/rotate', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_actor',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'rotate-idem-1',
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;

    // HTTP response MUST contain the credential and secret (returned once)
    expect(body).toHaveProperty('credential');
    expect(body).toHaveProperty('secret');
    expect(typeof body.secret).toBe('string');
    expect(body.secret.length).toBeGreaterThan(0);

    // The DB record MUST NOT contain the secret or the credential object
    expect(storedOperationResponse).toBeDefined();
    const stored = storedOperationResponse as Record<string, unknown>;
    // rotated=true and credentialId are the only allowed fields
    expect(stored.rotated).toBe(true);
    expect(stored.credentialId).toBe('new-cred-1');
    expect(stored).not.toHaveProperty('secret');
    // The stored response must NOT contain anything that looks like a credential token
    const storedJson = JSON.stringify(stored);
    expect(storedJson).not.toContain('oksk_');
  });

  test('replay response does not return the secret — alreadyRotated=true instead', async () => {
    replayMode = true;

    const router = await getRouter();
    const res = await router.request('/target-cred-1/rotate', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_actor',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'rotate-idem-1',
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;

    // Replay MUST NOT contain the secret
    expect(body).not.toHaveProperty('secret');
    expect(body).not.toHaveProperty('credential');
    // Replay MUST indicate the rotation already happened
    expect(body.alreadyRotated).toBe(true);
    expect(body.credentialId).toBe('new-cred-1');
    // The message must explain that the secret cannot be retrieved
    expect(typeof body.message).toBe('string');
    expect(body.message.toLowerCase()).toContain('secret');

    replayMode = false;
  });

  test('timeout/retry contract: after a missed response, caller must re-rotate', async () => {
    // This documents the specified behavior:
    // If a caller sends a rotation request and receives a network timeout (no response),
    // retrying with the same idempotency key yields alreadyRotated=true (no secret).
    // The caller must issue a NEW rotation (new idempotency key) to get a new secret.
    // This is the safe behavior: we prefer "caller must re-rotate" over persisting the
    // plaintext secret in the database to enable replay retrieval.
    replayMode = true;

    const router = await getRouter();
    const retryRes = await router.request('/target-cred-1/rotate', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer oksk_actor',
        'Content-Type': 'application/json',
        'Idempotency-Key': 'rotate-idem-1',  // Same key as before — simulates retry after timeout
      },
    });

    expect(retryRes.status).toBe(200);
    const body = await retryRes.json() as any;
    // The retry gets alreadyRotated, not the original secret
    expect(body.alreadyRotated).toBe(true);
    expect(body).not.toHaveProperty('secret');

    replayMode = false;
  });
});
