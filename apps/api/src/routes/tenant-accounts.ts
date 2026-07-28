import { Hono, type Context } from 'hono';
import { Prisma, createPrismaClient } from '@openkey/db';
import { requireOrganizationCredential, type OrganizationContext } from '../middleware/organization';
import {
  createTenantManagedAccount,
  disableTenantManagedAccount,
  getTenantManagedAccount,
  listTenantManagedAccounts,
  resolveManagementCredential,
  signTenantManagedAccount,
  restoreTenantManagedAccount,
  TenantManagedAccountError,
} from '../services/tenant-managed-accounts';

const prisma = createPrismaClient();

type CreateAccountBody = {
  email?: unknown;
  externalUserId?: unknown;
  metadata?: unknown;
};

type SigningBody = {
  expectedCustodyEpoch?: unknown;
  message?: unknown;
  format?: unknown;
  typedData?: unknown;
  digest?: unknown;
  auditContext?: unknown;
  transaction?: unknown;
};

type EpochBody = {
  expectedCustodyEpoch?: unknown;
};

function headers(c: Context) {
  c.header('Deprecation', 'true');
  c.header('Sunset', new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toUTCString());
}

function error(c: Context, error: TenantManagedAccountError) {
  const status = {
    INVALID_REQUEST: 400,
    ACCOUNT_NOT_FOUND: 404,
    ACCOUNT_USER_OWNED: 409,
    ACCOUNT_DISABLED: 409,
    ACCOUNT_IDENTITY_CONFLICT: 409,
    IDEMPOTENCY_CONFLICT: 409,
    CUSTODY_EPOCH_STALE: 409,
    CUSTODY_NOT_ACTIVE: 409,
    OPERATION_NOT_ALLOWED: 403,
    TENANT_ACCESS_ENDED: 409,
  } as const;
  return c.json({ error: { code: error.code, message: error.message } }, status[error.code]);
}

function parseLimit(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 100) return undefined;
  return parsed;
}

function requireIdempotencyKey(c: Context) {
  const value = c.req.header('Idempotency-Key');
  if (!value || value.length > 200) return null;
  return value;
}

export const tenantAccountsRouter = new Hono<OrganizationContext>();
tenantAccountsRouter.use('*', requireOrganizationCredential);

tenantAccountsRouter.post('/', async (c) => {
  const idempotencyKey = requireIdempotencyKey(c);
  if (!idempotencyKey) return c.json({ error: { code: 'INVALID_REQUEST', message: 'Idempotency-Key is required' } }, 400);
  const body: CreateAccountBody = await c.req.json<CreateAccountBody>().catch(() => ({} as CreateAccountBody));
  if (typeof body.email !== 'string') {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'email is required' } }, 400);
  }
  try {
    const credential = await resolveManagementCredential(prisma, c.get('organizationActor').credentialId, c.get('organizationActor').organizationId);
    const account = await createTenantManagedAccount(prisma, {
      credential,
      idempotencyKey,
      email: body.email,
      externalUserId: typeof body.externalUserId === 'string' ? body.externalUserId : undefined,
      metadata: body.metadata === undefined ? undefined : body.metadata as Prisma.JsonValue,
    });
    const { created, ...payload } = account;
    return c.json(payload, created ? 201 : 200);
  } catch (caught) {
    if (caught instanceof TenantManagedAccountError) return error(c, caught);
    throw caught;
  }
});

tenantAccountsRouter.get('/', async (c) => {
  const limit = parseLimit(c.req.query('limit'));
  try {
    // List and read operations require a MANAGEMENT credential, consistent with
    // write operations. BROKER and PROVISIONER credentials must not access tenant
    // account records.
    await resolveManagementCredential(prisma, c.get('organizationActor').credentialId, c.get('organizationActor').organizationId);
    const list = await listTenantManagedAccounts(prisma, c.get('organizationActor').organizationId, {
      email: c.req.query('email') ?? undefined,
      externalUserId: c.req.query('externalUserId') ?? undefined,
      status: c.req.query('status') ?? undefined,
      limit,
      cursor: c.req.query('cursor') ?? undefined,
    });
    return c.json(list);
  } catch (caught) {
    if (caught instanceof TenantManagedAccountError) return error(c, caught);
    throw caught;
  }
});

tenantAccountsRouter.get('/:id', async (c) => {
  try {
    // Read requires a MANAGEMENT credential, same as write operations.
    await resolveManagementCredential(prisma, c.get('organizationActor').credentialId, c.get('organizationActor').organizationId);
    return c.json(await getTenantManagedAccount(prisma, c.get('organizationActor').organizationId, c.req.param('id')));
  } catch (caught) {
    if (caught instanceof TenantManagedAccountError) return error(c, caught);
    throw caught;
  }
});

tenantAccountsRouter.post('/:id/sign', async (c) => {
  const idempotencyKey = requireIdempotencyKey(c);
  if (!idempotencyKey) return c.json({ error: { code: 'INVALID_REQUEST', message: 'Idempotency-Key is required' } }, 400);
  const body: SigningBody = await c.req.json<SigningBody>().catch(() => ({} as SigningBody));
  if (!Number.isSafeInteger(body.expectedCustodyEpoch)) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'expectedCustodyEpoch is required' } }, 400);
  }
  try {
    const credential = await resolveManagementCredential(prisma, c.get('organizationActor').credentialId, c.get('organizationActor').organizationId) as Awaited<ReturnType<typeof resolveManagementCredential>> & { kind: 'MANAGEMENT' };
    const payload =
      typeof body.message === 'string'
        ? { message: body.message, format: body.format === 'hex' ? 'hex' : 'utf8' as const }
        : body.typedData !== undefined
          ? { typedData: body.typedData }
          : typeof body.digest === 'string' && typeof body.auditContext === 'string'
            ? { digest: body.digest as `0x${string}`, auditContext: body.auditContext }
            : body.transaction !== undefined
              ? { transaction: body.transaction }
              : null;
    if (!payload) {
      return c.json({ error: { code: 'INVALID_REQUEST', message: 'A signing payload is required' } }, 400);
    }
    const result = await signTenantManagedAccount(prisma, {
      credential,
      managedAccountId: c.req.param('id'),
      expectedCustodyEpoch: Number(body.expectedCustodyEpoch),
      idempotencyKey,
      payload: payload as any,
    });
    return c.json(result);
  } catch (caught) {
    if (caught instanceof TenantManagedAccountError) return error(c, caught);
    throw caught;
  }
});

tenantAccountsRouter.post('/:id/disable', async (c) => {
  const idempotencyKey = requireIdempotencyKey(c);
  if (!idempotencyKey) return c.json({ error: { code: 'INVALID_REQUEST', message: 'Idempotency-Key is required' } }, 400);
  const body: EpochBody = await c.req.json<EpochBody>().catch(() => ({} as EpochBody));
  if (!Number.isSafeInteger(body.expectedCustodyEpoch)) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'expectedCustodyEpoch is required' } }, 400);
  }
  try {
    const credential = await resolveManagementCredential(prisma, c.get('organizationActor').credentialId, c.get('organizationActor').organizationId) as Awaited<ReturnType<typeof resolveManagementCredential>> & { kind: 'MANAGEMENT' };
    return c.json(await disableTenantManagedAccount(prisma, {
      credential,
      managedAccountId: c.req.param('id'),
      expectedCustodyEpoch: Number(body.expectedCustodyEpoch),
      idempotencyKey,
    }));
  } catch (caught) {
    if (caught instanceof TenantManagedAccountError) return error(c, caught);
    throw caught;
  }
});

tenantAccountsRouter.post('/:id/restore', async (c) => {
  const idempotencyKey = requireIdempotencyKey(c);
  if (!idempotencyKey) return c.json({ error: { code: 'INVALID_REQUEST', message: 'Idempotency-Key is required' } }, 400);
  const body: EpochBody = await c.req.json<EpochBody>().catch(() => ({} as EpochBody));
  if (!Number.isSafeInteger(body.expectedCustodyEpoch)) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'expectedCustodyEpoch is required' } }, 400);
  }
  try {
    const credential = await resolveManagementCredential(prisma, c.get('organizationActor').credentialId, c.get('organizationActor').organizationId) as Awaited<ReturnType<typeof resolveManagementCredential>> & { kind: 'MANAGEMENT' };
    return c.json(await restoreTenantManagedAccount(prisma, {
      credential,
      managedAccountId: c.req.param('id'),
      expectedCustodyEpoch: Number(body.expectedCustodyEpoch),
      idempotencyKey,
    }));
  } catch (caught) {
    if (caught instanceof TenantManagedAccountError) return error(c, caught);
    throw caught;
  }
});

tenantAccountsRouter.post('/managed-account-registration-intents', async (c) => {
  headers(c);
  return c.json({ error: { code: 'REGISTRATION_FLOW_REMOVED', message: 'Registration flow has been removed' } }, 410);
});

tenantAccountsRouter.get('/managed-account-registration-intents/:id', async (c) => {
  headers(c);
  return c.json({ error: { code: 'REGISTRATION_FLOW_REMOVED', message: 'Registration flow has been removed' } }, 410);
});
