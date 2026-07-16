import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { ejectHttpStatus, ejectManagedAccount, EjectRequestError } from '../services/eject-managed-account';
import { ManagedKeyAuthorizationError } from '../services/managed-key-authorization';
import { signWithUserOwnedManagedAccount } from '../services/personal-managed-key';

const prisma = createPrismaClient();

export const personalManagedAccountsRouter = new Hono<SessionContext>();
personalManagedAccountsRouter.use('*', requireSession);

personalManagedAccountsRouter.get('/', async (c) => {
  const accounts = await prisma.managedAccount.findMany({
    where: { ownerUserId: c.get('user').id, state: { in: ['MANAGED', 'EJECTING', 'USER_OWNED'] } },
    select: {
      id: true,
      state: true,
      custodyEpoch: true,
      revocationStatus: true,
      tenantParentExpiresAt: true,
      createdAt: true,
      organization: { select: { name: true } },
      key: { select: { address: true } },
      ejectRevocationReceipts: { select: { status: true } },
    },
    orderBy: { createdAt: 'desc' },
  });
  return c.json({
    accounts: accounts.map((account) => ({
      managedAccountId: account.id,
      managedBy: account.organization.name,
      state: account.state,
      custodyEpoch: account.custodyEpoch,
      custody: account.state === 'USER_OWNED' ? 'USER_OWNED' : 'ORGANIZATION_MANAGED',
      tenantAccess: account.revocationStatus,
      tenantParentExpiresAt: account.tenantParentExpiresAt,
      address: account.key.address,
      ownerDid: `did:pkh:eip155:1:${account.key.address}`,
      revocationReceipts: account.ejectRevocationReceipts,
    })),
  });
});

personalManagedAccountsRouter.post('/:id/eject', async (c) => {
  const idempotencyKey = c.req.header('Idempotency-Key');
  const body: { expectedEpoch?: unknown } = await c.req.json().catch(() => ({}));
  if (!idempotencyKey || idempotencyKey.length > 200 || !Number.isSafeInteger(body.expectedEpoch)) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'Idempotency-Key and expectedEpoch are required' } }, 400);
  }
  try {
    const result = await ejectManagedAccount(prisma, {
      ownerUserId: c.get('user').id,
      sessionId: c.get('session').id,
      managedAccountId: c.req.param('id'),
      expectedEpoch: Number(body.expectedEpoch),
      idempotencyKey,
    });
    return c.json(result);
  } catch (error) {
    if (error instanceof EjectRequestError || error instanceof ManagedKeyAuthorizationError) {
      return c.json({ error: { code: error.code, message: error.message } }, ejectHttpStatus(error) as 403 | 404 | 409);
    }
    throw error;
  }
});

personalManagedAccountsRouter.get('/:id/revocation', async (c) => {
  const account = await prisma.managedAccount.findFirst({
    where: { id: c.req.param('id'), ownerUserId: c.get('user').id },
    select: {
      state: true,
      custodyEpoch: true,
      revocationStatus: true,
      ejectRevocationReceipts: {
        select: {
          status: true, submittedAt: true, confirmedAt: true, responseDigest: true,
          node: { select: { nodeId: true, baseUrl: true } },
        },
      },
    },
  });
  if (!account) return c.json({ error: { code: 'NOT_FOUND', message: 'Managed account not found' } }, 404);
  return c.json({
    custody: account.state === 'USER_OWNED' ? 'USER_OWNED' : account.state,
    custodyEpoch: account.custodyEpoch,
    tenantAccess: account.revocationStatus,
    nodes: account.ejectRevocationReceipts,
  });
});

personalManagedAccountsRouter.post('/:id/sign', async (c) => {
  const body: { message?: unknown; expectedEpoch?: unknown; approvalId?: unknown } = await c.req.json().catch(() => ({}));
  if (typeof body.message !== 'string' || body.message.length === 0 || body.message.length > 100_000
    || !Number.isSafeInteger(body.expectedEpoch) || typeof body.approvalId !== 'string' || !body.approvalId) {
    return c.json({ error: { code: 'INVALID_REQUEST', message: 'message, approvalId, and expectedEpoch are required' } }, 400);
  }
  const account = await prisma.managedAccount.findFirst({
    where: { id: c.req.param('id'), ownerUserId: c.get('user').id },
    select: { keyId: true },
  });
  if (!account) return c.json({ error: { code: 'NOT_FOUND', message: 'Managed account not found' } }, 404);
  try {
    return c.json(await signWithUserOwnedManagedAccount(prisma, {
      sessionId: c.get('session').id,
      managedAccountId: c.req.param('id'),
      keyId: account.keyId,
      expectedEpoch: Number(body.expectedEpoch),
      approvalId: body.approvalId,
      message: body.message,
    }));
  } catch (error) {
    if (error instanceof ManagedKeyAuthorizationError) {
      return c.json({ error: { code: error.code, message: error.message } }, error.code === 'MANAGED_ACCOUNT_NOT_FOUND' ? 404 : 409);
    }
    throw error;
  }
});
