import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { Prisma, type PrismaClient } from '@openkey/db';
import { createTeeClient, seal, unseal, type TeeClient } from '@openkey/tee';

export const LIFECYCLE_EVENTS = [
  'managed_account.created',
  'managed_account.provisioning_failed',
  'custody.transfer_started',
  'custody.transferred',
  'tenant_access.revocation_pending',
  'tenant_access.revoked',
  'managed_account.quota_changed',
] as const;

export type LifecycleEvent = typeof LIFECYCLE_EVENTS[number];
type WebhookDb = Pick<PrismaClient, 'webhookEndpoint' | 'webhookDelivery'>;
type WebhookFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export async function createWebhookEndpoint(
  db: WebhookDb,
  input: { organizationId: string; url: string; eventTypes: LifecycleEvent[] },
  tee: TeeClient = createTeeClient(),
) {
  const url = new URL(input.url);
  if (url.protocol !== 'https:' && !(process.env.NODE_ENV !== 'production' && ['localhost', '127.0.0.1'].includes(url.hostname))) {
    throw new Error('Webhook URL must use HTTPS');
  }
  const eventTypes = [...new Set(input.eventTypes)];
  if (eventTypes.length === 0 || eventTypes.some((event) => !LIFECYCLE_EVENTS.includes(event))) {
    throw new Error('Webhook eventTypes are invalid');
  }
  const id = randomUUID();
  const secret = `okwhsec_${randomBytes(32).toString('base64url')}`;
  const sealingKey = await tee.deriveKey(`openkey/webhook/${id}`);
  const endpoint = await db.webhookEndpoint.create({
    data: {
      id,
      organizationId: input.organizationId,
      url: url.toString(),
      eventTypes,
      secretHash: createHash('sha256').update(secret).digest('hex'),
      sealedSecret: await seal(secret, sealingKey),
    },
    select: { id: true, url: true, eventTypes: true, active: true, createdAt: true },
  });
  return { endpoint, secret };
}

export async function enqueueLifecycleWebhook(
  db: WebhookDb,
  input: {
    organizationId: string;
    managedAccountId: string;
    eventType: LifecycleEvent;
    custodyEpoch: number;
    payload: Prisma.InputJsonValue;
  },
) {
  const endpoints = await db.webhookEndpoint.findMany({
    where: { organizationId: input.organizationId, active: true, eventTypes: { has: input.eventType } },
    select: { id: true },
  });
  if (endpoints.length === 0) return 0;
  const result = await db.webhookDelivery.createMany({
    data: endpoints.map((endpoint) => ({
      endpointId: endpoint.id,
      organizationId: input.organizationId,
      managedAccountId: input.managedAccountId,
      eventType: input.eventType,
      custodyEpoch: input.custodyEpoch,
      payload: input.payload,
    })),
    skipDuplicates: true,
  });
  return result.count;
}

export async function deliverWebhook(
  db: PrismaClient,
  deliveryId: string,
  options: { tee?: TeeClient; fetch?: WebhookFetch; now?: Date } = {},
) {
  const delivery = await db.webhookDelivery.findUnique({ where: { id: deliveryId }, include: { endpoint: true } });
  if (!delivery || delivery.status === 'DELIVERED') return delivery;
  if (!delivery.endpoint.active) throw new Error('Webhook endpoint is inactive');
  const tee = options.tee ?? createTeeClient();
  const secret = await unseal(delivery.endpoint.sealedSecret, await tee.deriveKey(`openkey/webhook/${delivery.endpoint.id}`));
  const timestamp = Math.floor((options.now ?? new Date()).getTime() / 1_000);
  const body = JSON.stringify({
    id: delivery.id,
    type: delivery.eventType,
    organizationId: delivery.organizationId,
    managedAccountId: delivery.managedAccountId,
    custodyEpoch: delivery.custodyEpoch,
    createdAt: delivery.createdAt.toISOString(),
    data: delivery.payload,
  });
  const signature = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  const now = options.now ?? new Date();
  const response = await (options.fetch ?? fetch)(delivery.endpoint.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'OpenKey-Delivery': delivery.id,
      'OpenKey-Signature': `t=${timestamp},v1=${signature}`,
    },
    body,
  });
  const responseText = await response.text();
  const responseDigest = createHash('sha256').update(responseText).digest('hex');
  return db.webhookDelivery.update({
    where: { id: delivery.id },
    data: {
      status: response.ok ? 'DELIVERED' : 'FAILED',
      attempts: { increment: 1 },
      lastAttemptAt: now,
      ...(response.ok ? { deliveredAt: now } : {}),
      responseDigest,
    },
  });
}

export async function processPendingWebhooks(db: PrismaClient, limit = 100) {
  const deliveries = await db.webhookDelivery.findMany({
    where: { status: { in: ['PENDING', 'FAILED'] } },
    select: { id: true, managedAccountId: true },
    orderBy: [{ managedAccountId: 'asc' }, { custodyEpoch: 'asc' }, { createdAt: 'asc' }],
    take: limit,
  });
  const results = [];
  const blockedAccounts = new Set<string>();
  for (const delivery of deliveries) {
    if (blockedAccounts.has(delivery.managedAccountId)) continue;
    try {
      const result = await deliverWebhook(db, delivery.id);
      const ok = result?.status === 'DELIVERED';
      results.push({ id: delivery.id, ok, result });
      if (!ok) blockedAccounts.add(delivery.managedAccountId);
    } catch (error) {
      blockedAccounts.add(delivery.managedAccountId);
      results.push({ id: delivery.id, ok: false, error });
    }
  }
  return results;
}
