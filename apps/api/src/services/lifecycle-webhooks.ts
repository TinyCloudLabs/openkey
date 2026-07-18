import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Prisma, type Plan, type PrismaClient } from '@openkey/db';
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
export type WebhookResolver = (hostname: string) => Promise<Array<{ address: string }>>;
export const WEBHOOK_REQUEST_TIMEOUT_MS = 10_000;
export const WEBHOOK_RESPONSE_MAX_BYTES = 64 * 1024;
export const PUBLIC_PLAN_WEBHOOK_ENDPOINT_LIMITS = {
  FREE: 3,
  PRO: 20,
  ENTERPRISE: 100,
} as const;

export class WebhookEndpointLimitError extends Error {
  constructor(readonly limit: number) {
    super(`Webhook endpoint limit of ${limit} is exhausted`);
    this.name = 'WebhookEndpointLimitError';
  }
}

export function webhookEndpointLimitForPlan(plan: Plan): number {
  // SCALE is a non-public legacy value. Fail closed until it is explicitly
  // audited into a public plan instead of silently inheriting an entitlement.
  if (plan === 'SCALE') return 0;
  return PUBLIC_PLAN_WEBHOOK_ENDPOINT_LIMITS[plan];
}

function ipv4Bytes(address: string): number[] | null {
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const bytes = parts.map(Number);
  return bytes.every((byte) => byte >= 0 && byte <= 255) ? bytes : null;
}

function ipv6Bytes(address: string): number[] | null {
  const source = address.toLowerCase().split('%')[0]!;
  const dotted = source.match(/(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  let normalized = source;
  if (dotted) {
    const bytes = ipv4Bytes(dotted);
    if (!bytes) return null;
    normalized = `${source.slice(0, -dotted.length)}${((bytes[0]! << 8) | bytes[1]!).toString(16)}:${((bytes[2]! << 8) | bytes[3]!).toString(16)}`;
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - left.length - right.length : 0;
  const groups = [...left, ...Array(fill).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.flatMap((group) => {
    const value = Number.parseInt(group, 16);
    return [value >> 8, value & 0xff];
  });
}

export function isPublicWebhookAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const bytes = ipv4Bytes(address)!;
    const [a, b] = bytes;
    return !(a === 0 || a === 10 || a === 127 || (a === 100 && b! >= 64 && b! <= 127)
      || (a === 169 && b === 254) || (a === 172 && b! >= 16 && b! <= 31)
      || (a === 192 && (b === 0 || b === 168)) || (a === 198 && (b === 18 || b === 19))
      || a! >= 224);
  }
  if (family === 6) {
    const bytes = ipv6Bytes(address);
    if (!bytes) return false;
    const unspecified = bytes.every((byte) => byte === 0);
    const loopback = bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1;
    const mappedV4 = bytes.slice(0, 10).every((byte) => byte === 0)
      && bytes[10] === 0xff && bytes[11] === 0xff;
    if (mappedV4) return isPublicWebhookAddress(bytes.slice(12).join('.'));
    return !(unspecified || loopback || (bytes[0]! & 0xfe) === 0xfc
      || (bytes[0] === 0xfe && (bytes[1]! & 0xc0) !== 0)
      || bytes[0] === 0xff);
  }
  return false;
}

const defaultResolver: WebhookResolver = async (hostname) => lookup(hostname, { all: true, verbatim: true });

export async function assertSafeWebhookTarget(
  value: string,
  resolve: WebhookResolver = defaultResolver,
  signal?: AbortSignal,
) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) {
    throw new Error('Webhook URL must be a non-credentialed HTTPS URL without a fragment');
  }
  const hostname = url.hostname.replace(/^\[(.*)\]$/, '$1');
  let addresses: Array<{ address: string }>;
  if (isIP(hostname)) {
    addresses = [{ address: hostname }];
  } else if (signal) {
    addresses = await Promise.race([
      resolve(hostname),
      new Promise<never>((_resolve, reject) => {
        if (signal.aborted) reject(signal.reason);
        else signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      }),
    ]);
  } else {
    addresses = await resolve(hostname);
  }
  if (addresses.length === 0 || addresses.some(({ address }) => !isPublicWebhookAddress(address))) {
    throw new Error('Webhook URL must resolve only to public network addresses');
  }
  return url;
}

export async function createWebhookEndpoint(
  db: PrismaClient,
  input: { organizationId: string; url: string; eventTypes: LifecycleEvent[] },
  tee: TeeClient = createTeeClient(),
) {
  const url = new URL(input.url);
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash
    || ['localhost', '[::1]'].includes(url.hostname) || url.hostname.endsWith('.localhost')
    || (isIP(url.hostname.replace(/^\[(.*)\]$/, '$1'))
      && !isPublicWebhookAddress(url.hostname.replace(/^\[(.*)\]$/, '$1')))) {
    throw new Error('Webhook URL must be a public, non-credentialed HTTPS URL without a fragment');
  }
  const eventTypes = [...new Set(input.eventTypes)];
  if (eventTypes.length === 0 || eventTypes.some((event) => !LIFECYCLE_EVENTS.includes(event))) {
    throw new Error('Webhook eventTypes are invalid');
  }
  const id = randomUUID();
  const secret = `okwhsec_${randomBytes(32).toString('base64url')}`;
  const sealingKey = await tee.deriveKey(`openkey/webhook/${id}`);
  const sealedSecret = await seal(secret, sealingKey);
  let endpoint;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      endpoint = await db.$transaction(async (tx) => {
        const organization = await tx.organization.findUnique({
          where: { id: input.organizationId },
          select: { plan: true },
        });
        if (!organization) throw new Error('Organization not found');
        const limit = webhookEndpointLimitForPlan(organization.plan);
        const activeEndpoints = await tx.webhookEndpoint.count({
          where: { organizationId: input.organizationId, active: true },
        });
        if (activeEndpoints >= limit) throw new WebhookEndpointLimitError(limit);
        return tx.webhookEndpoint.create({
          data: {
            id,
            organizationId: input.organizationId,
            url: url.toString(),
            eventTypes,
            secretHash: createHash('sha256').update(secret).digest('hex'),
            sealedSecret,
          },
          select: { id: true, url: true, eventTypes: true, active: true, createdAt: true },
        });
      }, { isolationLevel: 'Serializable' });
      break;
    } catch (caught) {
      if ((caught as { code?: string }).code === 'P2034' && attempt < 2) continue;
      throw caught;
    }
  }
  if (!endpoint) throw new Error('Webhook endpoint creation could not be serialized');
  return { endpoint, secret };
}

async function boundedResponseDigest(response: Response, maxBytes: number): Promise<string> {
  const hash = createHash('sha256');
  if (!response.body) return hash.digest('hex');
  const reader = response.body.getReader();
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return hash.digest('hex');
      total += value.byteLength;
      if (total > maxBytes) throw new Error('Webhook response exceeded the byte limit');
      hash.update(value);
    }
  } finally {
    if (total > maxBytes) await reader.cancel().catch(() => undefined);
  }
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
  options: {
    tee?: TeeClient;
    fetch?: WebhookFetch;
    resolve?: WebhookResolver;
    now?: Date;
    timeoutMs?: number;
    maxResponseBytes?: number;
  } = {},
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
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error('Webhook request timed out')),
    options.timeoutMs ?? WEBHOOK_REQUEST_TIMEOUT_MS,
  );
  let delivered = false;
  let responseDigest: string;
  try {
    await assertSafeWebhookTarget(delivery.endpoint.url, options.resolve, controller.signal);
    const response = await (options.fetch ?? fetch)(delivery.endpoint.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'OpenKey-Delivery': delivery.id,
        'OpenKey-Signature': `t=${timestamp},v1=${signature}`,
      },
      body,
      redirect: 'manual',
      signal: controller.signal,
    });
    responseDigest = await boundedResponseDigest(
      response,
      options.maxResponseBytes ?? WEBHOOK_RESPONSE_MAX_BYTES,
    );
    delivered = response.ok;
  } catch (caught) {
    const reason = controller.signal.aborted
      ? 'WEBHOOK_REQUEST_TIMEOUT'
      : caught instanceof Error && caught.message.includes('byte limit')
        ? 'WEBHOOK_RESPONSE_TOO_LARGE'
        : 'WEBHOOK_REQUEST_FAILED';
    responseDigest = createHash('sha256').update(reason).digest('hex');
  } finally {
    clearTimeout(timeout);
  }
  return db.webhookDelivery.update({
    where: { id: delivery.id },
    data: {
      status: delivered ? 'DELIVERED' : 'FAILED',
      attempts: { increment: 1 },
      lastAttemptAt: now,
      ...(delivered ? { deliveredAt: now } : {}),
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
