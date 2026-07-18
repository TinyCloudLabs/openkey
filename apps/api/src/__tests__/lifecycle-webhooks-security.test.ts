import { describe, expect, mock, test } from 'bun:test';
import { seal } from '@openkey/tee';
import {
  assertSafeWebhookTarget,
  createWebhookEndpoint,
  deliverWebhook,
  isPublicWebhookAddress,
} from '../services/lifecycle-webhooks';

const publicResolver = async () => [{ address: '93.184.216.34' }];

describe('lifecycle webhook egress security', () => {
  test('rejects local, private, link-local, multicast, and IPv4-mapped private addresses', () => {
    for (const address of [
      '0.0.0.0', '10.1.2.3', '127.0.0.1', '169.254.169.254', '172.16.1.2', '192.168.1.2',
      '224.0.0.1', '::', '::1', 'fc00::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1',
    ]) expect(isPublicWebhookAddress(address)).toBe(false);
    expect(isPublicWebhookAddress('93.184.216.34')).toBe(true);
    expect(isPublicWebhookAddress('2606:4700:4700::1111')).toBe(true);
  });

  test('rejects direct private targets and hostnames resolving to private addresses', async () => {
    await expect(assertSafeWebhookTarget('https://127.0.0.1/webhook', publicResolver)).rejects.toThrow('public');
    await expect(assertSafeWebhookTarget('https://hooks.example/webhook', async () => [{ address: '10.0.0.2' }]))
      .rejects.toThrow('public');
    await expect(assertSafeWebhookTarget('https://169.254.169.254/latest', publicResolver)).rejects.toThrow('public');
    await expect(assertSafeWebhookTarget('https://hooks.example/webhook', publicResolver)).resolves.toBeInstanceOf(URL);
  });

  test('rejects unsafe endpoint URLs before persistence', async () => {
    const db = { webhookEndpoint: { create: mock(async () => { throw new Error('must not persist'); }) } } as any;
    for (const url of [
      'http://hooks.example/webhook',
      'https://user:password@hooks.example/webhook',
      'https://hooks.example/webhook#fragment',
      'https://localhost/webhook',
      'https://10.0.0.2/webhook',
      'https://169.254.169.254/latest',
    ]) {
      await expect(createWebhookEndpoint(db, {
        organizationId: 'org', url, eventTypes: ['managed_account.created'],
      })).rejects.toThrow();
    }
    expect(db.webhookEndpoint.create).not.toHaveBeenCalled();
  });

  test('re-resolves each attempt and refuses to follow redirects', async () => {
    const key = new Uint8Array(32).fill(7);
    const sealedSecret = await seal('okwhsec_test', key);
    let storedStatus = 'PENDING';
    const db = {
      webhookDelivery: {
        findUnique: mock(async () => ({
          id: 'delivery', endpointId: 'endpoint', organizationId: 'org', managedAccountId: 'account',
          eventType: 'managed_account.created', custodyEpoch: 1, payload: {}, status: storedStatus,
          attempts: 0, createdAt: new Date('2026-07-18T12:00:00Z'),
          endpoint: { id: 'endpoint', url: 'https://hooks.example/webhook', active: true, sealedSecret },
        })),
        update: mock(async ({ data }: any) => {
          storedStatus = data.status;
          return { id: 'delivery', status: storedStatus };
        }),
      },
    } as any;
    const tee = { deriveKey: async () => key } as any;
    const resolve = mock(publicResolver);
    const fetch = mock(async (_input: string | URL | Request, init?: RequestInit) => {
      expect(init?.redirect).toBe('manual');
      return new Response('', { status: 302, headers: { Location: 'http://169.254.169.254/latest' } });
    });
    expect(await deliverWebhook(db, 'delivery', { tee, resolve, fetch })).toMatchObject({ status: 'FAILED' });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledTimes(1);

    storedStatus = 'PENDING';
    expect(await deliverWebhook(db, 'delivery', {
      tee,
      resolve,
      fetch: async (_input, init) => {
        expect(init?.redirect).toBe('manual');
        return new Response('accepted', { status: 200 });
      },
    })).toMatchObject({ status: 'DELIVERED' });
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  test('bounds DNS, request, and streaming response work and records failures', async () => {
    const key = new Uint8Array(32).fill(8);
    const sealedSecret = await seal('okwhsec_test', key);
    const updates: any[] = [];
    const db = {
      webhookDelivery: {
        findUnique: async () => ({
          id: 'bounded', organizationId: 'org', managedAccountId: 'account', eventType: 'managed_account.created',
          custodyEpoch: 1, payload: {}, status: 'PENDING', attempts: 0,
          createdAt: new Date('2026-07-18T12:00:00Z'),
          endpoint: { id: 'endpoint', url: 'https://hooks.example/webhook', active: true, sealedSecret },
        }),
        update: async ({ data }: any) => {
          updates.push(data);
          return { id: 'bounded', status: data.status };
        },
      },
    } as any;
    const tee = { deriveKey: async () => key } as any;

    const timedOut = await deliverWebhook(db, 'bounded', {
      tee,
      timeoutMs: 5,
      resolve: async () => new Promise(() => undefined),
      fetch: async () => { throw new Error('fetch must not run'); },
    });
    expect(timedOut).toMatchObject({ status: 'FAILED' });
    expect(updates.at(-1)).toMatchObject({ status: 'FAILED', attempts: { increment: 1 } });

    let cancelled = false;
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(8));
        controller.enqueue(new Uint8Array(8));
      },
      cancel() { cancelled = true; },
    });
    const tooLarge = await deliverWebhook(db, 'bounded', {
      tee,
      resolve: publicResolver,
      maxResponseBytes: 8,
      fetch: async () => new Response(oversized, { status: 200 }),
    });
    expect(tooLarge).toMatchObject({ status: 'FAILED' });
    expect(cancelled).toBe(true);
    expect(updates.at(-1).responseDigest).toMatch(/^[a-f0-9]{64}$/);
  });
});
