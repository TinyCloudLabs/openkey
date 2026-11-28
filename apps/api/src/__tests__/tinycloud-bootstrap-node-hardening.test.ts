// TC-4436: what the TinyCloud bootstrap accepts from a node. A node answer never sends a signed request on to another
// address, is read only up to a fixed size, and never puts its own text into a failure reason, an outcome or a log line.
// Real owner signatures and HTTP against loopback servers; only Prisma is in memory.
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { createFakeBootstrapStore } from './fake-bootstrap-state';
import { FAKE_PEER_ID, startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { originProvisionAuthority } from '../services/provision-authority';

const service = await import('../services/tinycloud-bootstrap?node-hardening' as string) as typeof import('../services/tinycloud-bootstrap');
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const key = { id: 'hardening-key', address: account.address, keyType: 'MANAGED' };
const authority = originProvisionAuthority('https://tinycloud.chat');
const originalEnv = { host: process.env.TINYCLOUD_BOOTSTRAP_HOST, node: process.env.NODE_ENV, on: process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN };
const originalWrite = process.stdout.write;
const NODE_TEXT = 'node-text-7f3a91c2-do-not-store';
const LIMIT = 64 * 1024;

type Handler = (request: Request) => Response | Promise<Response> | undefined;
let override: Handler;
let server: ReturnType<typeof Bun.serve>;
let sink: ReturnType<typeof Bun.serve>;
let sinkRequests: Array<{ method: string; bytes: number }>;
let upstream: FakeTinyCloudNode;
let store: ReturnType<typeof createFakeBootstrapStore>;
let output: string[];

beforeEach(() => {
  sinkRequests = [];
  sink = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(request) {
      sinkRequests.push({ method: request.method, bytes: (await request.arrayBuffer()).byteLength });
      return new Response('{}');
    },
  });
  upstream = startFakeTinyCloudNode();
  override = () => undefined;
  // The node under test answers what a test overrides and forwards the rest to the loopback node.
  server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(request) {
      const custom = override(request);
      if (custom) return custom;
      const { pathname, search } = new URL(request.url);
      return fetch(`${upstream.url}${pathname}${search}`, {
        method: request.method,
        headers: request.headers,
        body: request.method === 'GET' ? undefined : await request.arrayBuffer(),
      });
    },
  });
  store = createFakeBootstrapStore();
  output = [];
  process.stdout.write = ((chunk: string | Uint8Array) => { output.push(String(chunk)); return true; }) as typeof process.stdout.write;
  process.env.NODE_ENV = 'test';
  process.env.TINYCLOUD_BOOTSTRAP_HOST = nodeUrl();
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  service.setTinyCloudBootstrapProbeForTests(async () => {});
  service.setTinyCloudBootstrapExecutorForTests(async () => {});
});
afterEach(() => {
  process.stdout.write = originalWrite;
  server.stop(true);
  sink.stop(true);
  upstream.stop();
  service.setTinyCloudBootstrapProbeForTests();
  service.setTinyCloudBootstrapExecutorForTests();
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_HOST: originalEnv.host, NODE_ENV: originalEnv.node, TINYCLOUD_BOOTSTRAP_ON_SIGN: originalEnv.on })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});

const nodeUrl = () => `http://127.0.0.1:${server.port}`;
const sinkUrl = () => `http://127.0.0.1:${sink.port}/sink`;
const isPeer = (request: Request) => request.method === 'GET' && new URL(request.url).pathname.startsWith('/peer/generate/');
const isDelegate = (request: Request) => request.method === 'POST' && new URL(request.url).pathname === '/delegate';
const redirect = () => new Response(null, { status: 307, headers: { location: sinkUrl() } });

/** Hosts the requested space first: GET /peer/generate, then a signed POST /delegate. */
function run() {
  return service.ensureTinyCloudBootstrap({
    prisma: store.prisma, userId: 'hardening-user', key, privateKey, host: nodeUrl(), authority,
    requestedSpaces: { spaces: ['default'], alreadyHosted: false, nodeReportedUnhosted: true, report: () => {} },
  });
}

describe('TC-4436 node redirects', () => {
  test('a 3xx on the signed POST fails the run and the redirect target receives nothing', async () => {
    override = (request) => (isDelegate(request) ? redirect() : undefined);

    const outcome = await run();

    expect(outcome).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_node_redirect' });
    expect(store.rows[0]).toMatchObject({ status: 'failed', failureCode: 'tinycloud_bootstrap_node_redirect' });
    expect(sinkRequests).toEqual([]);
  });

  test('a 3xx on a GET fails the run and the redirect target receives nothing', async () => {
    override = (request) => (isPeer(request) ? redirect() : undefined);

    expect(await run()).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_node_redirect' });
    expect(sinkRequests).toEqual([]);
  });
});

describe('TC-4436 node response size', () => {
  test('a body that declares more than 64 KiB is refused', async () => {
    override = (request) => (isPeer(request) ? new Response('x'.repeat(LIMIT + 1)) : undefined);

    expect(await run()).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_node_response_too_large' });
    expect(upstream.hostPosts).toEqual([]);
  });

  test('a streamed body with no declared length that crosses 64 KiB is refused', async () => {
    override = (request) => {
      if (!isPeer(request)) return undefined;
      const chunk = new TextEncoder().encode('x'.repeat(16 * 1024));
      let sent = 0;
      return new Response(new ReadableStream({
        pull(controller) {
          if (sent >= 33) { controller.close(); return; }
          sent += 1;
          controller.enqueue(chunk);
        },
      }));
    };

    expect(await run()).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_node_response_too_large' });
  });

  test('response headers over 16 KiB are refused', async () => {
    override = (request) => (isPeer(request)
      ? new Response(FAKE_PEER_ID, { headers: { 'x-pad': 'y'.repeat(20 * 1024) } })
      : undefined);

    expect(await run()).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_node_response_too_large' });
  });

  test('a body within 64 KiB is read', async () => {
    override = (request) => (isPeer(request) ? new Response(FAKE_PEER_ID, { headers: { 'x-pad': 'y'.repeat(1024) } }) : undefined);

    expect(await run()).toEqual({ status: 'complete' });
    expect(upstream.hostPosts).toHaveLength(1);
  });
});

describe('TC-4436 node text', () => {
  test('a refused host delegation stores the status, never the node text', async () => {
    override = (request) => (isDelegate(request) ? new Response(NODE_TEXT, { status: 500 }) : undefined);

    const outcome = await run();

    expect(outcome).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_failed' });
    if (outcome.status !== 'failed') throw new Error('expected a failed outcome');
    expect(outcome.errorMessage).toContain('HTTP 500');
    expect(outcome.errorMessage).not.toContain(NODE_TEXT);
    expect(store.rows[0]?.failureReason).toContain('HTTP 500');
    expect(store.rows[0]?.failureReason).not.toContain(NODE_TEXT);
    expect(output.join('')).not.toContain(NODE_TEXT);
  });

  test('a failed seeding call stores the status, never the node text', async () => {
    service.setTinyCloudBootstrapProbeForTests();
    service.setTinyCloudBootstrapExecutorForTests();
    override = (request) => (new URL(request.url).pathname === '/invoke' ? new Response(NODE_TEXT, { status: 500 }) : undefined);

    const outcome = await service.ensureTinyCloudBootstrap({
      prisma: store.prisma, userId: 'hardening-user', key, privateKey, host: nodeUrl(), authority,
    });

    expect(outcome).toMatchObject({ status: 'failed' });
    if (outcome.status !== 'failed') throw new Error('expected a failed outcome');
    expect(outcome.errorMessage).toContain('HTTP 500');
    expect(outcome.errorMessage).not.toContain(NODE_TEXT);
    expect(store.rows[0]?.failureReason).toContain('HTTP 500');
    expect(store.rows[0]?.failureReason).not.toContain(NODE_TEXT);
    expect(output.join('')).not.toContain(NODE_TEXT);
  });
});
