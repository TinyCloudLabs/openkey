// P1: POST /api/keys/:id/sign sets the signer's own space up only when the request is from a first-party app. The
// asker is the widget's `requestOrigin`, and it counts only when the SIWE named exactly that origin: a raw body field
// alone never makes a request first-party. Real keys route, real bootstrap, real WASM and a loopback node.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage, prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';
import { escapedHostSpellings, withRawRecap } from './space-host-recap';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};
const spaceId = (name: string, owner: string = account.address) => `tinycloud:pkh:eip155:1:${owner}:${name}`;
const SPACES = ['default', 'applications', 'account', 'secrets', 'public', 'agents'];
const THIRD_PARTY = 'https://app.example.test';
const FIRST_PARTY = 'https://home.tinycloud.xyz';

interface StateRow {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
  failureCode?: string | null;
  failureReason?: string | null;
  checkedAt?: Date;
}
let state: StateRow | null = null;
let autoSignEnabled = true;
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled })) },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => (state ? { ...state } : null)),
    create: mock(async ({ data }: { data: Omit<StateRow, 'id'> }) => {
      if (state) throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
      state = { ...data, id: 'state_1' };
      return state;
    }),
    updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<StateRow> }) => {
      if (!state || (where.attemptId && where.attemptId !== state.attemptId)) return { count: 0 };
      // Lock acquisition (the only caller that sends an OR) only wins a free or expired lock.
      if (where.OR && state.status === 'in_progress' && state.lockExpiresAt && state.lockExpiresAt > new Date()) {
        return { count: 0 };
      }
      state = { ...state, ...data };
      return { count: 1 };
    }),
  },
};

// What happened, in order: the node hosting a space, and the key signing.
let events: string[] = [];
// The message the test asked the key to sign: the bootstrap signs its own host delegations with the same key.
let appMessage = "";
const unseal = mock(async () => privateKey);

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    seal: mock(async () => 'sealed-private-key'),
    unseal,
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        address: wallet.address,
        signMessage: async (args: { message: string }) => {
          events.push(args.message === appMessage ? 'sign' : 'sign:host');
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let keysRouter: { request: (path: string, init?: RequestInit) => Promise<Response> };
let node: FakeTinyCloudNode;
const logLines: Array<{ event: string; level?: string; error_code?: string }> = [];
const originalWrite = process.stdout.write;
const ENV = [
  'TINYCLOUD_BOOTSTRAP_HOST',
  'TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS',
  'TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS',
  'TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS',
  'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS',
  'TINYCLOUD_BOOTSTRAP_ON_SIGN',
] as const;
const savedEnv = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

beforeAll(async () => {
  // Imported after mock.module (and with an isolating query) so the route binds the mocked database and TEE.
  ({ keysRouter } = await import('../routes/keys?provision-authority-keys-isolated' as string));
});

beforeEach(() => {
  node = startFakeTinyCloudNode();
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  state = null;
  autoSignEnabled = true;
  events = [];
  logLines.length = 0;
  unseal.mockClear();
  prisma.user.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.create.mockClear();
  process.stdout.write = ((chunk: string | Uint8Array) => {
    for (const line of String(chunk).split('\n')) {
      if (line.startsWith('{')) logLines.push(JSON.parse(line));
    }
    return true;
  }) as typeof process.stdout.write;
  // The fake node reports each host delegation it applies; the order against the signature is what matters.
  node.beforeHost = async (id) => { events.push(`host:${id.slice(id.lastIndexOf(':') + 1)}`); };
});

afterEach(async () => {
  // The setup a request leaves running in the background must end before its node stops, or its
  // failure would be logged into the next test.
  await until(
    () => !state || state.status !== 'in_progress' || state.attemptId === 'someone-else',
    'the background setup to settle',
  );
  process.stdout.write = originalWrite;
  node.stop();
});

afterAll(() => {
  for (const name of ENV) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

/** The SDK's sign-in for `address` to one space: `abilities` are the service -> path -> actions in it. */
function siweFor(options: {
  space: string;
  address?: string;
  abilities?: Record<string, Record<string, string[]>>;
  expiresInMs?: number;
  domain?: string;
  rawAbilities?: Record<string, string[]>;
}) {
  return prepareSession({
    address: options.address ?? account.address,
    chainId: 1,
    domain: options.domain ?? 'app.example.test',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + (options.expiresInMs ?? 3_600_000)).toISOString(),
    spaceId: options.space,
    jwk,
    abilities: options.abilities ?? { kv: { 'data/': ['tinycloud.kv/get', 'tinycloud.kv/put'] } },
    ...(options.rawAbilities ? { rawAbilities: options.rawAbilities } : {}),
  } as never).siwe;
}

const applicationsOnly = () => siweFor({ space: spaceId('applications') });
const accountSignIn = () => siweFor({
  space: spaceId('account'),
  abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
});

interface SignBody {
  signature?: string;
  address?: string;
  tinycloudBootstrap?: { status: string; errorCode?: string };
}

async function sign(message: string, extra: Record<string, unknown> = {}) {
  appMessage = message;
  const response = await keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, requestOrigin: THIRD_PARTY, ...extra }),
  });
  return { status: response.status, body: (await response.json()) as SignBody };
}

// Real clock on purpose: the node timeouts and the lock wait are AbortSignal.timeout and setTimeout
// against a real loopback server; fake timers would not move them.
async function until(condition: () => boolean, what: string, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await Bun.sleep(10);
  }
}

const hostPostsFor = (name: string) => node.hostPosts.filter((post) => post.spaceId === spaceId(name));
const errorLogs = () => logLines.filter((line) => line.level === 'error');


const firstPartySiwe = () => siweFor({ space: spaceId('applications'), domain: 'home.tinycloud.xyz' });

function expectNothingSetUp() {
  expect(node.peerGets).toEqual([]);
  expect(node.hostPosts).toEqual([]);
  expect(node.sessionPosts).toEqual([]);
  expect(node.invokes).toBe(0);
  expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
  expect(state).toBeNull();
}

describe('the signer\'s own space is set up only for a first-party app', () => {
  test('an app from another site is signed for and nothing is set up on the node', async () => {
    const signed = await sign(applicationsOnly());

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expectNothingSetUp();
  });

  test('an app of TinyCloud is signed for and its space is hosted first', async () => {
    const signed = await sign(firstPartySiwe(), { requestOrigin: FIRST_PARTY });

    expect(signed.status).toBe(200);
    expect(signed.body.tinycloudBootstrap).toEqual({ status: 'hosted' });
    expect(node.hosted.has(spaceId('applications'))).toBe(true);
    await until(() => state?.status === 'complete', 'the background setup to complete');
  });

  test('a raw body origin that is first-party does not make a third-party request first-party', async () => {
    // The SIWE is a third-party app's own; only the request body says TinyCloud.
    const signed = await sign(applicationsOnly(), { requestOrigin: FIRST_PARTY });

    expect(signed.status).toBe(403);
    expect(signed.body.signature).toBeUndefined();
    expectNothingSetUp();
  });

  test('a first-party origin on a message that is not a TinyCloud sign-in sets nothing up', async () => {
    const signed = await sign('Sign in to the app', { requestOrigin: FIRST_PARTY });

    expect(signed.status).toBe(200);
    expectNothingSetUp();
  });

  test('a request with no origin at all sets nothing up', async () => {
    const response = await keysRouter.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
      body: JSON.stringify({ message: firstPartySiwe() }),
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expectNothingSetUp();
  });

  test('a spelling of a first-party origin that is not exactly the origin is third-party', async () => {
    for (const requestOrigin of [`${FIRST_PARTY}.evil.example`, `${FIRST_PARTY}/`, FIRST_PARTY.toUpperCase()]) {
      const signed = await sign(firstPartySiwe(), { requestOrigin });
      expect(signed.body.tinycloudBootstrap?.status).not.toBe('hosted');
    }
    expectNothingSetUp();
  });
});

// A signature on a space host message is the ability to create the space on the node, so a site that holds the signed
// bytes could submit them itself. Hosting the owner's primary space is what creates the account: only TinyCloud's own
// apps get that signature. Another site gets its own non-primary spaces hosted only once the owner's primary space is
// known to be hosted: a stored bootstrap row that is complete. Every target is read from the ReCap.
describe('a space host message from an app of another site', () => {
  const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const OTHER_OWNER = privateKeyToAccount('0x1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
  const hostSiwe = (name: string, options: { domain?: string; owner?: string } = {}) => generateHostSIWEMessage({
    address: account.address,
    chainId: 1,
    domain: options.domain ?? 'app.example.test',
    issuedAt: new Date().toISOString(),
    spaceId: spaceId(name, options.owner),
    peerId: PEER,
  });
  /** The same message with its ReCap (and the statement the recap parser checks against it) replaced by `att`. */
  const withRecap = (message: string, att: Record<string, Record<string, unknown[]>>) => {
    const lines = Object.entries(att).sort(([a], [b]) => a.localeCompare(b)).flatMap(([resource, abilities]) =>
      Object.keys(abilities).sort().map((ability) => `'${ability.slice(0, ability.indexOf('/'))}': '${ability.slice(ability.indexOf('/') + 1)}' for '${resource}'`));
    const statement = `I further authorize the stated URI to perform the following actions on my behalf: ${lines.map((line, i) => `(${i + 1}) ${line}.`).join(' ')}`;
    const recap = `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;
    return message.replace(/I further authorize[^\n]*/, statement).replace(/urn:recap:[A-Za-z0-9_-]+/, recap);
  };
  const HOST = 'tinycloud.space/host';
  const asHex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;
  const hostedPrimary = () => { state = { id: 'state_1', status: 'complete', attemptId: null, lockExpiresAt: null, checkedAt: new Date() }; };
  const forms = (message: string) => [message, asHex(message)];

  async function expectRefused(message: string, extra: Record<string, unknown> = {}) {
    for (const form of forms(message)) {
      const signed = await sign(form, extra);
      expect(signed.status).toBe(403);
      expect(signed.body).toMatchObject({ code: 'host_signing_first_party_only' });
      expect(signed.body.signature).toBeUndefined();
    }
    expect(unseal).not.toHaveBeenCalled();
    expect(events).toEqual([]);
    expect(node.hostPosts).toEqual([]);
  }

  /** Refused by this rule or, for a message the earlier SIWE checks already reject, by them: never a signature. */
  async function expectNotSigned(message: string) {
    for (const form of forms(message)) {
      const signed = await sign(form);
      expect([400, 403]).toContain(signed.status);
      expect(signed.body.signature).toBeUndefined();
    }
    expect(unseal).not.toHaveBeenCalled();
    expect(events).toEqual([]);
    expect(node.hostPosts).toEqual([]);
  }

  async function expectSigned(message: string) {
    for (const form of forms(message)) {
      const signed = await sign(form);
      expect(signed.status).toBe(200);
      expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    }
    expect(node.hostPosts).toEqual([]);
  }

  test('is signed for the primary space when it is hosted and refused when it is not', async () => {
    await expectRefused(hostSiwe('default'));
    hostedPrimary();
    await expectSigned(hostSiwe('default'));
    await expectSigned(hostSiwe('DEFAULT'));
  });

  test('is refused for a non-primary space while the primary space is not known to be hosted', async () => {
    // No row.
    await expectRefused(hostSiwe('public'));
    // Rows that are not done.
    for (const status of ['pending', 'in_progress', 'failed']) {
      state = { id: 'state_1', status, attemptId: null, lockExpiresAt: null, checkedAt: new Date() };
      await expectRefused(hostSiwe('public'));
    }
    // A lookup that errors is unknown, not hosted.
    state = { id: 'state_1', status: 'complete', attemptId: null, lockExpiresAt: null, checkedAt: new Date() };
    prisma.tinyCloudBootstrapState.findUnique.mockImplementationOnce(async () => { throw new Error('database unavailable'); });
    expect((await sign(hostSiwe('public'))).status).toBe(403);
    expect(unseal).not.toHaveBeenCalled();
  });

  test('is signed for a non-primary space once the primary space is hosted', async () => {
    hostedPrimary();
    await expectSigned(hostSiwe('public'));
    await expectSigned(hostSiwe('some-registry-space'));
  });

  test('is signed for a mix of the owner\'s own spaces when the primary space is hosted and refused when it is not', async () => {
    const message = withRecap(hostSiwe('public'), {
      [`${spaceId('public')}/space`]: { [HOST]: [{}] },
      [`${spaceId('default')}/space`]: { [HOST]: [{}] },
    });
    await expectRefused(message);
    hostedPrimary();
    await expectSigned(message);
  });

  test('is refused for a mix of the owner\'s primary space and another owner\'s space', async () => {
    hostedPrimary();
    await expectRefused(withRecap(hostSiwe('public'), {
      [`${spaceId('default')}/space`]: { [HOST]: [{}] },
      [`${spaceId('public', OTHER_OWNER)}/space`]: { [HOST]: [{}] },
    }));
  });

  test('is refused for a wildcard or space-agnostic host ability, and for a ReCap it cannot read', async () => {
    hostedPrimary();
    await expectRefused(withRecap(hostSiwe('public'), { [`${spaceId('public')}/space`]: { 'tinycloud.space/*': [{}] } }));
    await expectRefused(withRecap(hostSiwe('public'), { [`${spaceId('public')}/space`]: { [HOST]: [{}], 'tinycloud.space/other': [{}] } }));
    await expectRefused(withRecap(hostSiwe('public'), { 'tinycloud:pkh:eip155:1:*:public/space': { [HOST]: [{}] } }));
    await expectRefused(withRecap(hostSiwe('public'), { '*': { [HOST]: [{}] } }));
    // Names a space ability, but is not a ReCap the parser reads.
    const unreadable = hostSiwe('public').replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(`not json ${HOST}`).toString('base64url')}`);
    for (const form of forms(unreadable)) {
      // The message check that runs first may already refuse it as malformed; either way there is no signature.
      const signed = await sign(form);
      expect([400, 403]).toContain(signed.status);
      expect(signed.body.signature).toBeUndefined();
    }
    expect(unseal).not.toHaveBeenCalled();
  });

  // The node reads the ReCap with a JSON parser that decodes escapes; so does the decision, and it is the same parser.
  test('is signed for the primary space however the ability or the space id is spelled when it is hosted and refused when it is not', async () => {
    // The primary space's name spelled with a unicode escape.
    const escapedName = `{"att":{"${spaceId('d\\u0065fault')}/space":{"tinycloud.space/host":[{}]}},"prf":[]}`;
    for (const hosted of [false, true]) {
      state = null;
      if (hosted) hostedPrimary();
      for (const { json } of [...escapedHostSpellings(`${spaceId('default')}/space`), { json: escapedName }]) {
        const message = withRawRecap(hostSiwe('default'), json, `${spaceId('default')}/space`);
        if (hosted) await expectSigned(message); else await expectRefused(message);
      }
    }
  });

  test('is refused for an ability in another case, a repeated key, or base64 that is not base64url', async () => {
    hostedPrimary();
    const resource = `${spaceId('public')}/space`;
    await expectNotSigned(withRawRecap(hostSiwe('public'), `{"att":{"${resource}":{"TINYCLOUD.SPACE/HOST":[{}]}},"prf":[]}`, resource, 'TINYCLOUD.SPACE/HOST'));
    await expectNotSigned(withRawRecap(hostSiwe('public'), `{"att":{"${resource}":{"tinycloud.space/host":[{}]},"${resource}":{"tinycloud.kv/get":[{}]}},"prf":[]}`, resource));
    // Padded base64: the JSON is padded with spaces to a length that needs `=`.
    let json = `{"att":{"${resource}":{"tinycloud.space/host":[{}]}},"prf":[]}`;
    while (json.length % 3 !== 1) json += ' ';
    const message = withRawRecap(hostSiwe('public'), json, resource);
    const encoded = Buffer.from(json).toString('base64url');
    expect(message).toContain(encoded);
    await expectNotSigned(message.replace(encoded, Buffer.from(json).toString('base64')));
  });

  test('is signed for a non-primary space spelled with escapes once the primary space is hosted', async () => {
    hostedPrimary();
    for (const { json } of escapedHostSpellings(`${spaceId('public')}/space`)) {
      await expectSigned(withRawRecap(hostSiwe('public'), json, `${spaceId('public')}/space`));
    }
  });

  test('is refused for a space whose owner is not the key\'s owner', async () => {
    hostedPrimary();
    await expectRefused(hostSiwe('public', { owner: OTHER_OWNER }));
  });

  test('is signed for a first-party app whatever it names', async () => {
    for (const name of ['default', 'public']) {
      const signed = await sign(hostSiwe(name, { domain: 'home.tinycloud.xyz' }), { requestOrigin: FIRST_PARTY });
      expect(signed.status).toBe(200);
      expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    }
  });

  test('a first-party origin named only in the body does not unlock it', async () => {
    const signed = await sign(hostSiwe('default'), { requestOrigin: FIRST_PARTY });

    expect(signed.status).toBe(403);
    expect(signed.body.signature).toBeUndefined();
    expect(unseal).not.toHaveBeenCalled();
  });

  test('a message with no space ability is signed as before', async () => {
    expect((await sign(applicationsOnly())).status).toBe(200);
  });
});
