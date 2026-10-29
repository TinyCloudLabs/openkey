// /authorize-sign's final response for raw `urn:tinycloud:encryption:…` resources (TC-1783).
//
// A CLI checks the response against the signed ReCap with sdk-core's
// `parseCanonicalRecapResource`: a resource that does not start with `tinycloud:` is the `space`
// and has no `path`. The response used to report these two resources the way the WASM ReCap parser
// splits them (`space: "encryption"`, `path: <urn>`), so the CLI refused a `--keys` sign-in. Only
// that reporting changed; the signed bytes did not. The fixture file holds what the base code signed
// and answered for the same request, so these tests compare against it instead of against themselves.
import './tc1777-test-env';
import { afterEach, beforeAll, beforeEach, describe, expect, mock, setSystemTime, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import type { setPreparedHandoffServiceForTests } from '../routes/delegate';
// The approval view's own code, loaded by path: it lives in the web app and the
// capability-review package, outside this project's source root.
const loadSource = (relative: string) => import(new URL(relative, import.meta.url).href);
type Selection = { permissions: Array<{ actions: Array<{ id: string; ability: string }> }> };
const { defaultSelection, parseCapabilityReview } = (await loadSource('../../../../packages/capability-review/src/index.ts')) as {
  defaultSelection: (model: Selection) => Set<string>;
  parseCapabilityReview: (input: unknown) => Selection;
};
const { requestedActionIds, selectionFromPreview } = (await loadSource('../../../web/src/lib/widget-selection.ts')) as {
  requestedActionIds: (model: Selection, selection: ReadonlySet<string>) => string[];
  selectionFromPreview: (preview: Record<string, unknown>, requested: readonly string[]) => Set<string>;
};

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ORIGIN = 'https://listen.tinycloud.xyz';
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

const APP_ID = 'xyz.tinycloud.listen';

/** The manifest fetched from the app's origin. */
function declaredManifest() {
  return { name: 'Listen', appId: APP_ID, prefix: APP_ID };
}

let signed: string[] = [];
let manifestBindResult: { ok: boolean; manifest?: Record<string, unknown>; fetchedDigest?: string; reason?: string } = {
  ok: true,
  fetchedDigest: 'a'.repeat(64),
  manifest: declaredManifest(),
};
const fetchAndBindWellKnownManifest = mock(async () => manifestBindResult);

const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

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
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          signed.push(args.message);
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let setHandoffService: typeof setPreparedHandoffServiceForTests;
let createHandoffRouter: typeof import('../routes/prepared-handoffs')['createPreparedHandoffRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];

beforeAll(async () => {
  ({ delegateRouter: router, setPreparedHandoffServiceForTests: setHandoffService } = await import('../routes/delegate?authorize-sign-urn-form' as string));
  ({ createPreparedHandoffRouter: createHandoffRouter } = await import('../routes/prepared-handoffs?authorize-sign-urn-form' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?authorize-sign-urn-form' as string
  ));
});

beforeEach(() => {
  signed = [];
  manifestBindResult = {
    ok: true,
    fetchedDigest: 'a'.repeat(64),
    manifest: declaredManifest(),
  };
  fetchAndBindWellKnownManifest.mockClear();
  resetContexts?.();
});


import { hashMessage } from 'viem';
import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { cliConsumerCheck, extractRecapAttenuations } from './cli-consumer-check';
import { FIXTURE } from './authorize-sign-urn-form.fixture';
import { parseManifestKeys } from '../services/app-key-gate';
import { reportedEntry } from '../routes/delegate-session';

// The request is the CLI's default prepared sign-in (capabilities/read, duckdb, hooks, kv data and
// secrets, sql, the default network's decrypt + network.create) plus the `default/qa/` key row, as a
// literal in the fixture file together with what the base code signed and answered for it.
const RAW_NETWORK = urn('');
const RAW_QA = urn('/qa/');
const SEP = '\0';
const ENCRYPTION = 'tinycloud.encryption';

function post(path: string, body: unknown) {
  return router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

function reviewModel(siwe: string) {
  return parseCapabilityReview({
    message: siwe,
    signer: { label: 'Key', address, chainId: 1, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'listen.tinycloud.xyz', verifiedOrigin: ORIGIN, appId: null, manifestName: null, manifestNameProvenance: 'none',
      manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

type Grant = { service: string; space: string; path: string; actions: readonly string[] };
type Wire = { signedMessage: string; signature: string; selectedActionKeys: string[]; permissions: Grant[] };

/**
 * The CLI's prepared hand-off: a fresh store and service per call, and the ticket the CLI's request claims.
 * A request without a ticket is a website's sign-in, which the route treats differently (TC-2247).
 */
async function claimTicket(siwe: string): Promise<string> {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  setHandoffService(service);
  const ticket = Buffer.alloc(32, 40).toString('base64url');
  const claim = await createHandoffRouter(service).request('/claim', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      transportVersion: 2,
      request: { protocolVersion: 1, siwe, jwk, host: 'https://node.tinycloud.xyz', keyId: keyRecord.id, sessionDid: 'did:key:cli-session' },
      delivery: {
        handoffId: ticket,
        state: Buffer.alloc(32, 41).toString('base64url'),
        cancelSecret: Buffer.alloc(32, 42).toString('base64url'),
      },
    }),
  });
  expect(claim.status, await claim.clone().text()).toBe(201);
  return ticket;
}

/**
 * prepare → preview → authorize-sign, with the ids the signing window sends: every row ticked, minus the
 * actions `untick` names (it sees each action of the review model, as the window's own selection does).
 * `viaTicket` sends the three calls the way the CLI's prepared hand-off does; otherwise they are a website's.
 */
async function run(siwe: string, untick: (action: { id: string; ability: string }) => boolean = () => false, viaTicket = false) {
  const model = reviewModel(siwe);
  const selection = new Set(defaultSelection(model));
  for (const grant of model.permissions) for (const action of grant.actions) if (untick(action)) selection.delete(action.id);
  const requested = requestedActionIds(model, selection);
  const handoff = viaTicket ? { ticket: await claimTicket(siwe) } : {};
  const prepared = await post('/authorize-sign-prepare', viaTicket
    ? { ...handoff, keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz' }
    : {
      keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz', requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
      presentation: { manifestDigest: 'a'.repeat(64), displayName: 'Listen' },
    });
  expect(prepared.status).toBe(200);
  const { authorizationContextToken } = (await prepared.json()) as { authorizationContextToken: string };
  const preview = await post('/authorize-sign-preview', { ...handoff, authorizationContextToken, selectedActionIds: requested });
  expect(preview.status).toBe(200);
  const previewBody = (await preview.json()) as { previewApprovalToken: string; selectedActionKeys: string[]; permissions: Grant[] };
  const signIds = requestedActionIds(model, selectionFromPreview(previewBody, requested));
  const sign = await post('/authorize-sign', { ...handoff, authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken, selectedActionIds: signIds, protocolVersion: 1 });
  expect(sign.status).toBe(200);
  return { requested, previewBody, body: (await sign.json()) as Wire };
}

/** The same flow as the CLI's `--keys` sign-in sends it. */
const runViaCli = (siwe: string, untick?: (action: { id: string; ability: string }) => boolean) => run(siwe, untick, true);

// The fixture's clock: after the request's issuedAt, before its expiry.
beforeEach(() => setSystemTime(new Date('2026-10-26T12:00:30.000Z')));
afterEach(() => setSystemTime());

const ABILITIES_OF_RAW: Array<[resource: string, ability: string]> = [
  [RAW_NETWORK, `${ENCRYPTION}/decrypt`],
  [RAW_NETWORK, `${ENCRYPTION}/network.create`],
  [RAW_QA, `${ENCRYPTION}/decrypt`],
  [RAW_QA, `${ENCRYPTION}/key.create`],
];
/** Every key that changes, old form → consumer form. Nothing else may differ. */
const CHANGED_KEYS = new Map(
  ABILITIES_OF_RAW.map(([resource, ability]) => [
    [ENCRYPTION, 'encryption', resource, ability].join(SEP),
    [ENCRYPTION, resource, '', ability].join(SEP),
  ]),
);
/** Every grant that changes: the reported space/path of the two raw resources. */
const CHANGED_GRANTS: Array<{ old: Grant; now: Grant }> = [
  { resource: RAW_NETWORK, actions: [`${ENCRYPTION}/decrypt`, `${ENCRYPTION}/network.create`] },
  { resource: RAW_QA, actions: [`${ENCRYPTION}/decrypt`, `${ENCRYPTION}/key.create`] },
].map(({ resource, actions }) => ({
  old: { service: ENCRYPTION, space: 'encryption', path: resource, actions },
  now: { service: ENCRYPTION, space: resource, path: '', actions },
}));

const isRaw = (value: string) => value.includes('urn:tinycloud:encryption:');
const asResult = (selectedActionKeys: readonly string[], permissions: readonly Grant[]) => ({
  signedMessage: FIXTURE.signedMessage,
  selectedActionKeys: [...selectedActionKeys],
  permissions: permissions.map((grant) => ({ ...grant, actions: [...grant.actions] })),
});

describe('/authorize-sign reports raw encryption resources in the consumer encoding (TC-1783)', () => {
  test('the signed message, its ReCap, the signature and the digest are identical to the base behaviour', async () => {
    const { body } = await runViaCli(FIXTURE.preparedSiwe);
    // The wallet signed exactly one message, the one the base code signed.
    expect(signed.length).toBe(1);
    expect(signed[0] === FIXTURE.signedMessage).toBe(true);
    expect(FIXTURE.signedMessage === FIXTURE.preparedSiwe).toBe(true);
    expect(body.signedMessage === FIXTURE.signedMessage).toBe(true);
    // What the wallet signs is the EIP-191 digest of that message, and the signature over it.
    expect(hashMessage(signed[0]!)).toBe(FIXTURE.digest);
    expect(body.signature).toBe(FIXTURE.signature);
    // The decoded ReCap resources and abilities, as the consumer decodes them and as the server parses them.
    expect(extractRecapAttenuations(body.signedMessage)).toEqual(extractRecapAttenuations(FIXTURE.signedMessage));
    expect(parseRecapFromSiwe(body.signedMessage)).toEqual(parseRecapFromSiwe(FIXTURE.signedMessage));
  });

  test('only the reported space and path of the two raw encryption resources differ from the base response', async () => {
    const { body } = await runViaCli(FIXTURE.preparedSiwe);
    const oldKeys: readonly string[] = FIXTURE.oldResponse.selectedActionKeys;
    expect(body.selectedActionKeys.length).toBe(oldKeys.length);
    const changed = oldKeys.filter((key, index) => body.selectedActionKeys[index] !== key);
    expect(changed.sort()).toEqual([...CHANGED_KEYS.keys()].sort());
    body.selectedActionKeys.forEach((key, index) => {
      expect(key).toBe(CHANGED_KEYS.get(oldKeys[index]!) ?? oldKeys[index]!);
    });

    const oldGrants = FIXTURE.oldResponse.permissions as readonly Grant[];
    expect(body.permissions.length).toBe(oldGrants.length);
    const changedGrants = oldGrants.filter((grant, index) => JSON.stringify(body.permissions[index]) !== JSON.stringify(grant));
    expect(changedGrants).toEqual(CHANGED_GRANTS.map(({ old }) => old));
    expect(body.permissions.filter((grant) => isRaw(grant.space))).toEqual(CHANGED_GRANTS.map(({ now }) => now));
  });

  test('capabilities, duckdb, hooks, kv and sql entries are deep-equal before and after', async () => {
    const { body } = await runViaCli(FIXTURE.preparedSiwe);
    const keep = (keys: readonly string[]) => keys.filter((key) => !isRaw(key));
    const oldKeys = keep(FIXTURE.oldResponse.selectedActionKeys);
    expect(keep(body.selectedActionKeys)).toEqual(oldKeys);
    const oldGrants = (FIXTURE.oldResponse.permissions as readonly Grant[]).filter((grant) => !isRaw(grant.space + grant.path));
    expect(body.permissions.filter((grant) => !isRaw(grant.space + grant.path))).toEqual(oldGrants);
    // The rows the request is made of are all there.
    expect(new Set(oldGrants.map((grant) => grant.service))).toEqual(
      new Set(['tinycloud.capabilities', 'tinycloud.duckdb', 'tinycloud.hooks', 'tinycloud.kv', 'tinycloud.sql']),
    );
    expect(oldGrants.filter((grant) => grant.service === 'tinycloud.kv').map((grant) => grant.path)).toEqual(['', 'secrets/']);
  });

  test('the CLI consumer check accepts the response for every row', async () => {
    const { body } = await runViaCli(FIXTURE.preparedSiwe);
    expect(body.selectedActionKeys.length).toBe(31);
    expect(() => cliConsumerCheck(FIXTURE.preparedSiwe, body)).not.toThrow();
  });

  test('the same check rejects the base response, which is the mismatch this fixes', () => {
    const base = asResult(FIXTURE.oldResponse.selectedActionKeys, FIXTURE.oldResponse.permissions as readonly Grant[]);
    expect(() => cliConsumerCheck(FIXTURE.preparedSiwe, base)).toThrow(
      `OpenKey selectedActionKeys entry ${[ENCRYPTION, 'encryption', RAW_NETWORK, `${ENCRYPTION}/decrypt`].join(SEP)} is not covered by any granted capability`,
    );
    // Fixing only the keys is not enough: the grants carry the same encoding.
    const keysOnly = asResult(
      FIXTURE.oldResponse.selectedActionKeys.map((key) => CHANGED_KEYS.get(key) ?? key),
      FIXTURE.oldResponse.permissions as readonly Grant[],
    );
    expect(() => cliConsumerCheck(FIXTURE.preparedSiwe, keysOnly)).toThrow(/carries a path on a non-tinycloud: resource URI/);
  });

  test('the preview and the ids the window sends keep the server form', async () => {
    const { requested, previewBody } = await runViaCli(FIXTURE.preparedSiwe);
    expect(previewBody.selectedActionKeys).toEqual([...FIXTURE.previewSelectedActionKeys]);
    expect(previewBody.permissions).toEqual(FIXTURE.previewPermissions as unknown as Grant[]);
    for (const [resource, ability] of ABILITIES_OF_RAW) {
      expect(requested).toContain([ENCRYPTION, 'encryption', resource, ability].join(SEP));
    }
  });
});

// ---- follow-ups (TC-1783): a narrowed selection, an `apps/<keys_app_id>/` key row, and the reshaping rule ----

const isUnticked = ([, , path, ability]: string[]) =>
  (path === RAW_QA && ability === `${ENCRYPTION}/key.create`) ||
  (path === RAW_NETWORK && ability === `${ENCRYPTION}/network.create`) ||
  (path === 'secrets/' && ability === 'tinycloud.kv/del');

describe('/authorize-sign with a narrowed selection (TC-1783)', () => {
  test('reports only the ticked abilities, and raw encryption resources still in the consumer encoding', async () => {
    // The user unticks key.create in the qa/ row, network.create in the default network row, and kv/del on secrets/.
    const { body } = await runViaCli(FIXTURE.preparedSiwe, ({ id, ability }) => {
      const parts = id.split(SEP);
      return (parts.includes(RAW_QA) && ability === `${ENCRYPTION}/key.create`) ||
        (parts.includes(RAW_NETWORK) && ability === `${ENCRYPTION}/network.create`) ||
        (parts.includes('secrets/') && ability === 'tinycloud.kv/del');
    });

    const oldKeys: readonly string[] = FIXTURE.oldResponse.selectedActionKeys;
    const kept = oldKeys.filter((key) => !isUnticked(key.split(SEP)));
    expect(oldKeys.length - kept.length).toBe(3);
    expect(body.selectedActionKeys).toEqual(kept.map((key) => CHANGED_KEYS.get(key) ?? key));

    const raw = body.permissions.filter((grant) => isRaw(grant.space));
    expect(raw).toEqual([
      { service: ENCRYPTION, space: RAW_NETWORK, path: '', actions: [`${ENCRYPTION}/decrypt`] },
      { service: ENCRYPTION, space: RAW_QA, path: '', actions: [`${ENCRYPTION}/decrypt`] },
    ]);
    expect(body.permissions.some((grant) => isRaw(grant.path))).toBe(false);
    const secrets = body.permissions.find((grant) => grant.service === 'tinycloud.kv' && grant.path === 'secrets/');
    expect(secrets?.actions).toEqual(['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put']);
    expect(body.permissions.filter((grant) => !isRaw(grant.space) && !(grant.service === 'tinycloud.kv' && grant.path === 'secrets/')))
      .toEqual((FIXTURE.oldResponse.permissions as readonly Grant[]).filter((grant) => !isRaw(grant.path) && !(grant.service === 'tinycloud.kv' && grant.path === 'secrets/')));

    // What was signed is the narrowed ReCap, and the consumer accepts it against the request it prepared.
    expect(signed).toEqual([body.signedMessage]);
    expect(body.signedMessage === FIXTURE.preparedSiwe).toBe(false);
    const caps = extractRecapAttenuations(body.signedMessage);
    expect(Object.keys(caps[RAW_QA]!)).toEqual([`${ENCRYPTION}/decrypt`]);
    expect(Object.keys(caps[RAW_NETWORK]!)).toEqual([`${ENCRYPTION}/decrypt`]);
    expect(() => cliConsumerCheck(FIXTURE.preparedSiwe, body)).not.toThrow();
  });
});

describe('/authorize-sign for an apps/<keys_app_id>/ key row (TC-1783)', () => {
  const DATA_ID = 'dev.pages.okqa-dev';
  const KEYS_ID = APP_ID; // the key namespace is host-bound to listen.tinycloud.xyz; the data app id is another
  const APPS_PREFIX = urn(`/apps/${KEYS_ID}/`);
  const KV = ['tinycloud.kv/get', 'tinycloud.kv/put'];

  test('is reported as the urn with no path, and the signed message is byte-identical to the prepared one', async () => {
    manifestBindResult = {
      ok: true,
      fetchedDigest: 'a'.repeat(64),
      manifest: {
        ...declaredManifest(),
        appId: DATA_ID,
        declaredAppId: DATA_ID,
        declaredKeysAppId: KEYS_ID,
        declaredKeys: parseManifestKeys(KEYS_ID, [{ prefix: `apps/${KEYS_ID}/`, abilities: ['key.create', 'decrypt'] }]),
      },
    };
    const now = new Date();
    const siwe = prepareSession({
      address, chainId: 1, domain: 'listen.tinycloud.xyz', issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(), spaceId: SPACE, jwk,
      abilities: { kv: { '': KV } } as never,
      rawAbilities: { [APPS_PREFIX]: [`${ENCRYPTION}/key.create`, `${ENCRYPTION}/decrypt`] },
    }).siwe;

    const { body } = await run(siwe);

    // Byte-identical: the wallet signed the prepared message, and the response echoes it.
    expect(signed.length).toBe(1);
    expect(signed[0] === siwe).toBe(true);
    expect(body.signedMessage === siwe).toBe(true);
    expect(hashMessage(signed[0]!)).toBe(hashMessage(siwe));
    expect(Object.keys(extractRecapAttenuations(body.signedMessage)).sort()).toEqual([APPS_PREFIX, `${SPACE}/kv`].sort());

    expect(body.selectedActionKeys.filter((key) => isRaw(key)).sort()).toEqual(
      [`${ENCRYPTION}/decrypt`, `${ENCRYPTION}/key.create`].map((ability) => [ENCRYPTION, APPS_PREFIX, '', ability].join(SEP)).sort(),
    );
    expect(body.selectedActionKeys.some((key) => key.includes(`${SEP}encryption${SEP}`))).toBe(false);
    const raw = body.permissions.filter((grant) => isRaw(grant.space));
    expect(raw.map((grant) => ({ ...grant, actions: [...grant.actions].sort() }))).toEqual([
      { service: ENCRYPTION, space: APPS_PREFIX, path: '', actions: [`${ENCRYPTION}/decrypt`, `${ENCRYPTION}/key.create`] },
    ]);
    expect(body.permissions.some((grant) => isRaw(grant.path))).toBe(false);
    // The kv entry beside it is as the parser reports it.
    expect(body.permissions.filter((grant) => !isRaw(grant.space)).map((grant) => grant.service)).toEqual(['tinycloud.kv']);
    expect(() => cliConsumerCheck(siwe, body)).not.toThrow();
  });
});

describe('which entries are reshaped for the consumer', () => {
  test('a raw encryption entry as the ReCap parser splits it is, and nothing else changes in it', () => {
    const entry = { service: 'encryption', space: 'encryption', path: RAW_QA, actions: [`${ENCRYPTION}/decrypt`] };
    expect(reportedEntry(entry)).toEqual({ service: 'encryption', space: RAW_QA, path: '', actions: [`${ENCRYPTION}/decrypt`] });
  });

  test('an entry whose path merely starts with the same text is not reshaped unless its space is encryption', () => {
    const lookalikes = [
      { service: 'kv', space: SPACE, path: RAW_NETWORK, actions: ['tinycloud.kv/get'] },
      { service: 'kv', space: 'other', path: RAW_NETWORK, actions: ['tinycloud.kv/get'] },
      { service: 'encryption', space: '', path: RAW_NETWORK, actions: [`${ENCRYPTION}/decrypt`] },
    ];
    for (const entry of lookalikes) expect(reportedEntry(entry)).toBe(entry);
  });

  test('an encryption entry whose path is not a raw encryption urn is not reshaped', () => {
    const entry = { service: 'encryption', space: 'encryption', path: 'secrets/k', actions: [`${ENCRYPTION}/decrypt`] };
    expect(reportedEntry(entry)).toBe(entry);
  });
});
