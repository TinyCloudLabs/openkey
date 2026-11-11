// TC-2234: a share invitation approval request names no key. OpenKey generates the share key id at /prepare and
// signs `key.create` and `decrypt` on that one `default/share/<id>` key, for at most the invitation's acceptance
// window. A requester can never name its own share key, a folder, another key or another owner.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { signerFromJwk } from '@tinycloud/share-envelope/links';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { ApprovalResultService, type ApprovalRequestRecord } from '../services/approval-results';
import { issueAuthorizationContext } from '../services/authorization-signing';
import { parseApprovalRequestV1, type ApprovalRequestV1 } from '../services/share-invitation';
import {
  parsePreparedRecap,
  prepareDelegationSession,
  sessionAbilitiesFromPermissions,
  validatePermissions,
} from '../routes/delegate-session';
import { mockModules, replaceModules } from './mock-module';
import type * as ApprovalRoutes from '../routes/approval-requests';

const home = mkdtempSync('/var/tmp/tc2234-share-invitation-test.');
for (const name of ['HOME', 'TC_HOME', 'COURIER_HOME']) process.env[name] = home;
afterAll(() => rmSync(home, { recursive: true, force: true }));

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const ID = 'abcdefghijklmnopqrstuvwxyz';
const OTHER_ID = 'zyxwvutsrqponmlkjihgfedcba';
const OWNER = { address: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', chainId: 1 };
const OTHER_OWNER = { address: '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', chainId: 1 };
const OWNER_DID = `did:pkh:eip155:1:${OWNER.address}`;
const CREATE = 'tinycloud.encryption/key.create';
const DECRYPT = 'tinycloud.encryption/decrypt';
const HOUR = 3600_000;

const pair = generateKeyPairSync('ed25519');
const publicJwk = pair.publicKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string };
const sessionJwk = { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x };
const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);

const wholeSecond = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString();
const ACCEPT_BY = wholeSecond(Date.now() + HOUR);
/** The share envelope's expiry is the acceptance deadline, as both requesters send it. */
const context = (overrides: Record<string, unknown> = {}) => {
  const acceptanceExpiresAt = overrides.acceptanceExpiresAt ?? ACCEPT_BY;
  return {
    kind: 'share-invitation', version: 1, invitationId: '01JC5Z8Q0000000000000000AB',
    recipientEmail: 'alex@example.test', subjectKind: 'session', subjectName: 'Project notes',
    acceptanceExpiresAt, accessExpiresAt: acceptanceExpiresAt,
    ...overrides,
  };
};
const requestBody = (overrides: Record<string, unknown> = {}) => ({
  issuer: signer.did, requestVersion: 1, targetDid: signer.did,
  targetPublicJwk: sessionJwk,
  nodeOrigin: 'https://node.example.test',
  permissions: [],
  grantLifetimeSeconds: 3600,
  resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y },
  context: context(),
  ...overrides,
});
const parse = (value: unknown, linkExpiresAt = new Date(Date.now() + 2 * HOUR), linkIssuedAt = new Date()) =>
  parseApprovalRequestV1(value, { issuer: signer.did, linkIssuedAt, linkExpiresAt });

let database: PGlite;
let client: PrismaClient;
let routes: typeof ApprovalRoutes;

// The routes load better-auth through the session middleware; these tests call the exported helpers only.
replaceModules({ '../middleware/session': () => ({ requireSession: async () => new Response(null, { status: 401 }) }) });
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => client }) });

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  routes = await import('../routes/approval-requests?share-invitation-approval-test' as string);
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.approvalRequest.deleteMany();
});

const store = () => createPrismaApprovalRequestStore(client);
const register = (request: ApprovalRequestV1, id = ID) => store().register({
  id, bodyCid: `bafkrei${'a'.repeat(52)}`, issuer: signer.did, request,
  expiresAt: new Date(Date.now() + 2 * HOUR), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null,
});
const service = () => new ApprovalResultService(store(), { apiOrigin: 'http://localhost:3001', retentionSeconds: 600 });
const shareKeyUrn = (id: string, owner = OWNER) => `urn:tinycloud:encryption:did:pkh:eip155:${owner.chainId}:${owner.address}:default/share/${id}`;

/** /prepare's view: the body the page sends for an invitation request. */
async function prepare(id = ID, owner = OWNER, extra: Record<string, unknown> = {}) {
  const body: Record<string, unknown> = { approvalRequestId: id, jwk: sessionJwk, host: 'https://node.example.test', ...extra };
  const permissions = await routes.approvalRequestPermissions(body, owner, 'prepare');
  return { body, permissions: permissions! };
}

/** Prepares the SIWE OpenKey binds at /prepare and the token the managed signing path carries. */
async function preparedToken(id = ID, owner = OWNER) {
  const { body, permissions } = await prepare(id, owner);
  const prepared = prepareDelegationSession({
    address: owner.address, chainId: owner.chainId, prefix: 'default', jwk: sessionJwk, permissions, expiryMs: Number(body.expiry),
  });
  const token = issueAuthorizationContext({
    userId: 'owner', keyId: 'key', keyAddress: owner.address, jwk: sessionJwk, host: 'https://node.example.test',
    spaceId: prepared.spaceId, baselineAbilitiesDigest: 'digest', immutableFieldsDigest: 'digest',
    allowedActionIds: new Set(), initialSelectionActionIds: new Set(), expirationTime: new Date(Date.now() + HOUR).toISOString(),
    originalSiwe: prepared.prepared.siwe, approvalRequestId: id,
  }).token;
  return { prepared, permissions, token };
}

describe('the signed request', () => {
  test('names no permissions, and keeps its invitation context', () => {
    const parsed = parse(requestBody());
    expect(parsed.permissions).toEqual([]);
    expect(parsed.context).toEqual(context() as ApprovalRequestV1['context']);
  });

  test.each([
    ['its own share key', [{ service: 'tinycloud.encryption', space: 'encryption', path: shareKeyUrn('0'.repeat(32)), actions: [CREATE, DECRYPT] }]],
    ['the share folder', [{ service: 'tinycloud.encryption', space: 'encryption', path: `urn:tinycloud:encryption:${OWNER_DID}:default/share/`, actions: [DECRYPT] }]],
    ['any other permission', [{ service: 'tinycloud.kv', space: 'default', path: '', actions: ['tinycloud.kv/get'] }]],
  ])('is refused when it also names %s', (_name, permissions) => {
    expect(() => parse(requestBody({ permissions }))).toThrow('names no permissions');
  });

  test('is refused for a grant longer than 24 hours', () => {
    expect(() => parse(requestBody({ grantLifetimeSeconds: 86_401 }))).toThrow('at most 24 hours');
  });

  test('is refused when the invitation can be accepted after its link expires', () => {
    expect(() => parse(requestBody(), new Date(Date.now() + HOUR / 2))).toThrow('before its approval link expires');
  });

  test('is refused when the invitation can be accepted more than 24 hours after its link was issued', () => {
    const issued = new Date(Date.parse(ACCEPT_BY) - 24 * HOUR - 1000);
    expect(() => parse(requestBody(), new Date(Date.now() + 2 * HOUR), issued)).toThrow('within 24 hours');
  });

  test('is refused for a session whose access does not end at the acceptance deadline', () => {
    expect(() => parse(requestBody({ context: context({ accessExpiresAt: wholeSecond(Date.parse(ACCEPT_BY) + 7 * 24 * HOUR) }) })))
      .toThrow('accessExpiresAt must equal acceptanceExpiresAt for a session');
  });

  test.each([
    ['ends with acceptance', 0],
    ['lasts six days past acceptance', 6 * 24 * HOUR],
    ['lasts 90 days past acceptance', 90 * 24 * HOUR],
  ])('keeps the exact access expiry of a file invitation that %s', (_name, extraMs) => {
    const accessExpiresAt = wholeSecond(Date.parse(ACCEPT_BY) + extraMs);
    const parsed = parse(requestBody({ context: context({ subjectKind: 'file', accessExpiresAt }) }));
    expect(parsed.context!.accessExpiresAt).toBe(accessExpiresAt);
    expect(parsed.context!.acceptanceExpiresAt).toBe(ACCEPT_BY);
  });

  test('is refused for a file whose access ends before the acceptance deadline', () => {
    expect(() => parse(requestBody({ context: context({ subjectKind: 'file', accessExpiresAt: wholeSecond(Date.parse(ACCEPT_BY) - 1000) }) })))
      .toThrow('must not be before acceptanceExpiresAt for a file');
  });

  test('keeps a file access at the last second a SIWE timestamp can name, with no cap', () => {
    const parsed = parse(requestBody({ context: context({ subjectKind: 'file', accessExpiresAt: '9999-12-31T23:59:59.000Z' }) }));
    expect(parsed.context!.accessExpiresAt).toBe('9999-12-31T23:59:59.000Z');
  });

  // Every date crosses the wire as a string and is refused unless it is exactly what `toISOString()` writes for a
  // whole second, so nothing is wrapped, shortened or converted through an unsafe number.
  test.each([
    ['a number', 1_800_000_000_000],
    ['an unsafe integer', Number.MAX_SAFE_INTEGER + 2],
    ['a fraction', 1.5],
    ['an extended year past 9999', '+010000-01-01T00:00:00.000Z'],
    ['an extended year at the Date maximum', '+275760-09-13T00:00:00.000Z'],
    ['a negative year', '-000001-01-01T00:00:00.000Z'],
    ['a five-digit year', '10000-01-01T00:00:00.000Z'],
    ['a day that does not exist', '2026-02-30T00:00:00.000Z'],
    ['an hour that does not exist', '2026-11-12T24:00:00.000Z'],
    ['an offset instead of Z', '2026-11-12T00:00:00.000+00:00'],
    ['no milliseconds', '2026-11-12T00:00:00Z'],
    ['free text', 'next Tuesday'],
  ])('refuses a file access expiry given as %s', (_name, accessExpiresAt) => {
    expect(() => parse(requestBody({ context: context({ subjectKind: 'file', accessExpiresAt }) }))).toThrow('accessExpiresAt must be a UTC time in whole seconds');
  });

  test.each([
    ['an unknown field', { shareId: '0'.repeat(32) }],
    ['a recipient that is not canonical', { recipientEmail: 'Alex@Example.test' }],
    ['a subject name with a direction override', { subjectName: 'notes\u202Etxt.exe' }],
    ['a subject name longer than 120 characters', { subjectName: 'x'.repeat(121) }],
    ['a deadline with milliseconds', { acceptanceExpiresAt: new Date(Date.now() + HOUR).toISOString().replace(/\.\d{3}Z$/, '.123Z') }],
    ['an invitation id that is not a ULID', { invitationId: 'not-a-ulid' }],
  ])('is refused for a context with %s', (_name, overrides) => {
    expect(() => parse(requestBody({ context: context(overrides) }))).toThrow();
  });
});

describe('the key OpenKey issues at /prepare', () => {
  test('is a new 32-hex key on the approver\'s own default network, until the acceptance deadline', async () => {
    await register(parse(requestBody()));
    const { body, permissions } = await prepare();
    expect(permissions).toHaveLength(1);
    expect(permissions[0]!.path).toMatch(new RegExp(`^urn:tinycloud:encryption:${OWNER_DID}:default/share/[0-9a-f]{32}$`));
    expect(permissions[0]!.actions).toEqual([CREATE, DECRYPT]);
    expect(body.permissions).toBe(permissions);
    expect(Number(body.expiry)).toBeLessThanOrEqual(Date.parse(ACCEPT_BY) - Date.now());
    const abilities = sessionAbilitiesFromPermissions(permissions, OWNER);
    expect(abilities.rawAbilities).toEqual({ [permissions[0]!.path]: [CREATE, DECRYPT] });
    expect(Object.keys(abilities.spaceAbilities)).toEqual([]);
  });

  test('names the actual approver as owner on any chain', async () => {
    await register(parse(requestBody()));
    const { permissions } = await prepare(ID, { address: OTHER_OWNER.address.toLowerCase(), chainId: 10 });
    expect(permissions[0]!.path).toStartWith(`urn:tinycloud:encryption:did:pkh:eip155:10:${OTHER_OWNER.address}:default/share/`);
  });

  test('is a different key on every /prepare, so a request never names one it saw before', async () => {
    await register(parse(requestBody()));
    const seen = new Set<string>();
    for (let attempt = 0; attempt < 8; attempt++) seen.add((await prepare()).permissions[0]!.path);
    expect(seen.size).toBe(8);
  });

  test('is refused when the page forwards permissions of its own', async () => {
    await register(parse(requestBody()));
    const body = { approvalRequestId: ID, permissions: [{ service: 'tinycloud.encryption', path: shareKeyUrn('0'.repeat(32)), actions: [CREATE, DECRYPT] }] };
    await expect(routes.approvalRequestPermissions(body, OWNER, 'prepare')).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('is refused once the invitation can no longer be accepted', async () => {
    await register(parse(requestBody({ context: context({ acceptanceExpiresAt: wholeSecond(Date.now() + 30_000) }) })));
    await expect(prepare()).rejects.toMatchObject({ code: 'expired_request', status: 410 });
  });

  test.each([
    ['a day before', 24 * HOUR],
    ['an hour before (approved 23 hours in)', HOUR],
  ])('ends at the acceptance deadline %s it, even when the file stays open six days longer', async (_name, untilAcceptance) => {
    const acceptanceExpiresAt = wholeSecond(Date.now() + untilAcceptance);
    const accessExpiresAt = wholeSecond(Date.parse(acceptanceExpiresAt) + 6 * 24 * HOUR);
    await register(parse(requestBody({ grantLifetimeSeconds: 86_400, context: context({ subjectKind: 'file', acceptanceExpiresAt, accessExpiresAt }) }), new Date(Date.now() + 25 * HOUR)));
    const { body } = await prepare();
    expect(Number(body.expiry)).toBeLessThanOrEqual(Date.parse(acceptanceExpiresAt) - Date.now());
    expect(Number(body.expiry)).toBeLessThanOrEqual(24 * HOUR);
  });

  test('is refused after the acceptance deadline, even while the file stays open', async () => {
    const acceptanceExpiresAt = wholeSecond(Date.now() + 30_000);
    await register(parse(requestBody({ context: context({ subjectKind: 'file', acceptanceExpiresAt, accessExpiresAt: wholeSecond(Date.now() + 6 * 24 * HOUR) }) })));
    await expect(prepare()).rejects.toMatchObject({ code: 'expired_request', status: 410 });
  });

  test('cannot be moved to a later access expiry: the stored request keeps its sealed body', async () => {
    await register(parse(requestBody({ context: context({ subjectKind: 'file', accessExpiresAt: wholeSecond(Date.parse(ACCEPT_BY) + 24 * HOUR) }) })));
    const extended = parse(requestBody({ context: context({ subjectKind: 'file', accessExpiresAt: wholeSecond(Date.parse(ACCEPT_BY) + 6 * 24 * HOUR) }) }));
    // A different access expiry is a different sealed body, so a different body CID for the same request id.
    await expect(store().register({
      id: ID, bodyCid: `bafkrei${'b'.repeat(52)}`, issuer: signer.did, request: extended,
      expiresAt: new Date(Date.now() + 2 * HOUR), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null,
    })).rejects.toMatchObject({ code: 'request_binding', status: 409 });
  });

  test('does not apply to a request without an invitation', async () => {
    const { context: _omitted, ...withoutContext } = requestBody({ permissions: [{ service: 'tinycloud.capabilities', space: 'synthetic', path: '', actions: ['tinycloud.capabilities/read'] }] });
    const plain = parse(withoutContext);
    await register(plain);
    expect(await routes.approvalRequestPermissions({ approvalRequestId: ID }, OWNER, 'prepare')).toBeUndefined();
  });

  test('is a new key with its own expiry even when the page sends a token from an earlier /prepare', async () => {
    await register(parse(requestBody()));
    const earlier = await preparedToken();
    const { body, permissions } = await prepare(ID, OWNER, { authorizationContextToken: earlier.token, expiry: '24h' });
    expect(permissions[0]!.path).not.toBe(earlier.permissions[0]!.path);
    expect(Number(body.expiry)).toBeLessThanOrEqual(Date.parse(ACCEPT_BY) - Date.now());
  });

  test('is refused for a declined request, saying it was declined', async () => {
    await register(parse(requestBody()));
    expect(await store().deny(ID, new Date())).toBe(true);
    await expect(prepare()).rejects.toMatchObject({ code: 'expired_request', status: 410, extra: { status: 'denied' } });
  });

  test('cannot be approved with a browser wallet signature', async () => {
    await register(parse(requestBody()));
    await expect(routes.approvalRequestPermissions({ approvalRequestId: ID }, OWNER, 'complete')).rejects.toMatchObject({ code: 'request_binding' });
  });
});

describe('a requester cannot get key.create on a share key it names', () => {
  test.each([
    ['an exact share key', shareKeyUrn('0'.repeat(32)), [CREATE, DECRYPT]],
    ['the share folder', `urn:tinycloud:encryption:${OWNER_DID}:default/share/`, [CREATE, DECRYPT]],
    ['another key', `urn:tinycloud:encryption:${OWNER_DID}:default/notes/x`, [CREATE]],
    ['the whole network', `urn:tinycloud:encryption:${OWNER_DID}:default`, [CREATE]],
  ])('%s', (_name, path, actions) => {
    const permissions = validatePermissions([{ service: 'tinycloud.encryption', path, actions }]);
    expect(() => sessionAbilitiesFromPermissions(permissions, OWNER)).toThrow('decrypt');
  });

  test('an issued key with any other permission beside it is refused', async () => {
    await register(parse(requestBody()));
    const { permissions } = await prepare();
    const extra = validatePermissions([{ service: 'tinycloud.encryption', path: shareKeyUrn('1'.repeat(32)), actions: [DECRYPT] }]);
    expect(() => sessionAbilitiesFromPermissions([...permissions, ...extra], OWNER)).toThrow('one new share key only');
  });

  test('an issued key signed by another account is refused', async () => {
    await register(parse(requestBody()));
    const { permissions } = await prepare();
    expect(() => sessionAbilitiesFromPermissions(permissions, OTHER_OWNER)).toThrow('one new share key only');
  });
});

describe('signing takes the key from the SIWE /prepare bound', () => {
  test('the same key, not a new one', async () => {
    await register(parse(requestBody()));
    const { permissions, token, prepared } = await preparedToken();
    expect(parsePreparedRecap(prepared.prepared.siwe).map((entry) => entry.path)).toEqual([permissions[0]!.path]);
    const signed = await routes.approvalRequestPermissions({ approvalRequestId: ID, authorizationContextToken: token }, OWNER, 'sign');
    expect(signed).toEqual(permissions);
  });

  test('a token prepared for another request is refused', async () => {
    await register(parse(requestBody()));
    await register(parse(requestBody({ context: context({ invitationId: '01JC5Z8Q0000000000000000CD' }) })), OTHER_ID);
    const { token } = await preparedToken(OTHER_ID);
    await expect(routes.approvalRequestPermissions({ approvalRequestId: ID, authorizationContextToken: token }, OWNER, 'sign'))
      .rejects.toMatchObject({ code: 'request_binding' });
  });

  test('a token prepared for another owner is refused', async () => {
    await register(parse(requestBody()));
    const { token } = await preparedToken(ID, OTHER_OWNER);
    await expect(routes.approvalRequestPermissions({ approvalRequestId: ID, authorizationContextToken: token }, OWNER, 'sign'))
      .rejects.toMatchObject({ code: 'request_binding' });
  });

  test('signing without a token is refused', async () => {
    await register(parse(requestBody()));
    await expect(routes.approvalRequestPermissions({ approvalRequestId: ID }, OWNER, 'sign')).rejects.toMatchObject({ code: 'request_binding' });
  });
});

describe('the approval window', () => {
  const window = (permissions: unknown, input: { expiryMs?: number; signedSiwe?: string } = {}) =>
    service().assertDelegationWindow(ID, { jwk: sessionJwk, host: 'https://node.example.test', permissions, ...input });

  test('accepts the issued key until the acceptance deadline', async () => {
    await register(parse(requestBody()));
    const { permissions, prepared } = await preparedToken();
    await expect(window(permissions, { signedSiwe: prepared.prepared.siwe })).resolves.toBeDefined();
  });

  test('the prepared SIWE names its approval request once, as the Request ID', async () => {
    await register(parse(requestBody()));
    const { prepared } = await preparedToken();
    expect(prepared.prepared.siwe.match(/^Request ID: .*$/gm)).toEqual([`Request ID: urn:tinycloud:approval-request:${ID}:bafkrei${'a'.repeat(52)}`]);
  });

  test('refuses an owner-signed approval for another request (X approved as Y)', async () => {
    await register(parse(requestBody()));
    await register(parse(requestBody({ context: context({ invitationId: '01JC5Z8Q0000000000000000CD' }) })), OTHER_ID);
    const other = await preparedToken(OTHER_ID);
    await expect(window(other.permissions, { signedSiwe: other.prepared.prepared.siwe })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('refuses a SIWE for the issued key that names no approval request', async () => {
    await register(parse(requestBody()));
    const { permissions } = await preparedToken();
    const unbound = prepareDelegationSession({
      address: OWNER.address, chainId: OWNER.chainId, prefix: 'default', jwk: sessionJwk, expiryMs: HOUR / 2,
      permissions: validatePermissions([{ service: 'tinycloud.encryption', path: permissions[0]!.path, actions: [DECRYPT] }]),
    });
    expect(unbound.prepared.siwe).not.toContain('Request ID:');
    await expect(window(permissions, { signedSiwe: unbound.prepared.siwe })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test.each([
    ['the right request id with another body CID', (siwe: string) => siwe.replace(`:bafkrei${'a'.repeat(52)}`, `:bafkrei${'b'.repeat(52)}`)],
    ['a second Request ID line', (siwe: string) => siwe.replace(/^(Request ID: .*)$/m, '$1\n$1')],
    ['a malformed Request ID', (siwe: string) => siwe.replace(/^Request ID: .*$/m, 'Request ID: urn:tinycloud:approval-request:')],
  ])('refuses a SIWE with %s', async (_name, change) => {
    await register(parse(requestBody()));
    const { permissions, prepared } = await preparedToken();
    const changed = change(prepared.prepared.siwe);
    expect(changed).not.toBe(prepared.prepared.siwe);
    // A second Request ID line is not a canonical SIWE (`invalid_delegation`); the others name another request.
    await expect(window(permissions, { signedSiwe: changed })).rejects.toMatchObject({ status: 400, code: expect.stringMatching(/^(request_binding|invalid_delegation)$/) });
  });

  test('refuses an approval request binding on a request without an invitation', async () => {
    const plainPermissions = [{ service: 'tinycloud.capabilities', space: 'synthetic', path: '', actions: ['tinycloud.capabilities/read'] }];
    const { context: _omitted, ...withoutContext } = requestBody({ permissions: plainPermissions });
    await register(parse(withoutContext));
    const plain = prepareDelegationSession({
      address: OWNER.address, chainId: OWNER.chainId, prefix: 'default', jwk: sessionJwk, expiryMs: HOUR / 2, permissions: validatePermissions(plainPermissions),
    });
    await expect(window(plainPermissions, { signedSiwe: plain.prepared.siwe })).resolves.toBeDefined();
    const injected = plain.prepared.siwe.replace('\nResources:', `\nRequest ID: urn:tinycloud:approval-request:${ID}:bafkrei${'a'.repeat(52)}\nResources:`);
    await expect(window(plainPermissions, { signedSiwe: injected })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('refuses a delegation that runs past the acceptance deadline', async () => {
    await register(parse(requestBody({ context: context({ acceptanceExpiresAt: wholeSecond(Date.now() + HOUR / 2) }) })));
    const { permissions } = await prepare();
    await expect(window(permissions, { expiryMs: HOUR })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('refuses a SIWE whose signer does not own the key', async () => {
    await register(parse(requestBody()));
    const { permissions } = await preparedToken();
    const { prepared: foreign } = await preparedToken(ID, OTHER_OWNER);
    await expect(window(permissions, { signedSiwe: foreign.prepared.siwe })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('accepts a SIWE the owner narrowed to decrypt on the issued key', async () => {
    await register(parse(requestBody()));
    const { permissions, prepared } = await preparedToken();
    const decryptKey = prepared.permissions[0]!.actions.find((action) => action.ability === DECRYPT)!.key;
    const narrowed = prepareDelegationSession({
      address: OWNER.address, chainId: OWNER.chainId, prefix: 'default', jwk: sessionJwk, permissions, expiryMs: HOUR / 2, actionKeys: [decryptKey],
    });
    expect(parsePreparedRecap(narrowed.prepared.siwe)[0]!.actions).toEqual([DECRYPT]);
    await expect(window(permissions, { signedSiwe: narrowed.prepared.siwe })).resolves.toBeDefined();
  });

  test.each([
    ['another key', () => [{ service: 'tinycloud.encryption', path: shareKeyUrn('1'.repeat(32)), actions: [DECRYPT] }]],
    ['the issued key and another key', (issued: string) => [
      { service: 'tinycloud.encryption', path: issued, actions: [DECRYPT] },
      { service: 'tinycloud.encryption', path: shareKeyUrn('1'.repeat(32)), actions: [DECRYPT] },
    ]],
    ['the issued key and a space', (issued: string) => [
      { service: 'tinycloud.encryption', path: issued, actions: [DECRYPT] },
      { service: 'tinycloud.kv', space: 'default', path: '', actions: ['tinycloud.kv/get'] },
    ]],
  ])('refuses a signed SIWE that grants %s', async (_name, signedPermissions) => {
    await register(parse(requestBody()));
    const { permissions } = await preparedToken();
    const signed = prepareDelegationSession({
      address: OWNER.address, chainId: OWNER.chainId, prefix: 'default', jwk: sessionJwk,
      permissions: validatePermissions(signedPermissions(permissions[0]!.path)), expiryMs: HOUR / 2,
    });
    await expect(window(permissions, { signedSiwe: signed.prepared.siwe })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test.each([
    ['nothing', []],
    ['the share folder', [{ service: 'tinycloud.encryption', path: `urn:tinycloud:encryption:${OWNER_DID}:default/share/`, actions: [CREATE, DECRYPT] }]],
    ['two keys', [
      { service: 'tinycloud.encryption', path: shareKeyUrn('0'.repeat(32)), actions: [CREATE, DECRYPT] },
      { service: 'tinycloud.encryption', path: shareKeyUrn('1'.repeat(32)), actions: [CREATE, DECRYPT] },
    ]],
    ['another ability', [{ service: 'tinycloud.encryption', path: shareKeyUrn('0'.repeat(32)), actions: [CREATE, 'tinycloud.encryption/key.block'] }]],
  ])('refuses %s in place of the issued key', async (_name, permissions) => {
    await register(parse(requestBody()));
    await expect(window(permissions)).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('one approval per request: once approved, another /prepare is refused', async () => {
    await register(parse(requestBody()));
    const now = new Date();
    expect(await store().approve(ID, {
      resultRef: 'synthetic-result-reference', approvedByUserId: 'owner', ownerDid: OWNER_DID, encryptedResult: '{}',
      delegationExpiresAt: new Date(now.getTime() + HOUR / 2), resultExpiresAt: new Date(now.getTime() + 60_000),
    }, now)).toBe(true);
    const { permissions } = await prepare();
    await expect(window(permissions, { expiryMs: 60_000 })).rejects.toMatchObject({ code: 'expired_request', status: 410 });
  });
});

describe('a stored record', () => {
  test('keeps the context the requester signed', async () => {
    const saved = await register(parse(requestBody()));
    expect((saved.request as ApprovalRequestRecord['request'] & { context?: unknown }).context).toEqual(context());
  });
});
