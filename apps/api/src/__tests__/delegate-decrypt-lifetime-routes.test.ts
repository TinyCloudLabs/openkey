// TC-1781: decrypt lifetime cap on non-device `/delegate` transports, behind two
// independent flags. DECRYPT_STEPUP_ADMIT admits a lone own-network decrypt with
// an explicit lifetime of at most one hour. DECRYPT_LIFETIME_ENFORCE_NON_DEVICE
// refuses a decrypt entry that is not alone or has no explicit lifetime of at
// most one hour, before any signing or side effect. Both off keeps existing
// behaviour.

import { afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { buildStatements, DECRYPT_DEFAULT_KEY_STATEMENT, parseCapabilityReview } from '@openkey/capability-review';
import type { ParseContext } from '@openkey/capability-review';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { decryptRefusalForSignedSiwe, prepareDelegationSession } from '../routes/delegate-session';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { sessionDidForPublicJwk } from '../services/device-authorization';
import { mockModules, replaceModules } from './mock-module';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const keyBase = { userId: user.id, address: wallet.address, archivedAt: null, sealingContext: null };
const managedKey = { ...keyBase, id: 'key_managed', keyType: 'MANAGED', sealedBlob: 'sealed-blob' };
const externalKey = { ...keyBase, id: 'key_ext', keyType: 'EXTERNAL', sealedBlob: null };
const keys = [managedKey, externalKey];

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id?: string } }) => keys.find((key) => key.id === where.id) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => managedKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
  deviceAuthorization: {
    findUnique: mock(async ({ where }: { where: { id?: string } }) => (where.id === deviceTransactionRow.id ? deviceTransactionRow : null)),
  },
};
const activateSessionWithHost = mock(async () => ({ success: true }));

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
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => wallet.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});
await mockModules({
  // This file asserts the device-transaction opt-in exclusion; the window check
  // has its own tests. Stubbed here because a module-level service it loads is
  // replaced by other route tests, and bun caches that binding across files.
  '../routes/device-delegation-window': () => ({ deviceDelegationWindowError: async () => null }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let refusalFor: typeof decryptRefusalForSignedSiwe;
let prepareDelegation: typeof prepareDelegationSession;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (with an isolating query) so the route binds
  // the mocked database, TEE, and host activation.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?decrypt-lifetime-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?decrypt-lifetime-routes-isolated' as string
  ));
  ({ decryptRefusalForSignedSiwe: refusalFor } = await import(
    '../routes/delegate-session?decrypt-lifetime-routes-isolated' as string
  ));
  ({ prepareDelegationSession: prepareDelegation } = await import(
    '../routes/delegate-session?decrypt-lifetime-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

const FLAG = 'DECRYPT_LIFETIME_ENFORCE_NON_DEVICE';
const ADMIT = 'DECRYPT_STEPUP_ADMIT';
const REFUSAL = 'a decrypt approval lasts at most one hour';
const SINGLE_SPACE = 'permissions must belong to a single space';
let savedFlag: string | undefined;
let savedAdmit: string | undefined;

function setFlag(value: string | undefined) {
  if (value === undefined) delete process.env[FLAG];
  else process.env[FLAG] = value;
}

function setAdmit(value: string | undefined) {
  if (value === undefined) delete process.env[ADMIT];
  else process.env[ADMIT] = value;
}

beforeEach(() => {
  savedFlag = process.env[FLAG];
  savedAdmit = process.env[ADMIT];
  setFlag(undefined);
  setAdmit(undefined);
  resetContexts?.();
  activateSessionWithHost.mockClear();
});

afterEach(() => {
  setFlag(savedFlag);
  setAdmit(savedAdmit);
});

const space = `tinycloud:pkh:eip155:1:${wallet.address}:secrets`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const kvGet = { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: ['tinycloud.kv/get'] };
const decrypt = { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT] };
const capabilitiesRead = { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] };
// The CLI shape that carries a decrypt grant: decrypt is one entry among others.
const request = [kvGet, decrypt, capabilitiesRead];
const decryptOnly = [decrypt];
// A pending device transaction whose window admits a one-hour decrypt, so the
// device-window check passes and only the lone-decrypt opt-in differs.
const deviceTransactionRow = {
  id: 'dt_1',
  status: 'PENDING',
  sessionDid: sessionDidForPublicJwk(jwk),
  nodeOrigin: host,
  permissions: decryptOnly,
  transactionExpiresAt: new Date(Date.now() + 10 * 60_000),
  delegationExpiresAt: new Date(Date.now() + 10 * 60_000 + 3600_000),
};
// Session-bundle shape: decrypt and network.create in one entry.
const bundledDecrypt = [
  { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT, 'tinycloud.encryption/network.create'] },
];
const relayedDecrypt = { service: 'encryption', space: 'encryption', path: network, actions: [DECRYPT] };
const noDecrypt = [kvGet, capabilitiesRead];

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** Seconds from now until the Expiration Time of a prepared SIWE message. */
function expiresInSeconds(siwe: string): number {
  const match = siwe.match(/Expiration Time: (.+)/);
  return (Date.parse(match?.[1] ?? '') - Date.now()) / 1000;
}

/** The `/complete` body the web's external-wallet path sends. */
async function walletComplete(prepared: Record<string, any>, permissions: unknown[]) {
  return post('/complete', {
    prepared: prepared.prepared,
    signature: await wallet.signMessage({ message: prepared.prepared.siwe }),
    host,
    jwk,
    edited: prepared.edited,
    permissions,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  });
}

/** Versioned managed approval for a prepared request. */
async function managedApprove(prepared: Record<string, any>, permissions: unknown[]) {
  return post('/', {
    keyId: managedKey.id,
    jwk,
    host,
    permissions,
    prepared: prepared.prepared,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
    protocolVersion: 1,
  });
}

describe('flag OFF: non-device behaviour unchanged', () => {
  test('legacy approval signs a request carrying a decrypt grant at the 7-day default', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(res.status).toBe(200);
  });

  test('versioned approval signs a request carrying a decrypt grant at the 7-day default', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);
    expect(expiresInSeconds(prepared.body.prepared.siwe)).toBeGreaterThan(6 * 24 * 3600);
    const res = await managedApprove(prepared.body, request);
    expect(res.status).toBe(200);
  });

  test('wallet /prepare + /complete relays the decrypt grant at the 7-day default', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);
    const res = await walletComplete(prepared.body, request);
    expect(res.status).toBe(200);
    expect(res.body.permissions).toContainEqual(relayedDecrypt);
  });

  test('a non-canonical flag value leaves the cap off', async () => {
    setFlag('yes');
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(res.status).toBe(200);
  });

  test('with the flag off, a decrypt-only request is rejected by the single-space rule', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });
});

describe('flag ON: refusal before any side effect', () => {
  beforeEach(() => {
    setFlag('true');
  });

  test('legacy approval refuses a decrypt-only grant at the 7-day default with the fixed message', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(res.body.code).toBe('invalid_request');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('legacy approval refuses a decrypt-only grant over one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '61m' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  test('legacy approval refuses decrypt beside other entries, even at one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('legacy approval refuses a decrypt and network.create entry in one bundle at one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: bundledDecrypt, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  test('legacy approval without decrypt is unchanged at the 7-day default', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: noDecrypt });
    expect(res.status).toBe(200);
  });

  test('/prepare refuses a decrypt-only grant at the 7-day default and returns no prepared session', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(res.body.prepared).toBeUndefined();
  });

  test('/prepare refuses a request carrying decrypt beside other entries', async () => {
    const res = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  test('/prepare without decrypt is unchanged at the 7-day default', async () => {
    const res = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: noDecrypt });
    expect(res.status).toBe(200);
  });

  test('/complete refuses a decrypt grant prepared while the flag was off, before activation', async () => {
    setFlag(undefined);
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);

    setFlag('true');
    const res = await walletComplete(prepared.body, request);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('versioned approval refuses a grant prepared while the flag was off, and the context is not consumed', async () => {
    setFlag(undefined);
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);

    setFlag('true');
    const refused = await managedApprove(prepared.body, request);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    setFlag(undefined);
    const retried = await managedApprove(prepared.body, request);
    expect(retried.status).toBe(200);
  });
});

describe('authorize-sign transports: decrypt refusal', () => {
  // The SIWE is produced flag-off through /prepare, then sent to the
  // authorize-sign routes with the flag on or switched on mid-flow.
  const authorizeBody = (prepared: Record<string, any>) => ({
    keyId: managedKey.id,
    jwk,
    host,
    requestOrigin: 'https://cli.tinycloud.xyz',
    siwe: prepared.prepared.siwe,
  });

  test('/authorize-sign-prepare refuses a decrypt SIWE at the 7-day default while the flag is on', async () => {
    setFlag(undefined);
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    expect(prepared.status).toBe(200);

    setFlag('true');
    const res = await post('/authorize-sign-prepare', authorizeBody(prepared.body));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(res.body.code).toBe('invalid_request');
  });

  test('/authorize-sign refuses a decrypt grant when the flag is switched on after its preview', async () => {
    setFlag(undefined);
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: request });
    const context = await post('/authorize-sign-prepare', authorizeBody(prepared.body));
    expect(context.status).toBe(200);
    const selectedActionIds = context.body.allowedActionIds;
    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken: context.body.authorizationContextToken,
      selectedActionIds,
    });
    expect(preview.status).toBe(200);

    setFlag('true');
    const res = await post('/authorize-sign', {
      authorizationContextToken: context.body.authorizationContextToken,
      previewApprovalToken: preview.body.previewApprovalToken,
      selectedActionIds,
      protocolVersion: 1,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });
});

const PREFIX_REFUSAL = 'permissions[0].path must use the lowercase urn:tinycloud:encryption: prefix';

describe('uppercase URN prefix and lowercase address on the lone decrypt', () => {
  const upperPrefixNetwork = `URN:${network.slice('urn:'.length)}`;
  const lowerAddressNetwork = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address.toLowerCase()}:default`;

  test('flag ON: legacy approval refuses an uppercase URN prefix with the prefix message', async () => {
    setFlag('true');
    setAdmit('true');
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: [{ ...decrypt, path: upperPrefixNetwork }], expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(PREFIX_REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('flag ON: enforce alone refuses /prepare with an uppercase URN prefix', async () => {
    setFlag('true');
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: [{ ...decrypt, path: upperPrefixNetwork }], expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(PREFIX_REFUSAL);
    expect(res.body.prepared).toBeUndefined();
  });

  test('flag OFF: an uppercase URN prefix does not get the prefix message', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: [{ ...decrypt, path: upperPrefixNetwork }], expiry: '1h' });
    expect(res.body.error).not.toBe(PREFIX_REFUSAL);
  });

  test('flag ON: the lone decrypt on a lowercase address signs the checksummed own default network', async () => {
    setFlag('true');
    setAdmit('true');
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: [{ ...decrypt, path: lowerAddressNetwork }], expiry: '1h' });
    expect(prepared.status).toBe(200);
    expect(prepared.body.prepared.siwe).toContain(ownDefaultNetwork);
    expect(prepared.body.prepared.siwe).not.toContain(lowerAddressNetwork);
  });

  test('flag OFF: the lowercase-address lone decrypt is not admitted', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: [{ ...decrypt, path: lowerAddressNetwork }], expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });
});

describe('decryptRefusalForSignedSiwe', () => {
  const siweWith = (resources: string) =>
    [
      'openkey.test wants you to sign in with your Ethereum account:',
      wallet.address,
      '',
      'Authorize',
      '',
      'URI: https://openkey.test',
      'Version: 1',
      'Chain ID: 1',
      'Nonce: abc',
      'Issued At: 2030-01-01T00:00:00.000Z',
      'Expiration Time: 2030-01-01T00:30:00.000Z',
      'Resources:',
      resources,
    ].join('\n');

  test('refuses a recap resource that cannot be parsed while the flag is on', () => {
    setFlag('true');
    expect(refusalFor(siweWith('- urn:recap:!!!not-a-recap!!!'))?.error).toBe(REFUSAL);
  });

  test('passes ordinary text that mentions decrypt but carries no recap', () => {
    setFlag('true');
    expect(refusalFor('Please decrypt the vault for the team.')).toBeNull();
  });

  test('passes a SIWE whose resources carry no urn:recap entry while the flag is on', () => {
    setFlag('true');
    expect(refusalFor(siweWith('- https://example.test/resource'))).toBeNull();
  });

  test('passes a SIWE with an unparseable resource line that has no urn:recap while the flag is on', () => {
    setFlag('true');
    expect(refusalFor(siweWith('- !!!not-a-recap!!!'))).toBeNull();
  });

  test('returns null for an unparseable recap while the flag is off', () => {
    setFlag(undefined);
    expect(refusalFor(siweWith('- urn:recap:!!!not-a-recap!!!'))).toBeNull();
  });

  test('refuses an uppercase URN:RECAP: resource that cannot be parsed while the flag is on', () => {
    setFlag('true');
    expect(refusalFor(siweWith('- URN:RECAP:!!!not-a-recap!!!'))?.error).toBe(REFUSAL);
  });

  test('returns null for an uppercase unparseable recap while the flag is off', () => {
    setFlag(undefined);
    expect(refusalFor(siweWith('- URN:RECAP:!!!not-a-recap!!!'))).toBeNull();
  });
});

const OTHER_NETWORK = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x000000000000000000000000000000000000dEaD:default';
const NAMED_NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:named`;
const ownDefaultSpace = `tinycloud:pkh:eip155:1:${wallet.address}:default`;
const ownDefaultNetwork = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;

describe('both flags ON: lone own-network decrypt is admitted at one hour', () => {
  beforeEach(() => {
    setFlag('true');
    setAdmit('true');
  });

  test('legacy approval signs the lone own-network decrypt at one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(200);
  });

  test('/prepare prepares the lone decrypt on the own default network, expiring within one hour', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(prepared.status).toBe(200);
    expect(prepared.body.prepared.siwe).toContain(ownDefaultNetwork);
    const remaining = expiresInSeconds(prepared.body.prepared.siwe);
    expect(remaining).toBeGreaterThan(3500);
    expect(remaining).toBeLessThanOrEqual(3600);
  });

  test('/prepare shows the lone own-network decrypt with only the default-key consent statement', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(prepared.status).toBe(200);
    const context: ParseContext = {
      message: prepared.body.prepared.siwe,
      signer: { label: 'Test signer', address: wallet.address, chainId: 1, provenance: 'managed' },
      editable: true,
      metadataTrust: { status: 'unsigned', reason: 'no manifest' },
      reason: { text: '', source: 'none' },
      requester: {
        displayName: 'cli.tinycloud.xyz',
        verifiedOrigin: 'https://cli.tinycloud.xyz',
        appId: null,
        manifestName: null,
        manifestNameProvenance: 'none',
        manifestId: null,
        manifestIdProvenance: 'none',
        manifestDigest: null,
        domainWarning: false,
        originWarning: false,
      },
      requesterAddress: null,
      requesterVerified: false,
    };
    const statements = parseCapabilityReview(context)
      .permissions.flatMap((permission) => buildStatements(permission))
      .map((row) => row.primaryText);
    expect(statements).toEqual([DECRYPT_DEFAULT_KEY_STATEMENT]);
  });

  test('wallet /prepare and /complete approve the lone decrypt at one hour', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(prepared.status).toBe(200);
    const res = await walletComplete(prepared.body, decryptOnly);
    expect(res.status).toBe(200);
  });

  test('/prepare refuses the lone decrypt at 3601 seconds with the fixed message', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '3601s' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(res.body.prepared).toBeUndefined();
  });

  test('legacy approval refuses the lone decrypt at 3601 seconds before activation', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '3601s' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('a lone decrypt on another network keeps the single-space refusal at one hour', async () => {
    const permissions = [{ ...decrypt, path: OTHER_NETWORK }];
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('a lone decrypt on a named key keeps the single-space refusal at one hour', async () => {
    const permissions = [{ ...decrypt, path: NAMED_NETWORK }];
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('a device transaction does not admit the lone own-network decrypt', async () => {
    const res = await post('/prepare', {
      keyId: managedKey.id,
      jwk,
      host,
      permissions: decryptOnly,
      expiry: '1h',
      deviceTransactionId: 'dt_1',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('a device transaction on the legacy approval does not admit the lone own-network decrypt', async () => {
    const res = await post('/', {
      keyId: managedKey.id,
      jwk,
      host,
      permissions: decryptOnly,
      expiry: '1h',
      deviceTransactionId: 'dt_1',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('both flags OFF keep the lone own-network decrypt on the single-space refusal', async () => {
    setFlag(undefined);
    setAdmit(undefined);
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });
});

describe('admit ON, enforce OFF: lone own-network decrypt admitted; other requests unchanged', () => {
  beforeEach(() => {
    setAdmit('true');
  });

  test('legacy approval signs the lone own-network decrypt at an explicit one hour', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(200);
  });

  test('/prepare admits the lone decrypt at an explicit 3600 seconds on the own default network', async () => {
    const prepared = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '3600s' });
    expect(prepared.status).toBe(200);
    expect(prepared.body.prepared.siwe).toContain(ownDefaultNetwork);
  });

  test('wallet /prepare and /complete approve the lone decrypt at one hour', async () => {
    const prepared = await post('/prepare', { keyId: externalKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(prepared.status).toBe(200);
    const res = await walletComplete(prepared.body, decryptOnly);
    expect(res.status).toBe(200);
  });

  test('the lone decrypt at 3601 seconds keeps the single-space refusal before activation', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '3601s' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('the lone decrypt with no explicit expiry keeps the single-space refusal', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
    expect(res.body.prepared).toBeUndefined();
  });

  test('a device transaction does not admit the lone own-network decrypt', async () => {
    const res = await post('/prepare', {
      keyId: managedKey.id,
      jwk,
      host,
      permissions: decryptOnly,
      expiry: '1h',
      deviceTransactionId: 'dt_1',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('a lone decrypt on a named key keeps the single-space refusal at one hour', async () => {
    const permissions = [{ ...decrypt, path: NAMED_NETWORK }];
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('a bundled decrypt with network.create is not admitted and keeps the single-space refusal', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: bundledDecrypt });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
  });

  test('decrypt beside other entries signs at one hour without the cap', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: request, expiry: '1h' });
    expect(res.status).toBe(200);
  });
});

describe('admit OFF, enforce ON: lone own-network decrypt refused', () => {
  beforeEach(() => {
    setFlag('true');
  });

  test('legacy approval refuses the lone decrypt at one hour with the single-space rule', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('/prepare refuses the lone decrypt at one hour and returns no prepared session', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '1h' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(SINGLE_SPACE);
    expect(res.body.prepared).toBeUndefined();
  });

  test('the lone decrypt at 3601 seconds keeps the fixed refusal', async () => {
    const res = await post('/prepare', { keyId: managedKey.id, jwk, host, permissions: decryptOnly, expiry: '3601s' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
  });

  test('the lone decrypt at the 7-day default keeps the fixed refusal', async () => {
    const res = await post('/', { keyId: managedKey.id, jwk, host, permissions: decryptOnly });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(REFUSAL);
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});

describe('prepareDelegationSession: lone own-network decrypt admission', () => {
  const input = { address: wallet.address, chainId: 1, prefix: 'applications', jwk, expiryMs: 3600_000 };

  test('admits the lone own-network decrypt on the default space when opted in', () => {
    const result = prepareDelegation({ ...input, permissions: decryptOnly, loneOwnDefaultDecrypt: true });
    expect(result.spaceId).toBe(ownDefaultSpace);
  });

  test('admits the own network when the path is lowercased', () => {
    const permissions = [{ ...decrypt, path: decrypt.path.toLowerCase() }];
    const result = prepareDelegation({ ...input, permissions, loneOwnDefaultDecrypt: true });
    expect(result.spaceId).toBe(ownDefaultSpace);
  });

  test('keeps the single-space refusal without the opt-in', () => {
    expect(() => prepareDelegation({ ...input, permissions: decryptOnly })).toThrow(SINGLE_SPACE);
  });

  test('does not admit a decrypt beside another entry, keeping the entry space', () => {
    const result = prepareDelegation({ ...input, permissions: [decrypt, kvGet], loneOwnDefaultDecrypt: true });
    expect(result.spaceId).toBe(space);
  });

  test('keeps the single-space refusal for a decrypt with an extra action', () => {
    const permissions = [{ ...decrypt, actions: [DECRYPT, 'tinycloud.encryption/network.create'] }];
    expect(() => prepareDelegation({ ...input, permissions, loneOwnDefaultDecrypt: true })).toThrow(SINGLE_SPACE);
  });

  test('keeps the single-space refusal for another network', () => {
    const permissions = [{ ...decrypt, path: OTHER_NETWORK }];
    expect(() => prepareDelegation({ ...input, permissions, loneOwnDefaultDecrypt: true })).toThrow(SINGLE_SPACE);
  });

  test('keeps the single-space refusal for a raw entry in another space', () => {
    const permissions = [{ ...decrypt, space: 'secrets' }];
    expect(() => prepareDelegation({ ...input, permissions, loneOwnDefaultDecrypt: true })).toThrow(SINGLE_SPACE);
  });
});
