// TC-3443: a delegate request that names no permissions gets only its own
// folder, `applications/<app id>/`, for 7 days: the same set the SDK's generic
// manifest asks for. It goes through normal approval; Auto-Sign never signs it.

import { readFileSync } from 'node:fs';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { makeSpaceId, prepareSession } from '@tinycloud/node-sdk-wasm';
import { BOOTSTRAP_SESSION_REQUESTS, bootstrapSpaceId } from '@tinycloud/bootstrap';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import {
  genericAppId,
  ownFolderPermissions,
  parsePreparedRecap,
  prepareDelegationSession,
  type RecapEntry,
} from '../routes/delegate-session';
import { mockModules, replaceModules } from './mock-module';

// Generated from the SDK (js-sdk sdk-core `owner-access.ts` genericAppId /
// genericAppManifest, resolved with the standard tier in `manifest.ts`). When
// the SDK changes that set, regenerate the file and change OpenKey with it.
const sdk = JSON.parse(readFileSync(new URL('./generic-app-manifest-vectors.json', import.meta.url), 'utf8')) as {
  vectors: Array<{
    host: string | null;
    appId: string;
    space: string;
    resources: Array<{ service: string; space: string; path: string; actions: string[] }>;
    expiryMs: number;
    includePublicSpace: boolean;
  }>;
};

// The same file, byte for byte, as js-sdk `packages/sdk-core/src/generic-app-id.vectors.json`;
// `sha256sum` of the two must match.
const sharedAppIds = JSON.parse(readFileSync(new URL('./generic-app-id.vectors.json', import.meta.url), 'utf8')) as Array<{
  host: string | null;
  appId: string;
}>;

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const chainId = 1;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED' as const,
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const signedMessages: string[] = [];
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true, passkeyApprovalMode: 'NEVER' })) },
  passkey: { count: mock(async () => 0) },
  appSignInDay: {
    upsert: mock(async (_args: unknown): Promise<unknown> => null),
    deleteMany: mock(async (_args: unknown): Promise<unknown> => null),
  },
  tinyCloudBootstrapState: {},
};
const activateSessionWithHost = mock(async () => ({ success: true, status: 200, activated: [], skipped: [] }));

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
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          signedMessages.push(args.message);
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrap: mock(async () => ({ status: 'complete' as const })),
    isTinyCloudBootstrapComplete: mock(async () => true),
  }),
  '../routes/approval-requests': () => ({
    admitApprovalDelegation: async () => {},
    checkApprovalDelegation: async () => {},
    bindApprovalRenewal: async () => undefined,
    confirmBoundRenewal: () => {},
    releaseApprovalDelegation: async () => {},
    saveApprovalDelegation: async (_body: unknown, _userId: string, delegation: Record<string, unknown>) => delegation,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  // Imported after mock.module (with an isolating query) so the route binds the mocks above.
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?own-folder-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?own-folder-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  resetContexts?.();
  activateSessionWithHost.mockClear();
  signedMessages.length = 0;
});

async function post(path: string, body: Record<string, unknown>, headers: Record<string, string> = {}) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function prepare(extra: Record<string, unknown> = {}) {
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host, ...extra });
  expect(prepared.status).toBe(200);
  return prepared.body;
}

/** The SDK's resources as the recap entries a signed SIWE carries for `account`. */
function sdkEntries(appId: string): RecapEntry[] {
  const vector = sdk.vectors.find((candidate) => candidate.appId === appId)!;
  return vector.resources.map((resource) => ({
    service: resource.service.slice('tinycloud.'.length),
    space: makeSpaceId(account.address, chainId, resource.space),
    path: resource.path,
    actions: resource.actions,
  }));
}

function sorted(entries: RecapEntry[]) {
  const key = (entry: RecapEntry) => `${entry.space}\0${entry.service}\0${entry.path}`;
  return entries
    .map((entry) => ({ service: entry.service, space: entry.space, path: entry.path, actions: [...entry.actions].sort() }))
    .sort((a, b) => key(a).localeCompare(key(b)));
}

function lifetimeMs(siwe: string) {
  const issued = /^Issued At: (.+)$/m.exec(siwe)![1]!;
  const expires = /^Expiration Time: (.+)$/m.exec(siwe)![1]!;
  return Date.parse(expires) - Date.parse(issued);
}

describe('the own folder equals the SDK generic manifest', () => {
  test('genericAppId matches the SDK for every pinned host', () => {
    for (const vector of sdk.vectors) expect(genericAppId(vector.host)).toBe(vector.appId);
  });

  test('genericAppId matches every row of the app id file shared with the js-sdk', () => {
    for (const vector of sharedAppIds) expect(genericAppId(vector.host)).toBe(vector.appId);
  });

  test('the shared app id file pins the same hosts and app ids as the manifest fixture', () => {
    expect(sharedAppIds).toEqual(sdk.vectors.map(({ host, appId }) => ({ host, appId })));
  });

  test('ownFolderPermissions is byte-for-byte the SDK resource set, with no public space and 7 days', () => {
    for (const vector of sdk.vectors) {
      expect(vector.space).toBe('applications');
      expect(vector.includePublicSpace).toBe(false);
      expect(vector.expiryMs).toBe(SEVEN_DAYS_MS);
      expect(JSON.stringify(ownFolderPermissions(vector.host ?? ''))).toBe(JSON.stringify(vector.resources));
    }
  });
});

describe('a request that names no permissions', () => {
  test('/prepare grants only the own folder of the requester origin, for 7 days', async () => {
    const prepared = await prepare({ requesterOrigin: 'https://notes.example.com' });
    const siwe = prepared.prepared.siwe as string;
    expect(siwe.startsWith('notes.example.com wants you to sign in')).toBe(true);
    expect(sorted(parsePreparedRecap(siwe))).toEqual(sorted(sdkEntries('com.example.notes')));
    expect(lifetimeMs(siwe)).toBe(SEVEN_DAYS_MS);
    expect(prepared.ownFolderOnly).toBe(true);
    expect(prepared.ownFolderShared).toBe(false);
    expect(prepared.spaceId).toBe(makeSpaceId(account.address, chainId, 'applications'));
  });

  test('/prepare with a port in the origin names the folder with the port', async () => {
    const prepared = await prepare({ requesterOrigin: 'http://localhost:5173' });
    const folder = 'localhost_5173/';
    expect(sorted(parsePreparedRecap(prepared.prepared.siwe))).toEqual(sorted(sdkEntries('com.example.notes').map((entry) => (
      entry.path ? { ...entry, path: folder } : entry
    ))));
    expect(prepared.ownFolderShared).toBe(false);
  });

  test('/prepare without a requester origin uses the default domain', async () => {
    const prepared = await prepare();
    const siwe = prepared.prepared.siwe as string;
    const folder = 'xyz.tinycloud.cli/';
    expect(sorted(parsePreparedRecap(siwe))).toEqual(sorted(sdkEntries('com.example.notes').map((entry) => (
      entry.path ? { ...entry, path: folder } : entry
    ))));
    expect(lifetimeMs(siwe)).toBe(SEVEN_DAYS_MS);
    expect(prepared.ownFolderOnly).toBe(true);
    expect(prepared.ownFolderShared).toBe(true);
  });

  test('/prepare for an origin whose host is not a DNS name gets its own o_ folder', async () => {
    const prepared = await prepare({ requesterOrigin: 'http://[::1]:5173' });
    const folder = 'o_fd7fe9743eb5dc81/';
    expect(sorted(parsePreparedRecap(prepared.prepared.siwe))).toEqual(sorted(sdkEntries('com.example.notes').map((entry) => (
      entry.path ? { ...entry, path: folder } : entry
    ))));
    expect(prepared.ownFolderShared).toBe(false);
  });

  test('approving it signs the prepared own-folder bytes', async () => {
    const prepared = await prepare({ requesterOrigin: 'https://notes.example.com' });
    const res = await post('/', {
      keyId: keyRecord.id,
      jwk,
      host,
      prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status).toBe(200);
    expect(signedMessages).toEqual([prepared.prepared.siwe]);
  });

  test('/complete accepts the own-folder SIWE a wallet signed', async () => {
    const prepared = await prepare({ requesterOrigin: 'https://notes.example.com' });
    const siwe = prepared.prepared.siwe as string;
    const res = await post('/complete', {
      prepared: prepared.prepared,
      signature: await account.signMessage({ message: siwe }),
      host,
      jwk,
      edited: false,
      protocolVersion: 1,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
    });
    expect(res.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('/complete refuses a SIWE on the whole default space, which the old default allowed', async () => {
    const wholeDefault = prepareDelegationSession({
      address: account.address,
      chainId,
      prefix: 'default',
      jwk,
      expiryMs: SEVEN_DAYS_MS,
      permissions: [{ service: 'tinycloud.kv', space: 'default', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] }],
    });
    const siwe = wholeDefault.prepared.siwe;
    const res = await post('/complete', {
      prepared: { ...wholeDefault.prepared, siwe },
      signature: await account.signMessage({ message: siwe }),
      host,
      jwk,
    });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('invalid_permissions');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});

describe('a request that names its permissions', () => {
  const requested = [
    { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
    { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
  ];

  test('/prepare grants exactly what it asked for and shows no own-folder line', async () => {
    const prepared = await prepare({ permissions: requested, requesterOrigin: 'https://notes.example.com' });
    const space = makeSpaceId(account.address, chainId, 'default');
    expect(sorted(parsePreparedRecap(prepared.prepared.siwe))).toEqual(sorted([
      { service: 'kv', space, path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
      { service: 'capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
    ]));
    expect(prepared.ownFolderOnly).toBe(false);
    expect(prepared.ownFolderShared).toBe(false);
  });
});

describe('Auto-Sign', () => {
  async function autoSign(message: string) {
    return post('/sign', { address: account.address, chainId, message, type: 'siwe', keyId: keyRecord.id }, {
      origin: 'https://notes.example.com',
    });
  }

  test('does not sign an own-folder request; it goes to approval', async () => {
    const { prepared } = prepareDelegationSession({
      address: account.address,
      chainId,
      prefix: 'default',
      jwk,
      expiryMs: SEVEN_DAYS_MS,
      domain: 'notes.example.com',
    });
    const res = await autoSign(prepared.siwe);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ approved: false, needsApproval: true, code: 'outside_bootstrap_allowlist' });
    expect(signedMessages).toEqual([]);
  });

  test('still signs the applications bootstrap session, so the refusal above is the scope', async () => {
    const spaceId = bootstrapSpaceId(account.address, chainId, 'applications');
    const abilities: Record<string, Record<string, string[]>> = {};
    for (const resource of BOOTSTRAP_SESSION_REQUESTS.applications.resources) {
      const service = resource.service.slice('tinycloud.'.length);
      (abilities[service] ??= {})[resource.path] = [...resource.actions];
    }
    const { siwe } = prepareSession({
      address: account.address,
      chainId,
      domain: 'notes.example.com',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
      spaceId,
      jwk,
      abilities,
    });
    const res = await autoSign(siwe);
    expect(res.body).toMatchObject({ approved: true });
    expect(signedMessages).toEqual([siwe]);
  });
});
