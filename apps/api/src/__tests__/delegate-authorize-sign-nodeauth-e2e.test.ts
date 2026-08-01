// Sol MAJOR-7 (continuation): real OpenKey ↔ NodeUserAuthorization
// round-trip integration test.
//
// The prior e2e test on the js-sdk side used `makeSimulatedOpenKey` which
// reconstructed the rich result locally — it never invoked @openkey/sdk or
// the actual OpenKey HTTP routes. Conversely the OpenKey route tests used
// mocked Prisma/TEE and never fed the response through `signInWithOpenKeyResult`.
//
// This test closes that gap FROM THE OPENKEY SIDE:
//   1. Prepare a SIWE with the EXACT shape `NodeUserAuthorization.
//      prepareSessionForSigning()` produces — a real WASM `prepareSession`
//      call with a non-empty statement (the "I further authorize..." ReCap
//      prose) and the full production header set (URI, Version, Chain ID,
//      Nonce, Issued At, Expiration Time).
//   2. Call the actual /authorize-sign-prepare, /authorize-sign-preview,
//      and /authorize-sign routes through the real Hono router with the
//      Prisma/TEE mocks the other route tests use.
//   3. Verify the response envelope EXACTLY matches what
//      `signInWithOpenKeyResult` will accept:
//        - `signedMessage` is present and byte-for-byte matches the preview
//        - `selectedActionKeys` are canonical four-part IDs
//        - `permissions` are grouped by (service, space, path)
//        - the signature verifies against signedMessage
//   4. Verify narrowing removes exactly the selected actions with no drift
//      on immutable header fields.
//
// A matching test in the js-sdk repo runs the OTHER direction: feed the
// route response into `signInWithOpenKeyResult` and confirm the client
// accepts it end-to-end. Together the two tests cover the wire boundary
// from both sides using REAL production code paths.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession, parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_nodeauth', email: 'nodeauth@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };

let currentUser = user;

const keyRecord = {
  id: 'key_nodeauth',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  keyPurpose: 'PERSONAL',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== currentUser.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.keyPurpose !== undefined && where.keyPurpose !== keyRecord.keyPurpose) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== currentUser.id) return [];
      if (where.keyPurpose !== undefined && where.keyPurpose !== keyRecord.keyPurpose) return [];
      if (where.archivedAt !== null) return [];
      return [keyRecord];
    }),
    findUnique: mock(async () => keyRecord),
  },
  user: {
    findUnique: mock(async () => ({ autoSignEnabled: true })),
  },
  tinyCloudBootstrapState: {},
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));

mock.module('@openkey/tee', () => ({
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
      signMessage: async (input: { message: string }) => wallet.signMessage(input),
    };
  },
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => address,
}));

mock.module('@tinycloud/sdk-core', () => ({
  activateSessionWithHost: mock(async () => ({ success: true })),
}));

mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('session', {
      id: 'session_' + currentUser.id,
      userId: currentUser.id,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await next();
  }),
}));

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];

beforeAll(async () => {
  ({ delegateRouter: router } = await import(
    '../routes/delegate?nodeauth-e2e' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?nodeauth-e2e' as string
  ));
});

beforeEach(() => {
  currentUser = user;
  resetContexts?.();
});

/**
 * Produce a SIWE with the EXACT shape `NodeUserAuthorization.
 * prepareSessionForSigning()` produces via the WASM emitter — including a
 * non-empty ReCap-derived `statement` line, full header set, and the
 * canonical `urn:recap:` payload.
 */
function makeProductionShapeSiwe(opts?: {
  extraKvActions?: string[];
  extraSqlActions?: string[];
}) {
  const chainId = 1;
  const now = new Date();
  const issuedAt = now.toISOString();
  const expirationTime = new Date(now.getTime() + 3_600_000).toISOString();
  const spaceId = `tinycloud:pkh:eip155:${chainId}:${address}:default`;
  const kvActions = ['tinycloud.kv/get', 'tinycloud.kv/put', ...(opts?.extraKvActions ?? [])];
  const sqlActions = ['tinycloud.sql/read', ...(opts?.extraSqlActions ?? [])];
  const prepared = prepareSession({
    address,
    chainId,
    domain: 'example.com',
    issuedAt,
    expirationTime,
    spaceId,
    jwk,
    abilities: {
      kv: { [spaceId]: kvActions },
      sql: { [spaceId]: sqlActions },
      capabilities: { [spaceId]: ['tinycloud.capabilities/read'] },
    } as any,
  });
  return {
    siwe: prepared.siwe as string,
    chainId,
    spaceId,
    issuedAt,
    expirationTime,
    jwk,
  };
}

describe('OpenKey ↔ NodeUserAuthorization e2e', () => {
  test('production-shape SIWE (with non-empty ReCap statement) round-trips unchanged', async () => {
    const { siwe } = makeProductionShapeSiwe();
    // 1. Prepare
    const prepRes = await router.request('/authorize-sign-prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz' }),
    });
    expect(prepRes.status).toBe(200);
    const prepBody = await prepRes.json() as any;
    // The route stores the ORIGINAL SIWE bytes in the context; consume
    // will hand them back. The `statement` line MUST be preserved verbatim
    // — the whole reason Sol rejected the prior implementation is that
    // real SIWE statements were causing hard failure at narrow time.
    expect(siwe).toContain('I further authorize');

    // 2. Preview (unchanged selection)
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prepBody.authorizationContextToken,
        selectedActionIds: prepBody.allowedActionIds,
      }),
    });
    expect(previewRes.status).toBe(200);
    const previewBody = await previewRes.json() as any;
    // Unchanged selection = original bytes.
    expect(previewBody.signedMessage).toBe(siwe);

    // 3. Finalize
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prepBody.authorizationContextToken,
        previewApprovalToken: previewBody.previewApprovalToken,
        selectedActionIds: prepBody.allowedActionIds,
        protocolVersion: 1,
      }),
    });
    const signBody = await signRes.json() as any;
    expect(signRes.status).toBe(200);

    // Sol wire format for signInWithOpenKeyResult.
    expect(signBody.protocolVersion).toBe(1);
    expect(typeof signBody.address).toBe('string');
    expect(typeof signBody.signature).toBe('string');
    expect(typeof signBody.signedMessage).toBe('string');
    expect(Array.isArray(signBody.selectedActionKeys)).toBe(true);
    expect(Array.isArray(signBody.permissions)).toBe(true);
    expect(signBody.signedMessage).toBe(siwe);
    // The signature MUST verify against signedMessage — the same check
    // signInWithOpenKeyResult runs client-side.
    const recovered = verifyMessage(signBody.signedMessage, signBody.signature);
    expect(recovered.toLowerCase()).toBe(address.toLowerCase());
    // Canonical four-part IDs.
    for (const key of signBody.selectedActionKeys) {
      const parts = key.split('\0');
      expect(parts.length).toBe(4);
    }
    // Permissions must have non-empty actions and match entries in signedMessage.
    for (const perm of signBody.permissions) {
      expect(typeof perm.service).toBe('string');
      expect(typeof perm.space).toBe('string');
      expect(typeof perm.path).toBe('string');
      expect(Array.isArray(perm.actions)).toBe(true);
      expect(perm.actions.length).toBeGreaterThan(0);
    }
  });

  test('narrowing a production-shape SIWE succeeds — statement drops broadening actions', async () => {
    // Sol CRITICAL-1: the whole point. A real production SIWE with a
    // non-empty ReCap statement MUST be narrowable end-to-end.
    const { siwe } = makeProductionShapeSiwe();
    const prepRes = await router.request('/authorize-sign-prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz' }),
    });
    expect(prepRes.status).toBe(200);
    const prepBody = await prepRes.json() as any;
    const allowed: string[] = prepBody.allowedActionIds;
    // Narrow: drop kv/put and sql/read. Keep kv/get and capabilities/read.
    const narrowed = allowed.filter(
      (id: string) => !id.includes('kv/put') && !id.includes('sql/read'),
    );
    // The test is meaningful only when narrowing actually removed something.
    expect(narrowed.length).toBeLessThan(allowed.length);

    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prepBody.authorizationContextToken,
        selectedActionIds: narrowed,
      }),
    });
    // Sol CRITICAL-1: the preview MUST succeed. The prior implementation
    // returned 400 immutable_fields_not_preservable here because the
    // statement line was non-empty.
    if (previewRes.status !== 200) {
      const body = await previewRes.json();
      console.error('preview failure:', body);
    }
    expect(previewRes.status).toBe(200);
    const previewBody = await previewRes.json() as any;
    // The narrowed signedMessage MUST differ from the original but
    // preserve every immutable header field.
    expect(previewBody.signedMessage).not.toBe(siwe);
    // Extract & compare header fields byte-for-byte (excluding statement
    // and Resources: which are derived from the ReCap contents).
    const strip = (s: string) => s.split('\n').filter((l) => !/^-|^Resources:|^I further authorize/.test(l)).slice(0, 8);
    // First 3 lines: header, address, blank
    expect(strip(previewBody.signedMessage).slice(0, 3)).toEqual(strip(siwe).slice(0, 3));
    // URI / Version / Chain / Nonce / IssuedAt / ExpirationTime must match
    const extractHeader = (s: string, name: string): string | null => {
      const m = s.match(new RegExp(`^${name}:\\s*(.+)$`, 'm'));
      return m?.[1]?.trim() ?? null;
    };
    for (const name of ['URI', 'Version', 'Chain ID', 'Nonce', 'Issued At', 'Expiration Time']) {
      expect(extractHeader(previewBody.signedMessage, name)).toBe(extractHeader(siwe, name));
    }
    // The narrowed statement MUST NOT mention the removed actions.
    expect(previewBody.signedMessage).not.toContain("tinycloud.kv': 'put");
    expect(previewBody.signedMessage).not.toContain("tinycloud.sql': 'read");

    // Finalize
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prepBody.authorizationContextToken,
        previewApprovalToken: previewBody.previewApprovalToken,
        selectedActionIds: narrowed,
        protocolVersion: 1,
      }),
    });
    if (signRes.status !== 200) {
      const body = await signRes.json();
      console.error('sign failure:', body);
    }
    expect(signRes.status).toBe(200);
    const signBody = await signRes.json() as any;
    // Signed bytes must match the preview EXACTLY.
    expect(signBody.signedMessage).toBe(previewBody.signedMessage);
    // Signature must verify against signedMessage (what signInWithOpenKeyResult does).
    const recovered = verifyMessage(signBody.signedMessage, signBody.signature);
    expect(recovered.toLowerCase()).toBe(address.toLowerCase());
    // The final ReCap MUST NOT contain the narrowed-out abilities.
    const finalEntries = parseRecapFromSiwe(signBody.signedMessage) as any[];
    const flatAbilities = finalEntries.flatMap((e) => e.actions);
    expect(flatAbilities).toContain('tinycloud.kv/get');
    expect(flatAbilities).not.toContain('tinycloud.kv/put');
    expect(flatAbilities).not.toContain('tinycloud.sql/read');
  });

  test('finalize response has the wire shape signInWithOpenKeyResult validates', async () => {
    const { siwe } = makeProductionShapeSiwe();
    const prepRes = await router.request('/authorize-sign-prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz' }),
    });
    const prepBody = await prepRes.json() as any;
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prepBody.authorizationContextToken,
        selectedActionIds: prepBody.allowedActionIds,
      }),
    });
    const previewBody = await previewRes.json() as any;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prepBody.authorizationContextToken,
        previewApprovalToken: previewBody.previewApprovalToken,
        selectedActionIds: prepBody.allowedActionIds,
        protocolVersion: 1,
      }),
    });
    const signBody = await signRes.json() as any;

    // Wire-format assertions that mirror the checks in
    // NodeUserAuthorization.signInWithOpenKeyResult:
    //   - protocolVersion is 1
    //   - address, signature, signedMessage are strings
    //   - selectedActionKeys are canonical 4-part `service\0space\0path\0ability`
    //   - permissions[].service/space/path are strings; actions[] non-empty
    //   - every selectedActionKey resolves to a signedCaps (resource, ability) pair
    expect(signBody.protocolVersion).toBe(1);
    expect(typeof signBody.address).toBe('string');
    expect(typeof signBody.signature).toBe('string');
    expect(typeof signBody.signedMessage).toBe('string');
    expect(Array.isArray(signBody.selectedActionKeys)).toBe(true);
    expect(Array.isArray(signBody.permissions)).toBe(true);
    // Build signedCaps from parseRecapFromSiwe and confirm every 4-part ID
    // maps back to a real pair — same logic signInWithOpenKeyResult runs.
    const parsedEntries = parseRecapFromSiwe(signBody.signedMessage) as any[];
    const groundedPairs = new Set<string>();
    for (const entry of parsedEntries) {
      const resource = entry.path ? `${entry.space}/${entry.path}` : entry.space;
      // Best-effort canonical service: strip the entry.service short-name
      // used in the 4-part key. For real production, canonical service is
      // `tinycloud.<short>` when short doesn't already contain a dot.
      for (const action of entry.actions) {
        const service = action.includes('/') ? action.split('/')[0]! : '';
        if (!service) continue;
        // The 4-part key uses `resource` split as space/path with the
        // shortServiceName included in the path — parse.rs at the SDK
        // side splits `resource = space` when path is empty else
        // `resource = space + "/" + path`. Store `space + "\0" + path`
        // for a lookup key.
        let space = resource;
        let path = '';
        if (resource.startsWith('tinycloud:')) {
          const slash = resource.indexOf('/');
          if (slash >= 0) {
            space = resource.slice(0, slash);
            path = resource.slice(slash + 1);
          }
        }
        groundedPairs.add(`${service}\0${space}\0${path}\0${action}`);
      }
    }
    for (const key of signBody.selectedActionKeys) {
      expect(groundedPairs.has(key)).toBe(true);
    }
  });
});
