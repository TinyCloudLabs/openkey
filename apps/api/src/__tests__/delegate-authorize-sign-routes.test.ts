// Route-level HTTP tests for the OpenKey editable-signing pipeline
// (/authorize-sign-prepare → /authorize-sign-preview → /authorize-sign).
//
// Sol MAJOR-10 asked for route-level tests over the wire — these exercise
// the actual Hono router (not internal helpers). We assert:
//
//   1. /authorize-sign-preview issues a previewApprovalToken.
//   2. /authorize-sign rejects requests missing the preview-approval token
//      (Sol CRITICAL-1 preview/final binding).
//   3. /authorize-sign accepts the preview-approval token round-trip and
//      returns bytes that match the preview verbatim.
//   4. /authorize-sign rejects a preview-approval token whose selectedActionIds
//      no longer match the finalize selection.
//   5. /authorize-sign rejects a token bound to a different user.
//   6. /authorize-sign refuses to sign without an /authorize-sign-prepare
//      context (Sol CRITICAL-1 token requirement).
//
// These tests boot the router with mocked TEE and Prisma clients but call
// through the real handler code — including the shared authorization-signing
// service — so a wire-format drift on the response envelope surfaces here
// even when the internal helper tests still pass.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import * as manifestOriginFetchModule from '../services/manifest-origin-fetch';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const otherUser = { id: 'user_2', email: 'bob@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };

let currentUser = user;

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
      if (where.userId !== currentUser.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== currentUser.id) return [];
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

let manifestBindResult: {
  ok: boolean;
  manifest?: Record<string, unknown>;
  fetchedDigest?: string;
  reason?: string;
} = { ok: false, reason: 'not configured' };

mock.module('../services/manifest-origin-fetch', () => ({
  ...manifestOriginFetchModule,
  fetchAndBindWellKnownManifest: mock(async () => manifestBindResult),
}));

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];

beforeAll(async () => {
  ({ delegateRouter: router } = await import(
    '../routes/delegate?authorize-sign-routes-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?authorize-sign-routes-isolated' as string
  ));
});

beforeEach(() => {
  currentUser = user;
  manifestBindResult = { ok: false, reason: 'not configured' };
  resetContexts?.();
});

function makePreparedSiwe(): string {
  const chainId = 1;
  const now = new Date();
  const spaceId = `tinycloud:pkh:eip155:${chainId}:${address}:default`;
  const prepared = prepareSession({
    address,
    chainId,
    domain: 'openkey.so',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId,
    jwk,
    abilities: {
      kv: {
        [spaceId]: ['tinycloud.kv/get', 'tinycloud.kv/put'],
      },
      capabilities: {
        [spaceId]: ['tinycloud.capabilities/read'],
      },
    } as any,
  });
  return prepared.siwe;
}

async function issuePrepareContext(): Promise<{
  token: string;
  siwe: string;
  allowed: string[];
}> {
  const siwe = makePreparedSiwe();
  const res = await router.request('/authorize-sign-prepare', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz' }),
  });
  expect(res.status).toBe(200);
  const body = await res.json() as any;
  expect(typeof body.authorizationContextToken).toBe('string');
  return { token: body.authorizationContextToken, siwe, allowed: body.allowedActionIds ?? [] };
}

describe('POST /authorize-sign-prepare manifest provenance', () => {
  test('propagates only server origin-bound manifest scope declarations', async () => {
    const digest = 'a'.repeat(64);
    manifestBindResult = {
      ok: true,
      fetchedDigest: digest,
      manifest: {
        name: 'Listen',
        appId: 'xyz.tinycloud.listen',
        prefix: 'xyz.tinycloud.listen',
        declaredSecrets: [
          {
            secretName: 'GOOGLE_MEET_TOKENS',
            scope: 'listen',
            actions: ['read', 'write', 'delete'],
          },
        ],
      },
    };

    const res = await router.request('/authorize-sign-prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        keyId: keyRecord.id,
        siwe: makePreparedSiwe(),
        jwk,
        reportedOrigin: 'https://listen.tinycloud.xyz',
        presentation: {
          protocolVersion: 1,
          displayName: 'Caller-controlled fallback',
          manifestDigest: digest,
        },
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.metadataTrust.status).toBe('origin-bound');
    expect(body.verifiedManifest.name).toBe('Listen');
    expect(body.verifiedManifest.name).not.toBe('Caller-controlled fallback');
    expect(body.verifiedManifest.declaredAppScope.secrets).toEqual([
      {
        secretName: 'GOOGLE_MEET_TOKENS',
        scope: 'listen',
        actions: ['read', 'write', 'delete'],
      },
    ]);
  });
});

describe('POST /authorize-sign-preview', () => {
  test('issues a preview-approval token bound to the selection and bytes', async () => {
    const { token, allowed } = await issuePrepareContext();
    const res = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(typeof body.signedMessage).toBe('string');
    // Sol CRITICAL-1: the token seals selection + bytes.
    expect(typeof body.previewApprovalToken).toBe('string');
    expect(body.previewApprovalToken).toMatch(/^okp_/);
    expect(typeof body.signedMessageDigest).toBe('string');
  });
});

describe('POST /authorize-sign', () => {
  test('rejects requests missing a preview-approval token', async () => {
    const { token, allowed } = await issuePrepareContext();
    const res = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        selectedActionIds: allowed,
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.code).toBe('missing_preview_approval_token');
  });

  test('rejects requests missing an authorization context token', async () => {
    const res = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        selectedActionIds: [],
        previewApprovalToken: 'okp_bogus',
        protocolVersion: 1,
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.code).toBe('missing_authorization_context_token');
  });

  test('preview round-trip: sign accepts bound token and returns preview bytes', async () => {
    const { token, allowed } = await issuePrepareContext();
    // Preview first — the response carries a token that seals (selection, bytes).
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const preview = await previewRes.json() as any;
    // Finalize with the previewApprovalToken.
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: allowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const signBody = await signRes.json() as any;
    expect(signBody.signedMessage).toBe(preview.signedMessage);
    expect(typeof signBody.signature).toBe('string');
  });

  test('rejects preview-approval bound to a different selection', async () => {
    const { token, allowed } = await issuePrepareContext();
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const preview = await previewRes.json() as any;
    // Finalize with a NARROWER selection than the preview evaluated.
    // Drop one non-required action so the sets diverge.
    const narrowerSelection = allowed.filter((id: string) => !id.includes('kv/put'));
    // Only run this test if we actually have a narrowing to do — otherwise
    // the preview selection equals the finalize selection and the test
    // does not exercise the mismatch code path.
    if (narrowerSelection.length === allowed.length) {
      // Nothing to narrow — skip.
      return;
    }
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: narrowerSelection,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(400);
    const body = await signRes.json() as any;
    // Any of these guards firing is an acceptable rejection: the
    // preview-approval selection mismatch, the context-token subset
    // check, the attenuation-broadens-baseline check, or (when the WASM
    // narrower can't preserve certain header fields) the immutable-
    // fields refusal. All prove the server refused to sign a divergent
    // selection.
    expect(body.code).toMatch(
      /preview-approval-selection-mismatch|selected_actions_|immutable_fields_not_preservable|action-not-in-initial-selection|caveats_not_supported|candidate-broadens-baseline|regenerated_immutable_drift|regenerated_broadens_baseline|narrowed_.+/,
    );
  });

  test('rejects a preview-approval token bound to another user', async () => {
    const { token, allowed } = await issuePrepareContext();
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const preview = await previewRes.json() as any;
    // Switch the authenticated session to a different user and try to
    // finalize. The peekAuthorizationContext user-mismatch check on the
    // context token fires FIRST (400 user_mismatch); either that OR the
    // preview-approval user-mismatch check is acceptable rejection.
    currentUser = otherUser;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: allowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBeGreaterThanOrEqual(400);
  });
});

describe('POST /authorize-sign-preview response shape (wire format)', () => {
  test('response envelope carries protocolVersion, address, signedMessage, previewApprovalToken', async () => {
    const { token, allowed } = await issuePrepareContext();
    const res = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const body = await res.json() as any;
    expect(body).toMatchObject({
      protocolVersion: 1,
      address: expect.any(String),
      signedMessage: expect.any(String),
      previewApprovalToken: expect.stringMatching(/^okp_/),
      previewApprovalExpiresAt: expect.any(String),
      signedMessageDigest: expect.any(String),
      authorizationContextToken: token,
    });
  });
});

// Regression coverage for the widget's `validatePreviewSelection`
// contract: the widget projects `permissions[]` through
// `actionId(service, space, path, ability)` and compares the resulting
// set with the returned `selectedActionKeys`. Both sides MUST use the
// canonical `tinycloud.<short>` service form. The previous route
// implementation emitted the raw WASM short-form (`kv`, `sql`, ...) in
// `permissions[].service` while `selectedActionKeys` were canonicalized
// via `computeActionKey`. That mismatch made the widget throw
// "permissions disagree with selectedActionKeys" and blocked the
// vertical happy path. This test locks the wire shape.
describe('POST /authorize-sign-preview and /authorize-sign wire shape — canonical service', () => {
  function actionIdForPermission(
    service: string,
    space: string,
    path: string,
    action: string,
  ): string {
    // Mirror `@openkey/capability-review`'s `actionId` NUL-tuple exactly.
    return `${service}\0${space}\0${path}\0${action}`;
  }

  test('preview returns permissions[].service canonicalized to tinycloud.<short> and projection matches selectedActionKeys', async () => {
    const { token, allowed } = await issuePrepareContext();
    const res = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(Array.isArray(body.permissions)).toBe(true);
    expect(body.permissions.length).toBeGreaterThan(0);
    for (const p of body.permissions) {
      expect(typeof p.service).toBe('string');
      expect(p.service.startsWith('tinycloud.')).toBe(true);
    }
    const projected = new Set<string>(
      body.permissions.flatMap((p: any) =>
        (p.actions as string[]).map((a) =>
          actionIdForPermission(p.service, p.space, p.path, a),
        ),
      ),
    );
    const returned = new Set<string>(body.selectedActionKeys);
    // Set equality — projected IDs and returned selected keys agree.
    expect(projected.size).toBe(returned.size);
    for (const value of returned) {
      expect(projected.has(value)).toBe(true);
    }
  });

  test('finalize returns permissions[].service canonicalized to tinycloud.<short> and projection matches selectedActionKeys', async () => {
    const { token, allowed } = await issuePrepareContext();
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const preview = await previewRes.json() as any;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: allowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const body = await signRes.json() as any;
    expect(Array.isArray(body.permissions)).toBe(true);
    expect(body.permissions.length).toBeGreaterThan(0);
    for (const p of body.permissions) {
      expect(typeof p.service).toBe('string');
      expect(p.service.startsWith('tinycloud.')).toBe(true);
    }
    const projected = new Set<string>(
      body.permissions.flatMap((p: any) =>
        (p.actions as string[]).map((a) =>
          actionIdForPermission(p.service, p.space, p.path, a),
        ),
      ),
    );
    const returned = new Set<string>(body.selectedActionKeys);
    expect(projected.size).toBe(returned.size);
    for (const value of returned) {
      expect(projected.has(value)).toBe(true);
    }
  });
});

// Sol final continuation contract requirement 3: caveat semantics must
// be exact for surviving abilities. The normal HTTP flow only exposes
// whole-ability removal (the server reuses baseline caveats when
// building the candidate); tests for caveat MUTATIONS live at the
// service layer (`authorization-signing.test.ts::caveat semantics`).
// Here we exercise the HTTP path to prove:
//   - Whole-ability removal succeeds and the narrowed SIWE lacks the
//     removed ability.
//   - Baseline caveats survive byte-for-byte on retained abilities.
describe('POST /authorize-sign — caveat semantics for narrowing', () => {
  test('removes a whole ability while preserving caveats on retained abilities', async () => {
    const { token, siwe, allowed } = await issuePrepareContext();
    // Narrow by removing `tinycloud.kv/put`. `tinycloud.kv/get` and
    // `tinycloud.capabilities/read` must remain, and their caveats must
    // match the baseline byte-for-byte because we reuse baseline caveats.
    const narrowed = allowed.filter((id: string) => !id.includes('kv/put'));
    expect(narrowed.length).toBeLessThan(allowed.length);

    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: narrowed }),
    });
    expect(previewRes.status).toBe(200);
    const preview = await previewRes.json() as any;

    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: narrowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;
    // The narrowed SIWE MUST NOT reference the removed ability — the
    // ReCap-derived statement drops `put` while retaining `get`.
    expect(sign.signedMessage).not.toMatch(/'tinycloud\.kv':[^\n]*'put'/);
    expect(sign.signedMessage).toMatch(/'tinycloud\.kv':[^\n]*'get'/);
    expect(sign.signedMessage).toMatch(/'tinycloud\.capabilities':[^\n]*'read'/);
    // And the immutable header lines MUST match the original SIWE.
    const extract = (s: string, name: string) => {
      const m = s.match(new RegExp(`^${name}:\\s*(.+)$`, 'm'));
      return m?.[1]?.trim() ?? null;
    };
    for (const name of ['URI', 'Version', 'Chain ID', 'Nonce', 'Issued At', 'Expiration Time']) {
      expect(extract(sign.signedMessage, name)).toBe(extract(siwe, name));
    }
    // The signature MUST verify against signedMessage (the final round-trip
    // guarantee that everything the client cares about is intact).
    const { verifyMessage } = await import('ethers');
    const recovered = verifyMessage(sign.signedMessage, sign.signature);
    expect(recovered.toLowerCase()).toBe(address.toLowerCase());
  });

  test('full-selection round-trip signs the ORIGINAL bytes byte-for-byte', async () => {
    // No narrowing means the server must NOT regenerate — it must sign
    // the caller's exact prepared SIWE. This preserves any caveats and
    // duplicate counts the baseline carried since we never re-emit.
    const { token, siwe, allowed } = await issuePrepareContext();
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const preview = await previewRes.json() as any;
    // The preview MUST equal the original SIWE when nothing was narrowed.
    expect(preview.signedMessage).toBe(siwe);
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: allowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;
    expect(sign.signedMessage).toBe(siwe);
  });

  // Sol final contract MAJOR-3: route-level cases that prove caveat
  // preservation and duplicate-count preservation traverse the actual
  // HTTP routes end-to-end. The existing route tests only verified that
  // whole-ability removal returned a narrower statement; they did NOT
  // decode the `urn:recap:` payload and compare caveats between the
  // baseline and the finalized signed bytes. These tests do — decoding
  // BOTH sides via the same base64url ReCap payload the SDK consumer
  // walks, and asserting the caveat arrays are multiset-equal on every
  // surviving (resource, ability) pair. A regression that quietly drops
  // caveats (broadening authority on surviving actions) or that changes
  // a caveat duplicate count would fail here even when the higher-level
  // statement/permissions assertions still pass.
  test('finalize preserves baseline caveat multisets (byte-for-byte) on retained abilities across the HTTP route', async () => {
    const { token, siwe, allowed } = await issuePrepareContext();
    // Narrow: drop kv/put. kv/get and capabilities/read must survive
    // with EVERY baseline caveat preserved (the server reuses baseline
    // caveats when regenerating; a bug that swapped or dropped caveats
    // would surface here).
    const narrowed = allowed.filter((id: string) => !id.includes('kv/put'));
    expect(narrowed.length).toBeLessThan(allowed.length);
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: narrowed }),
    });
    const preview = await previewRes.json() as any;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: narrowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;
    // Decode the ATT map from BOTH the baseline SIWE and the finalized
    // signedMessage. The base64url helper mirrors what the js-sdk
    // consumer walks — a divergence here IS a wire-format bug.
    const baselineAtt = extractAttFromSiwe(siwe);
    const finalAtt = extractAttFromSiwe(sign.signedMessage);
    // For every (resource, ability) that survives in `finalAtt`, the
    // caveat MULTISET must equal the baseline's caveat multiset for
    // that same pair. Whole-ability and whole-resource removals are
    // legal; caveat mutations on survivors are not.
    for (const [resource, finalAbilityMap] of Object.entries(finalAtt)) {
      const baselineAbilityMap = baselineAtt[resource];
      expect(baselineAbilityMap, `resource ${resource} missing from baseline`).toBeDefined();
      if (!baselineAbilityMap) continue;
      for (const [ability, finalCaveats] of Object.entries(finalAbilityMap)) {
        const baselineCaveats = baselineAbilityMap[ability];
        expect(baselineCaveats, `ability ${ability} on ${resource} missing from baseline`).toBeDefined();
        if (!baselineCaveats) continue;
        // Multiset equality — sort canonical JSON strings and compare
        // element-wise. Handles duplicates AND key-order differences.
        expect(multisetEqual(baselineCaveats, finalCaveats)).toBe(true);
      }
    }
    // Sanity: the finalize DID drop the requested ability from ATT
    // (i.e. the narrowing actually happened) — otherwise the caveat
    // multiset test would pass trivially by comparing to the baseline
    // unchanged.
    const anyKvActions = Object.values(finalAtt)
      .flatMap((abilityMap) => Object.keys(abilityMap));
    expect(anyKvActions).toContain('tinycloud.kv/get');
    expect(anyKvActions).not.toContain('tinycloud.kv/put');
  });

  test('finalize preserves baseline caveat duplicate counts on retained abilities across the HTTP route', async () => {
    // A prepared SIWE constructed via `prepareSession` emits caveats
    // exactly once per ability, so on the standard route the
    // finalize/baseline duplicate counts are both zero — comparing
    // them proves the pipeline does NOT synthesize spurious caveats.
    // We assert this explicitly rather than relying on the multiset
    // check above: the check above would pass trivially if both
    // sides were [] on every ability. Here we go further and prove
    // that the finalize-side caveat length on each surviving ability
    // EXACTLY equals the baseline-side length (not just multiset-
    // equal). A regression that ADDED a caveat on a surviving
    // ability would fail here even if the added caveat matched a
    // baseline caveat coincidentally.
    const { token, siwe, allowed } = await issuePrepareContext();
    const narrowed = allowed.filter((id: string) => !id.includes('kv/put'));
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: narrowed }),
    });
    const preview = await previewRes.json() as any;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: narrowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;
    const baselineAtt = extractAttFromSiwe(siwe);
    const finalAtt = extractAttFromSiwe(sign.signedMessage);
    for (const [resource, finalAbilityMap] of Object.entries(finalAtt)) {
      for (const [ability, finalCaveats] of Object.entries(finalAbilityMap)) {
        const baselineCaveats = baselineAtt[resource]?.[ability] ?? [];
        expect(finalCaveats.length).toBe(baselineCaveats.length);
      }
    }
  });

  test('narrowing a SIWE with MEANINGFUL caveats preserves the caveat multiset on every surviving (resource, ability) pair', async () => {
    // Sol MAJOR-2 (final): the WASM emitter unconditionally writes `[{}]`
    // for every ability regardless of input caveats. If the narrower
    // trusted the WASM output verbatim, meaningful caveats on the
    // baseline would silently disappear on narrowing — broadening
    // authority. This test constructs a SIWE with a NON-VACUOUS
    // caveat (`{ nb: 1700000000 }`) on `tinycloud.kv/get` and a
    // DUPLICATED caveat (`{ nb: 1700000000 }` twice) on
    // `tinycloud.kv/put`, runs prepare → preview → finalize with
    // narrowing (drop `tinycloud.kv/put`), and asserts the final
    // signedMessage preserves the EXACT caveat multiset on the
    // surviving `tinycloud.kv/get` ability.
    const baseSiwe = makePreparedSiwe();
    const baselineAtt = extractAttFromSiwe(baseSiwe);
    // Inject meaningful caveats + a duplicate on kv/put.
    const richAtt: Record<string, Record<string, unknown[]>> = {};
    for (const [resource, abilityMap] of Object.entries(baselineAtt)) {
      const dst: Record<string, unknown[]> = {};
      for (const [ability, caveats] of Object.entries(abilityMap)) {
        if (ability === 'tinycloud.kv/get') {
          dst[ability] = [{ nb: 1_700_000_000 }];
        } else if (ability === 'tinycloud.kv/put') {
          // Duplicate caveat — two structurally identical restrictions.
          dst[ability] = [{ nb: 1_700_000_000 }, { nb: 1_700_000_000 }];
        } else {
          dst[ability] = [...caveats];
        }
      }
      richAtt[resource] = dst;
    }
    const richSiwe = rewriteRecapPayload(baseSiwe, richAtt);

    const prepRes = await router.request('/authorize-sign-prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ keyId: keyRecord.id, siwe: richSiwe, jwk, host: 'https://node.tinycloud.xyz' }),
    });
    expect(prepRes.status).toBe(200);
    const prep = await prepRes.json() as any;
    // Drop kv/put — keep kv/get and capabilities/read.
    const allowed: string[] = prep.allowedActionIds;
    const narrowed = allowed.filter((id: string) => !id.includes('kv/put'));
    expect(narrowed.length).toBeLessThan(allowed.length);

    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: prep.authorizationContextToken, selectedActionIds: narrowed }),
    });
    if (previewRes.status !== 200) {
      console.error('preview failure:', await previewRes.json());
    }
    expect(previewRes.status).toBe(200);
    const preview = await previewRes.json() as any;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prep.authorizationContextToken,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: narrowed,
        protocolVersion: 1,
      }),
    });
    if (signRes.status !== 200) {
      console.error('sign failure:', await signRes.json());
    }
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;

    const finalAtt = extractAttFromSiwe(sign.signedMessage);
    // Surviving abilities keep their EXACT baseline caveat multiset.
    for (const [resource, finalAbilityMap] of Object.entries(finalAtt)) {
      for (const [ability, finalCaveats] of Object.entries(finalAbilityMap)) {
        const baselineCaveats = richAtt[resource]?.[ability];
        expect(baselineCaveats, `ability ${ability} on ${resource} missing from baseline`).toBeDefined();
        if (!baselineCaveats) continue;
        expect(multisetEqual(baselineCaveats, finalCaveats)).toBe(true);
        // Duplicate count must match array length.
        expect(finalCaveats.length).toBe(baselineCaveats.length);
      }
    }
    // The removed ability MUST NOT appear anywhere in the final ATT.
    for (const abilityMap of Object.values(finalAtt)) {
      expect(Object.keys(abilityMap)).not.toContain('tinycloud.kv/put');
    }
    // The surviving kv/get MUST carry the meaningful `{ nb: ... }` caveat.
    const surviving = Object.values(finalAtt).flatMap((m) =>
      m['tinycloud.kv/get'] ?? [],
    );
    expect(surviving.length).toBeGreaterThanOrEqual(1);
    expect((surviving[0] as any).nb).toBe(1_700_000_000);
  });

  test('unchanged-selection round-trip on a SIWE with duplicated caveats returns the original bytes verbatim', async () => {
    // Sol MAJOR-2: even with a DUPLICATED meaningful caveat on
    // `tinycloud.kv/put`, an unchanged-selection round-trip must return
    // byte-for-byte the original SIWE (the unchanged-selection branch
    // signs original bytes verbatim). The multiset preservation is
    // therefore trivial by construction, but this test guards the
    // "no narrowing, no rewriting" invariant.
    const baseSiwe = makePreparedSiwe();
    const baselineAtt = extractAttFromSiwe(baseSiwe);
    const richAtt: Record<string, Record<string, unknown[]>> = {};
    for (const [resource, abilityMap] of Object.entries(baselineAtt)) {
      const dst: Record<string, unknown[]> = {};
      for (const [ability, caveats] of Object.entries(abilityMap)) {
        if (ability === 'tinycloud.kv/put') {
          dst[ability] = [{ nb: 1_700_000_000 }, { nb: 1_700_000_000 }];
        } else {
          dst[ability] = [...caveats];
        }
      }
      richAtt[resource] = dst;
    }
    const richSiwe = rewriteRecapPayload(baseSiwe, richAtt);
    const prepRes = await router.request('/authorize-sign-prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ keyId: keyRecord.id, siwe: richSiwe, jwk, host: 'https://node.tinycloud.xyz' }),
    });
    expect(prepRes.status).toBe(200);
    const prep = await prepRes.json() as any;
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: prep.authorizationContextToken, selectedActionIds: prep.allowedActionIds }),
    });
    expect(previewRes.status).toBe(200);
    const preview = await previewRes.json() as any;
    expect(preview.signedMessage).toBe(richSiwe);
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: prep.authorizationContextToken,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: prep.allowedActionIds,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;
    expect(sign.signedMessage).toBe(richSiwe);
    const finalAtt = extractAttFromSiwe(sign.signedMessage);
    // Duplicate count preserved.
    const putList = Object.values(finalAtt).flatMap((m) =>
      m['tinycloud.kv/put'] ?? [],
    );
    expect(putList.length).toBe(2);
    expect((putList[0] as any).nb).toBe(1_700_000_000);
    expect((putList[1] as any).nb).toBe(1_700_000_000);
  });

  test('full-selection round-trip preserves the entire baseline ATT map byte-for-byte on the HTTP route', async () => {
    // When nothing is narrowed the server reuses the caller's exact
    // prepared bytes — the ATT map on both sides must be structurally
    // identical, including caveat multisets AND duplicate counts.
    // This is the strictest form of the caveat-preservation check.
    const { token, siwe, allowed } = await issuePrepareContext();
    const previewRes = await router.request('/authorize-sign-preview', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationContextToken: token, selectedActionIds: allowed }),
    });
    const preview = await previewRes.json() as any;
    const signRes = await router.request('/authorize-sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationContextToken: token,
        previewApprovalToken: preview.previewApprovalToken,
        selectedActionIds: allowed,
        protocolVersion: 1,
      }),
    });
    expect(signRes.status).toBe(200);
    const sign = await signRes.json() as any;
    const baselineAtt = extractAttFromSiwe(siwe);
    const finalAtt = extractAttFromSiwe(sign.signedMessage);
    // Same resource set, same ability set per resource.
    expect(Object.keys(finalAtt).sort()).toEqual(Object.keys(baselineAtt).sort());
    for (const resource of Object.keys(baselineAtt)) {
      expect(Object.keys(finalAtt[resource]!).sort()).toEqual(
        Object.keys(baselineAtt[resource]!).sort(),
      );
      for (const ability of Object.keys(baselineAtt[resource]!)) {
        expect(multisetEqual(
          baselineAtt[resource]![ability]!,
          finalAtt[resource]![ability]!,
        )).toBe(true);
      }
    }
  });
});

/**
 * Rewrite the `urn:recap:` base64url payload of a SIWE to carry the
 * given `att` map. Preserves every other byte of the SIWE (URI,
 * Version, statement, headers, non-recap resource lines). Used to
 * construct fixtures with meaningful caveats + duplicated caveats
 * that WASM's `prepareSession` will not emit on its own.
 */
function rewriteRecapPayload(
  siwe: string,
  newAtt: Record<string, Record<string, unknown[]>>,
): string {
  const lines = siwe.split('\n');
  const idx = lines.findIndex((l) => l.startsWith('- urn:recap:'));
  if (idx < 0) throw new Error('no urn:recap line');
  const line = lines[idx]!;
  const m = line.match(/^(- urn:recap:)([A-Za-z0-9_-]+=*)$/);
  if (!m || !m[2]) throw new Error('malformed urn:recap line');
  const normalized = m[2].replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const parsed = JSON.parse(Buffer.from(padded, 'base64').toString('utf8')) as {
    att?: unknown;
    prf?: unknown[];
  };
  parsed.att = newAtt;
  const rebuilt = Buffer.from(JSON.stringify(parsed), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  lines[idx] = `${m[1]}${rebuilt}`;
  return lines.join('\n');
}

/**
 * Decode the `urn:recap:` base64url payload out of a SIWE and return
 * the merged `att` map: resource → ability → caveats[]. Matches the
 * shared canonical decoder used in the js-sdk consumer so a wire-
 * format drift on either side surfaces here.
 */
function extractAttFromSiwe(siwe: string): Record<string, Record<string, unknown[]>> {
  const merged: Record<string, Record<string, unknown[]>> = {};
  for (const line of siwe.split(/\r?\n/)) {
    const m = line.match(/urn:recap:([A-Za-z0-9_-]+=*)/);
    if (!m || !m[1]) continue;
    const normalized = m[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const json = Buffer.from(padded, 'base64').toString('utf8');
    const parsed = JSON.parse(json) as { att?: Record<string, Record<string, unknown[]>> };
    const att = parsed?.att;
    if (!att || typeof att !== 'object') continue;
    for (const [resource, abilityMap] of Object.entries(att)) {
      const target = merged[resource] ?? (merged[resource] = {});
      for (const [ability, caveats] of Object.entries(abilityMap)) {
        if (!Array.isArray(caveats)) continue;
        target[ability] = [...(target[ability] ?? []), ...caveats];
      }
    }
  }
  return merged;
}

/**
 * Canonicalize + multiset-compare two caveat arrays. Sorts by a
 * deterministic JSON key that ignores object property ordering so
 * structurally identical caveats compare equal regardless of surface
 * serialization order. Matches the canonicalMultisetEqual behaviour
 * of the shared @openkey/capability-review subset validator.
 */
function multisetEqual(a: readonly unknown[], b: readonly unknown[]): boolean {
  if (a.length !== b.length) return false;
  const canon = (v: unknown): string =>
    JSON.stringify(v, function (this: unknown, key: string, val: unknown) {
      void key;
      if (val === null || typeof val !== 'object' || Array.isArray(val)) return val;
      const rec = val as Record<string, unknown>;
      const keys = Object.keys(rec).sort();
      const out: Record<string, unknown> = {};
      for (const k of keys) out[k] = rec[k];
      return out;
    });
  const sa = a.map(canon).sort();
  const sb = b.map(canon).sort();
  for (let i = 0; i < sa.length; i += 1) if (sa[i] !== sb[i]) return false;
  return true;
}
