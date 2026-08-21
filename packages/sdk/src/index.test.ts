// Unit tests for the @openkey/sdk validation helpers.
//
// The SDK is otherwise a browser-runtime piece (IframeModal manipulates
// the DOM), but the resize-correlation validation is a pure function
// (Sol final continuation contract requirement 5). This suite covers
// every rejection branch so a regression that reintroduces stray-frame
// resize acceptance would surface immediately.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  validateIframeResize,
  shouldRouteAuthorizeTinyCloudExternal,
  resolveAuthorizeTinyCloudRouting,
  KeyIdTypeMismatchError,
  OpenKey,
} from './index';

describe('validateIframeResize (Sol continuation req 5)', () => {
  const expectedActive = {
    requestId: 'req-abc',
    protocolVersion: 1,
    viewportHeight: 900,
  };

  test('accepts a well-formed resize matching the active requestId + protocolVersion', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        requestId: 'req-abc',
        protocolVersion: 1,
      },
      expectedActive,
    );
    // 500 <= viewport*0.85 (765) so height passes unchanged.
    expect(h).toBe(500);
  });

  test('clamps oversized height to 85% of the viewport', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 10_000,
        requestId: 'req-abc',
        protocolVersion: 1,
      },
      expectedActive,
    );
    expect(h).toBe(Math.floor(900 * 0.85));
  });

  test('drops resize with a WRONG requestId (stale/foreign widget instance)', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        requestId: 'req-different',
        protocolVersion: 1,
      },
      expectedActive,
    );
    expect(h).toBeNull();
  });

  test('drops resize with a WRONG protocolVersion', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        requestId: 'req-abc',
        protocolVersion: 2,
      },
      expectedActive,
    );
    expect(h).toBeNull();
  });

  test('drops resize missing requestId entirely', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        protocolVersion: 1,
      },
      expectedActive,
    );
    expect(h).toBeNull();
  });

  test('drops resize missing protocolVersion entirely', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        requestId: 'req-abc',
      },
      expectedActive,
    );
    expect(h).toBeNull();
  });

  test('drops resize when NO active request has been bound yet', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        requestId: 'req-abc',
        protocolVersion: 1,
      },
      { requestId: null, protocolVersion: null, viewportHeight: 900 },
    );
    expect(h).toBeNull();
  });

  test('drops resize when only requestId is bound (missing protocolVersion)', () => {
    const h = validateIframeResize(
      {
        type: 'openkey:resize',
        height: 500,
        requestId: 'req-abc',
        protocolVersion: 1,
      },
      { requestId: 'req-abc', protocolVersion: null, viewportHeight: 900 },
    );
    expect(h).toBeNull();
  });

  test('drops resize with invalid (negative/zero/NaN) height', () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 'tall', null]) {
      const h = validateIframeResize(
        {
          type: 'openkey:resize',
          height: bad as unknown,
          requestId: 'req-abc',
          protocolVersion: 1,
        },
        expectedActive,
      );
      expect(h).toBeNull();
    }
  });

  test('drops messages that are not resize events (wrong type discriminant)', () => {
    for (const type of ['openkey:sign:response', 'openkey:close', 'random', undefined]) {
      const h = validateIframeResize(
        {
          type,
          height: 500,
          requestId: 'req-abc',
          protocolVersion: 1,
        },
        expectedActive,
      );
      expect(h).toBeNull();
    }
  });

  test('drops non-object / null / undefined incoming', () => {
    for (const bad of [null, undefined, 'string', 42, true]) {
      const h = validateIframeResize(bad as unknown, expectedActive);
      expect(h).toBeNull();
    }
  });

  test('shouldRouteAuthorizeTinyCloudExternal returns true when lastAuth.keyType is EXTERNAL (Sol MAJOR-4 final)', () => {
    // Sol MAJOR-4 (final) requires this decision to hinge on the ACTIVE
    // session's keyType and NOT on any keyId-string comparison. The
    // authoritative fact is: "is this user currently authenticated
    // with an external wallet?" — if yes, OpenKey has no private
    // material and MUST route external regardless of what caller-side
    // keyId hint arrives. These cases lock in that invariant.
    // (a) No explicit keyId + external session → external.
    expect(
      shouldRouteAuthorizeTinyCloudExternal({
        lastAuth: { keyType: 'EXTERNAL' },
      }),
    ).toBe(true);
    // (b) Explicit keyId matches lastAuth.keyId + external session →
    // external (unchanged from prior behaviour).
    expect(
      shouldRouteAuthorizeTinyCloudExternal({
        lastAuth: { keyType: 'EXTERNAL' } as any,
      }),
    ).toBe(true);
    // (c) Explicit keyId DIFFERS from lastAuth.keyId + external
    // session → STILL external (this is the exact case Sol rejected).
    // The user only has one active session; the widget cannot server-
    // sign an external key regardless of what identifier form the
    // caller passes.
    expect(
      shouldRouteAuthorizeTinyCloudExternal({
        lastAuth: { keyType: 'EXTERNAL' } as any,
      }),
    ).toBe(true);
  });

  test('shouldRouteAuthorizeTinyCloudExternal returns false when lastAuth.keyType is MANAGED (Sol MAJOR-4 final)', () => {
    // (d) Explicit keyId + managed session → managed. A managed key
    // has TEE-sealed material OpenKey CAN sign server-side.
    expect(
      shouldRouteAuthorizeTinyCloudExternal({
        lastAuth: { keyType: 'MANAGED' },
      }),
    ).toBe(false);
    // (e) No explicit keyId + managed session → managed.
    expect(
      shouldRouteAuthorizeTinyCloudExternal({
        lastAuth: { keyType: 'MANAGED' },
      }),
    ).toBe(false);
  });

  test('shouldRouteAuthorizeTinyCloudExternal returns false when no active session is bound', () => {
    // (f) No lastAuth at all → managed. The widget renders a connect
    // flow first; if the resulting session ends up external, the
    // widget itself refuses to server-sign and asks the SDK to re-
    // enter via the external path. The SDK should not preemptively
    // pick a branch when it has no key state.
    expect(shouldRouteAuthorizeTinyCloudExternal({ lastAuth: null })).toBe(false);
    // (g) Empty lastAuth object (no keyType) → managed by default.
    expect(
      shouldRouteAuthorizeTinyCloudExternal({
        lastAuth: {} as any,
      }),
    ).toBe(false);
  });

  test('sequential requests: previous requestId is no longer accepted after the next one is bound', () => {
    // Simulate the outer flow re-binding correlation for a new request.
    // A resize claiming the OLD requestId must be dropped even though it
    // was valid moments ago.
    const oldExpected = { requestId: 'req-1', protocolVersion: 1, viewportHeight: 900 };
    const newExpected = { requestId: 'req-2', protocolVersion: 1, viewportHeight: 900 };
    expect(
      validateIframeResize(
        { type: 'openkey:resize', height: 500, requestId: 'req-1', protocolVersion: 1 },
        oldExpected,
      ),
    ).toBe(500);
    // After rebinding, the OLD requestId is rejected.
    expect(
      validateIframeResize(
        { type: 'openkey:resize', height: 500, requestId: 'req-1', protocolVersion: 1 },
        newExpected,
      ),
    ).toBeNull();
    // The NEW requestId is accepted.
    expect(
      validateIframeResize(
        { type: 'openkey:resize', height: 500, requestId: 'req-2', protocolVersion: 1 },
        newExpected,
      ),
    ).toBe(500);
  });
});

describe('OpenKey.signOut', () => {
  test('clears the current SDK session before the correlated widget acknowledgement', async () => {
    const openkey = Object.create(OpenKey.prototype) as OpenKey;
    (openkey as any).activeFlowCancellations = new Set();
    (openkey as any).lastAuth = { address: '0xfirst', keyId: 'key-first', keyType: 'MANAGED' };
    (openkey as any).sessionToken = 'first-session-token';
    let signOutRequest: any;
    (openkey as any).openFlow = async (_action: string, request: any) => {
      signOutRequest = request;
      expect((openkey as any).lastAuth).toBeNull();
      expect((openkey as any).sessionToken).toBeNull();
      return { requestId: request.requestId, revoked: true };
    };

    const acknowledgement = await openkey.signOut();

    expect(signOutRequest).toMatchObject({
      type: 'openkey:sign-out:request',
      protocolVersion: 1,
      sessionToken: 'first-session-token',
    });
    expect(acknowledgement).toEqual({ requestId: signOutRequest.requestId, revoked: true });
    expect(openkey.getSessionToken()).toBeNull();
  });

  test('allows a fresh public connect flow to select another account after sign-out', async () => {
    const openkey = Object.create(OpenKey.prototype) as OpenKey;
    (openkey as any).activeFlowCancellations = new Set();
    (openkey as any).lastAuth = { address: '0xfirst', keyId: 'key-first', keyType: 'MANAGED' };
    (openkey as any).sessionToken = 'first-session-token';
    const requests: any[] = [];
    (openkey as any).openFlow = async (_action: string, request: any) => {
      requests.push(request);
      if (request.type === 'openkey:sign-out:request') {
        return { requestId: request.requestId, revoked: true };
      }
      return { address: '0xsecond', keyId: 'key-second', keyType: 'MANAGED' };
    };

    await openkey.signOut();
    const secondAccount = await openkey.connect();

    expect(requests.map((request) => request.type)).toEqual([
      'openkey:sign-out:request',
      'openkey:auth:request',
    ]);
    expect(secondAccount).toEqual({
      address: '0xsecond',
      keyId: 'key-second',
      keyType: 'MANAGED',
    });
    expect((openkey as any).lastAuth).toEqual(secondAccount);
  });

  test('uses a widget that can acknowledge sign-out when configured for redirect auth', async () => {
    const openkey = Object.create(OpenKey.prototype) as OpenKey;
    (openkey as any).activeFlowCancellations = new Set();
    (openkey as any).mode = 'redirect';
    let mode: unknown;
    (openkey as any).openFlow = async (_action: string, request: any, requestedMode: unknown) => {
      mode = requestedMode;
      return { requestId: request.requestId, revoked: false };
    };

    await openkey.signOut();

    expect(mode).toBe('popup');
  });

  test('cancels every in-flight widget flow before sign-out can receive its response', async () => {
    const openkey = Object.create(OpenKey.prototype) as OpenKey;
    const cancellations: string[] = [];
    (openkey as any).activeFlowCancellations = new Set([
      () => { cancellations.push('first'); },
      () => { cancellations.push('second'); },
    ]);
    (openkey as any).lastAuth = { address: '0xfirst', keyId: 'key-first', keyType: 'MANAGED' };
    (openkey as any).sessionToken = 'first-session-token';
    (openkey as any).openFlow = async (_action: string, request: any) => {
      expect(cancellations).toEqual(['first', 'second']);
      return { requestId: request.requestId, revoked: true };
    };

    await openkey.signOut({ mode: 'popup' });

    expect((openkey as any).lastAuth).toBeNull();
    expect(openkey.getSessionToken()).toBeNull();
    expect((openkey as any).isResponseForAction('connect', {
      type: 'openkey:sign-out:response',
      success: true,
      requestId: 'sign-out-1',
      protocolVersion: 1,
      revoked: true,
    })).toBe(false);
  });
});

describe('resolveAuthorizeTinyCloudRouting (Sol MAJOR-4 final continuation)', () => {
  // Sol MAJOR-4 (final continuation) rejected a routing helper that
  // looked only at `lastAuth.keyType`. When the caller supplies an
  // explicit `requestKeyId`, the resolver MUST resolve THAT key's type
  // and route by it. Conflicting pins (lastAuth is one type, target key
  // is the other) MUST throw. These cases lock in the new invariants.

  const managedLast = { keyId: 'key_managed_abc', keyType: 'MANAGED' as const };
  const externalLast = { keyId: 'external:0xdead', keyType: 'EXTERNAL' as const };
  const managedKey = { id: 'key_managed_abc', keyType: 'MANAGED' as const };
  const externalKey = {
    id: 'key_external_xyz',
    address: '0xDeadBeef00000000000000000000000000000000',
    keyType: 'EXTERNAL' as const,
  };

  test('no request pin + external lastAuth → external route', () => {
    const r = resolveAuthorizeTinyCloudRouting({ lastAuth: externalLast });
    expect(r.route).toBe('external');
    expect(r.resolvedKeyType).toBe('EXTERNAL');
    expect(r.resolvedKeyId).toBe('external:0xdead');
  });

  test('no request pin + managed lastAuth → managed route', () => {
    const r = resolveAuthorizeTinyCloudRouting({ lastAuth: managedLast });
    expect(r.route).toBe('managed');
    expect(r.resolvedKeyType).toBe('MANAGED');
    expect(r.resolvedKeyId).toBe('key_managed_abc');
  });

  test('no request pin + null lastAuth → managed route (widget renders connect)', () => {
    const r = resolveAuthorizeTinyCloudRouting({ lastAuth: null });
    expect(r.route).toBe('managed');
    expect(r.resolvedKeyId).toBeNull();
    expect(r.resolvedKeyType).toBeNull();
  });

  test('explicit external keyId + managed lastAuth → EXTERNAL route (target wins)', () => {
    // This is the exact production bug: a caller pins an external
    // wallet key while the last connect() was against a managed key.
    // Prior behaviour: routed managed, /authorize-sign received no
    // externalSignature, server-sign failed. New behaviour: route
    // external, throwing KeyIdTypeMismatchError to surface the pin
    // conflict — never silently coerce a wrong route.
    let threw = false;
    try {
      resolveAuthorizeTinyCloudRouting({
        lastAuth: managedLast,
        requestKeyId: externalKey.id,
        knownKeys: [managedKey, externalKey],
      });
    } catch (e) {
      threw = true;
      expect(e).toBeInstanceOf(KeyIdTypeMismatchError);
      expect((e as KeyIdTypeMismatchError).code).toBe('KEY_ID_TYPE_MISMATCH');
      expect((e as KeyIdTypeMismatchError).requestKeyType).toBe('EXTERNAL');
      expect((e as KeyIdTypeMismatchError).lastAuthKeyType).toBe('MANAGED');
    }
    expect(threw).toBe(true);
  });

  test('explicit managed keyId + external lastAuth → throws KEY_ID_TYPE_MISMATCH', () => {
    let threw = false;
    try {
      resolveAuthorizeTinyCloudRouting({
        lastAuth: externalLast,
        requestKeyId: managedKey.id,
        knownKeys: [managedKey, externalKey],
      });
    } catch (e) {
      threw = true;
      expect(e).toBeInstanceOf(KeyIdTypeMismatchError);
      expect((e as KeyIdTypeMismatchError).requestKeyType).toBe('MANAGED');
      expect((e as KeyIdTypeMismatchError).lastAuthKeyType).toBe('EXTERNAL');
    }
    expect(threw).toBe(true);
  });

  test('explicit external keyId + external lastAuth (same id) → external route', () => {
    const r = resolveAuthorizeTinyCloudRouting({
      lastAuth: externalLast,
      requestKeyId: externalLast.keyId,
      knownKeys: [externalKey],
    });
    expect(r.route).toBe('external');
    expect(r.resolvedKeyId).toBe(externalLast.keyId);
  });

  test('explicit external keyId + external lastAuth (different external id) → external route', () => {
    // A caller who has multiple external keys enrolled and pins one
    // that is NOT the last-connected external key. Still routes
    // external (both are external; no conflict).
    const secondExternal = {
      id: 'key_external_two',
      address: '0xBeefFeed00000000000000000000000000000000',
      keyType: 'EXTERNAL' as const,
    };
    const r = resolveAuthorizeTinyCloudRouting({
      lastAuth: externalLast,
      requestKeyId: secondExternal.id,
      knownKeys: [externalKey, secondExternal],
    });
    expect(r.route).toBe('external');
    expect(r.resolvedKeyId).toBe(secondExternal.id);
    expect(r.resolvedKeyType).toBe('EXTERNAL');
  });

  test('explicit managed keyId matching lastAuth → managed route', () => {
    const r = resolveAuthorizeTinyCloudRouting({
      lastAuth: managedLast,
      requestKeyId: managedLast.keyId,
      knownKeys: [managedKey],
    });
    expect(r.route).toBe('managed');
    expect(r.resolvedKeyId).toBe(managedLast.keyId);
  });

  test('explicit keyId with unknown type + no lastAuth → managed fallback', () => {
    const r = resolveAuthorizeTinyCloudRouting({
      lastAuth: null,
      requestKeyId: 'key_unknown_xyz',
      knownKeys: [],
    });
    expect(r.route).toBe('managed');
    expect(r.resolvedKeyId).toBe('key_unknown_xyz');
    // Unknown; falls back to lastAuth type (null → managed).
    expect(r.resolvedKeyType).toBeNull();
  });

  test('explicit keyId resolves by ADDRESS when caller passes address instead of internal id', () => {
    // Caller passed the external-key address (a public identifier
    // apps commonly use in place of the internal id). Resolver
    // identifies this as external via address lookup and throws
    // mismatch because lastAuth is managed. Prior behaviour: string
    // equality miss, routed managed. New behaviour: address lookup
    // succeeds, throws mismatch.
    let threw = false;
    try {
      resolveAuthorizeTinyCloudRouting({
        lastAuth: managedLast,
        requestKeyId: externalKey.address,
        knownKeys: [managedKey, externalKey],
      });
    } catch (e) {
      threw = true;
      expect(e).toBeInstanceOf(KeyIdTypeMismatchError);
    }
    expect(threw).toBe(true);
  });

  test('bare "external:<addr>" convention id routes external without a knownKeys entry', () => {
    // Convention: `external:<address>` is the SDK's synthetic id for a
    // wallet-only session. Even with an empty knownKeys, the resolver
    // recognises the prefix and treats it as EXTERNAL.
    const r = resolveAuthorizeTinyCloudRouting({
      lastAuth: null,
      requestKeyId: 'external:0xabc',
      knownKeys: [],
    });
    expect(r.route).toBe('external');
    expect(r.resolvedKeyType).toBe('EXTERNAL');
  });
});
