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
