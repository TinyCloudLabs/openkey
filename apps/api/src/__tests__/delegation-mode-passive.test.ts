// TC-3810 (passive OpenKey parser prerequisite): accept and preserve the signed
// top-level ReCap field `xyz.tinycloud.policy/delegationMode` ("terminal" |
// "attenuable") without changing OpenKey's signing defaults.
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { actionKey, parsePreparedRecap, prepareDelegationSession } from '../routes/delegate-session';
import { appKeyRefusalForSiwe } from '../services/app-key-refusal';
import { withExpirationTime } from '../services/approval-expiry';
import { extractRecapAttenuationFromSiwe } from '../services/authorization-signing';
import {
  DELEGATION_MODE_KEY,
  checkSignedSubset,
  decodeRecapUri,
  parseStrictSiwe,
  serializeSiwe,
  type DelegationMode,
} from '../services/signed-subset';
import { narrowSiwePreservingImmutable } from '../services/siwe-narrow';

const address = '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const issuedAt = '2026-11-08T00:00:00.000Z';
const expirationTime = '2026-11-15T00:00:00.000Z';
const shorter = '2026-11-09T00:00:00.000Z';

function baseRequest(): string {
  return prepareSession({
    address,
    chainId: 1,
    domain: 'app.example.com',
    issuedAt,
    expirationTime,
    spaceId: space,
    jwk,
    abilities: {
      kv: { 'notes/': ['tinycloud.kv/get', 'tinycloud.kv/put'], '': ['tinycloud.kv/list'] },
      capabilities: { '': ['tinycloud.capabilities/read'] },
    },
  }).siwe as string;
}

const baseline = baseRequest();
const allIds = new Set(parsePreparedRecap(baseline).flatMap((e) => e.actions.map((a) => actionKey(e, a))));
const withoutPut = new Set([...allIds].filter((id) => !id.endsWith('tinycloud.kv/put')));

function replaceRecapJson(siwe: string, json: string): string {
  const line = siwe.split('\n').find((l) => l.startsWith('- urn:recap:'))!;
  return siwe.replace(line, `- urn:recap:${Buffer.from(json, 'utf8').toString('base64url')}`);
}

function decodeRawRecapJson(siwe: string): string {
  const line = siwe.split('\n').find((l) => l.startsWith('- urn:recap:'))!;
  return Buffer.from(line.slice('- urn:recap:'.length), 'base64url').toString('utf8');
}

function withDelegationMode(siwe: string, mode: DelegationMode): string {
  const parsed = JSON.parse(decodeRawRecapJson(siwe)) as Record<string, unknown>;
  return replaceRecapJson(
    siwe,
    JSON.stringify({
      att: parsed.att,
      prf: parsed.prf,
      [DELEGATION_MODE_KEY]: mode,
    }),
  );
}

function narrowWith(original: string, selected: Set<string>, includeBaselineCaveats = true) {
  const entries = parsePreparedRecap(original)
    .map((e) => ({ ...e, actions: e.actions.filter((a) => selected.has(actionKey(e, a))) }))
    .filter((e) => e.actions.length > 0);
  return narrowSiwePreservingImmutable({
    originalSiwe: original,
    narrowedEntries: entries,
    address,
    chainId: 1,
    domain: 'app.example.com',
    issuedAt,
    expirationTime,
    spaceId: space,
    jwk,
    ...(includeBaselineCaveats ? { baselineCaveats: extractRecapAttenuationFromSiwe(original) } : {}),
  });
}

describe('ReCap delegationMode strict parser', () => {
  test('accepts absent, terminal, and attenuable delegationMode values', () => {
    const absent = parseStrictSiwe(baseline);
    expect(absent.ok).toBe(true);
    if (!absent.ok) return;
    expect(absent.siwe.recap?.delegationMode).toBeUndefined();
    expect(Object.hasOwn(absent.siwe.recap!, 'delegationMode')).toBe(false);

    for (const mode of ['terminal', 'attenuable'] as const) {
      const message = withDelegationMode(baseline, mode);
      const parsed = parseStrictSiwe(message);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) continue;
      expect(parsed.siwe.recap?.delegationMode).toBe(mode);
      expect(serializeSiwe(parsed.siwe)).toBe(message);
      expect(parsePreparedRecap(message).length).toBeGreaterThan(0);
      expect(appKeyRefusalForSiwe(message, parsePreparedRecap(message))).toBeNull();
    }
  });

  const attJson = JSON.stringify(JSON.parse(decodeRawRecapJson(baseline)).att);

  const malformed: Array<[string, string]> = [
    ['null value', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":null}`],
    ['wrong-case string "Terminal"', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"Terminal"}`],
    ['wrong-case string "ATTENUABLE"', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"ATTENUABLE"}`],
    ['empty string', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":""}`],
    ['unknown string', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"readonly"}`],
    ['number value', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":1}`],
    ['boolean value', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":true}`],
    ['array value', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":["terminal"]}`],
    ['object value', `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":{"mode":"terminal"}}`],
    [
      'duplicate key (different values)',
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"terminal","${DELEGATION_MODE_KEY}":"attenuable"}`,
    ],
    [
      'duplicate key (identical values)',
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"terminal","${DELEGATION_MODE_KEY}":"terminal"}`,
    ],
    [
      'duplicate key (unicode-escaped slash equivalent)',
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"terminal","xyz.tinycloud.policy\\u002fdelegationMode":"attenuable"}`,
    ],
    [
      'duplicate key (backslash-escaped slash equivalent)',
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"attenuable","xyz.tinycloud.policy\\/delegationMode":"terminal"}`,
    ],
    [
      'valid mode plus an unknown top-level field',
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"terminal","extra":"nope"}`,
    ],
    [
      'unknown top-level field alone',
      `{"att":${attJson},"prf":[],"xyz.tinycloud.policy/other":"terminal"}`,
    ],
  ];

  for (const [label, json] of malformed) {
    test(`refuses ${label}`, () => {
      const uri = `urn:recap:${Buffer.from(json, 'utf8').toString('base64url')}`;
      expect(() => decodeRecapUri(uri)).toThrow();
      const message = replaceRecapJson(baseline, json);
      expect(parseStrictSiwe(message).ok).toBe(false);
    });
  }
});

describe('round-trip, expiry edits, and narrowing preserve delegationMode', () => {
  for (const mode of ['terminal', 'attenuable'] as const) {
    test(`unchanged round-trip preserves exact bytes for ${mode}`, () => {
      const requested = withDelegationMode(baseline, mode);
      const parsed = parseStrictSiwe(requested);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      expect(serializeSiwe(parsed.siwe)).toBe(requested);
      expect(
        checkSignedSubset({
          requested,
          signed: requested,
          selectedActionIds: allIds,
          longerExpiryAllowed: false,
        }),
      ).toEqual({ ok: true });
    });

    test(`expiry edit preserves ${mode} and passes checkSignedSubset`, () => {
      const requested = withDelegationMode(baseline, mode);
      const edited = withExpirationTime(requested, shorter);
      expect(edited).not.toBeNull();
      const parsed = parseStrictSiwe(edited!);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      expect(parsed.siwe.recap?.delegationMode).toBe(mode);
      expect(
        checkSignedSubset({
          requested,
          signed: edited!,
          selectedActionIds: allIds,
          ownerPickedExpiration: shorter,
          longerExpiryAllowed: false,
        }),
      ).toEqual({ ok: true });
    });

    for (const includeBaselineCaveats of [true, false]) {
      test(`narrowing preserves ${mode} (baselineCaveats=${includeBaselineCaveats}) in canonical key order`, () => {
        const requested = withDelegationMode(baseline, mode);
        const result = narrowWith(requested, withoutPut, includeBaselineCaveats);
        expect(result.ok, result.ok ? '' : result.message).toBe(true);
        if (!result.ok) return;

        const parsed = parseStrictSiwe(result.siwe);
        expect(parsed.ok).toBe(true);
        if (!parsed.ok) return;
        expect(parsed.siwe.recap?.delegationMode).toBe(mode);

        // Verify canonical top-level key order: att, prf, xyz.tinycloud.policy/delegationMode.
        const rawJson = decodeRawRecapJson(result.siwe);
        expect(Object.keys(JSON.parse(rawJson) as Record<string, unknown>)).toEqual([
          'att',
          'prf',
          DELEGATION_MODE_KEY,
        ]);

        expect(
          checkSignedSubset({
            requested,
            signed: result.siwe,
            selectedActionIds: withoutPut,
            longerExpiryAllowed: false,
          }),
        ).toEqual({ ok: true });
      });
    }
  }

  test('narrowing without delegationMode never adds one', () => {
    for (const includeBaselineCaveats of [true, false]) {
      const result = narrowWith(baseline, withoutPut, includeBaselineCaveats);
      expect(result.ok, result.ok ? '' : result.message).toBe(true);
      if (!result.ok) return;
      const parsed = parseStrictSiwe(result.siwe);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      expect(parsed.siwe.recap?.delegationMode).toBeUndefined();
      expect(Object.keys(JSON.parse(decodeRawRecapJson(result.siwe)) as Record<string, unknown>)).toEqual([
        'att',
        'prf',
      ]);
      expect(
        checkSignedSubset({
          requested: baseline,
          signed: result.siwe,
          selectedActionIds: withoutPut,
          longerExpiryAllowed: false,
        }),
      ).toEqual({ ok: true });
    }
  });

  test('narrowing refuses an original SIWE whose delegationMode is malformed or duplicated', () => {
    const attJson = JSON.stringify(JSON.parse(decodeRawRecapJson(baseline)).att);
    const entries = parsePreparedRecap(baseline)
      .map((e) => ({ ...e, actions: e.actions.filter((a) => withoutPut.has(actionKey(e, a))) }))
      .filter((e) => e.actions.length > 0);
    for (const json of [
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":null}`,
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"Terminal"}`,
      `{"att":${attJson},"prf":[],"${DELEGATION_MODE_KEY}":"terminal","xyz.tinycloud.policy\\u002fdelegationMode":"attenuable"}`,
    ]) {
      const bad = replaceRecapJson(baseline, json);
      const result = narrowSiwePreservingImmutable({
        originalSiwe: bad,
        narrowedEntries: entries,
        address,
        chainId: 1,
        domain: 'app.example.com',
        issuedAt,
        expirationTime,
        spaceId: space,
        jwk,
      });
      expect(result.ok).toBe(false);
    }
  });
});

describe('checkSignedSubset refuses delegationMode mismatches', () => {
  const terminal = withDelegationMode(baseline, 'terminal');
  const attenuable = withDelegationMode(baseline, 'attenuable');

  const mismatches: Array<[string, string, string]> = [
    ['terminal dropped to absent', terminal, baseline],
    ['attenuable dropped to absent', attenuable, baseline],
    ['absent added as terminal', baseline, terminal],
    ['absent added as attenuable', baseline, attenuable],
    ['terminal flipped to attenuable', terminal, attenuable],
    ['attenuable flipped to terminal', attenuable, terminal],
  ];

  for (const [name, requested, signed] of mismatches) {
    test(`refuses when ${name}`, () => {
      expect(
        checkSignedSubset({
          requested,
          signed,
          selectedActionIds: allIds,
          longerExpiryAllowed: false,
        }),
      ).toMatchObject({
        ok: false,
        code: 'signed_exceeds_request',
        reason: 'delegation_mode',
      });
    });
  }

  test('refuses a narrowed signed result whose mode was dropped or flipped', () => {
    const requestedTerminal = withDelegationMode(baseline, 'terminal');
    const narrowedNoMode = narrowWith(baseline, withoutPut, true);
    expect(narrowedNoMode.ok).toBe(true);
    if (!narrowedNoMode.ok) return;

    expect(
      checkSignedSubset({
        requested: requestedTerminal,
        signed: narrowedNoMode.siwe,
        selectedActionIds: withoutPut,
        longerExpiryAllowed: false,
      }),
    ).toMatchObject({
      ok: false,
      code: 'signed_exceeds_request',
      reason: 'delegation_mode',
    });

    const narrowedFlipped = withDelegationMode(narrowedNoMode.siwe, 'attenuable');
    expect(
      checkSignedSubset({
        requested: requestedTerminal,
        signed: narrowedFlipped,
        selectedActionIds: withoutPut,
        longerExpiryAllowed: false,
      }),
    ).toMatchObject({
      ok: false,
      code: 'signed_exceeds_request',
      reason: 'delegation_mode',
    });
  });
});

describe('passive only: existing minting behaviour unchanged', () => {
  test('prepareDelegationSession does not emit xyz.tinycloud.policy/delegationMode', () => {
    const result = prepareDelegationSession({
      address,
      chainId: 1,
      prefix: 'default',
      jwk,
      permissions: [{ service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get'] }],
      expiryMs: 60 * 60 * 1000,
    });
    const parsed = parseStrictSiwe(result.prepared.siwe);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.siwe.recap?.delegationMode).toBeUndefined();
    expect(Object.keys(JSON.parse(decodeRawRecapJson(result.prepared.siwe)) as Record<string, unknown>)).toEqual([
      'att',
      'prf',
    ]);
  });
});
