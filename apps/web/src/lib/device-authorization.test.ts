// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  approvedDevicePermissions,
  cleanConsentText,
  decodeBase64UrlJson,
  decodeDelegatePermissionsParam,
  readDelegatePermissionsParam,
  delegationPasteCode,
  deviceLifetimeOptions,
  deviceRequestReason,
  deviceRequestTtlSeconds,
  encodeBase64UrlJson,
  loadVerifiedDeviceRequest,
  SHARE_ONLY_DEVICE_REASON,
  type DevicePermission,
  type DeviceRequestRecord,
} from './device-authorization';

const space = 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default';
// The CLI's built-in publishing manifest (TC-539 acceptance scope).
const requested: DevicePermission[] = [
  { service: 'tinycloud.kv', space: 'default', path: 'xyz.tinycloud.share/shares/', actions: ['tinycloud.kv/put', 'tinycloud.kv/get'] },
  { service: 'tinycloud.kv', space: 'default', path: 'shares/', actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/metadata', 'tinycloud.kv/list'] },
  { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
];

describe('approvedDevicePermissions', () => {
  test('maps signed ReCap grants back onto the request, in request order', () => {
    // `/api/delegate` reports grants as parsed from the SIWE ReCap: short
    // service names, full space URIs, sorted entries and abilities.
    const granted = [
      { service: 'capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
      { service: 'kv', space, path: 'shares/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put'] },
      { service: 'kv', space, path: 'xyz.tinycloud.share/shares/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
    ];
    expect(approvedDevicePermissions(requested, granted)).toEqual([
      requested[0],
      { ...requested[1], actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/list'] },
      requested[2],
    ]);
  });

  test('omits unchecked capabilities and keeps the legacy Share binding unchanged', () => {
    expect(approvedDevicePermissions(requested, [
      { service: 'capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
    ])).toEqual([requested[2]]);

    const share = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    expect(approvedDevicePermissions(share, [
      { service: 'capabilities', space: 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:applications', path: '', actions: ['tinycloud.capabilities/read'] },
    ])).toEqual(share);
  });

  test('refuses a delegation broader than the request or granting nothing', () => {
    const cases: unknown[] = [
      [{ service: 'kv', space, path: 'shares/', actions: ['tinycloud.kv/del'] }],
      [{ service: 'kv', space, path: 'other/', actions: ['tinycloud.kv/get'] }],
      [{ service: 'sql', space, path: 'shares/', actions: ['tinycloud.kv/get'] }],
      [{ service: 'kv', space: space.replace(':default', ':public'), path: 'shares/', actions: ['tinycloud.kv/get'] }],
      [],
      undefined,
    ];
    for (const granted of cases) expect(() => approvedDevicePermissions(requested, granted)).toThrow();
  });

  test('maps paths named like Object.prototype members', () => {
    const own: DevicePermission[] = ['constructor', 'toString', '__proto__'].map((path) => ({
      service: 'tinycloud.kv', space: 'default', path, actions: ['tinycloud.kv/get'],
    }));
    const granted = own.map((permission) => ({ service: 'kv', space, path: permission.path, actions: ['tinycloud.kv/get'] }));
    expect(approvedDevicePermissions(own, granted)).toEqual(own);
  });
});

describe('owner space URIs', () => {
  const lower = 'tinycloud:pkh:eip155:1:0x00000000000000000000000000000000000000ab:default';
  const signed = 'tinycloud:pkh:eip155:1:0x00000000000000000000000000000000000000aB:default';
  const request: DevicePermission[] = [{ service: 'tinycloud.kv', space: lower, path: 'shares/', actions: ['tinycloud.kv/get'] }];

  test('match the signed EIP-55 address and keep the request spelling', () => {
    expect(approvedDevicePermissions(request, [{ service: 'kv', space: signed, path: 'shares/', actions: ['tinycloud.kv/get'] }]))
      .toEqual(request);
  });

  test('still compare chain, address, and space name', () => {
    for (const space of [signed.replace(':1:', ':10:'), signed.replace('aB:', 'aC:'), signed.replace(':default', ':Default')]) {
      expect(() => approvedDevicePermissions(request, [{ service: 'kv', space, path: 'shares/', actions: ['tinycloud.kv/get'] }])).toThrow();
    }
  });
});

describe('base64url JSON parameters', () => {
  test('round-trip non-ASCII reasons as UTF-8, including CLI-encoded payloads', () => {
    const payload = { permissions: requested, reason: 'Publier le résumé à José' };
    expect(decodeBase64UrlJson(encodeBase64UrlJson(payload))).toEqual(payload);
    // What a Node CLI sends: Buffer UTF-8 base64url.
    expect(decodeBase64UrlJson(Buffer.from(JSON.stringify(payload)).toString('base64url'))).toEqual(payload);
  });

  test('paste codes carry non-Latin-1 reasons in the form the CLI decodes', () => {
    const payload = { delegationHeader: { Authorization: 'Bearer x' }, reason: '公開 Publier le résumé à José' };
    // btoa(JSON.stringify(payload)) throws InvalidCharacterError here.
    expect(() => btoa(JSON.stringify(payload))).toThrow();
    // js-sdk CLI (master, 0.10.0, 1.0.0-beta.14): Buffer.from(code, "base64").toString("utf-8").
    expect(JSON.parse(Buffer.from(delegationPasteCode(payload), 'base64').toString('utf-8'))).toEqual(payload);
    // ASCII payloads keep the exact pre-TC-539 encoding.
    const ascii = { delegationHeader: { Authorization: 'Bearer x' }, reason: 'Publish notes' };
    expect(delegationPasteCode(ascii)).toBe(btoa(JSON.stringify(ascii)));
  });

  test('refuses permissions parameters that are not a readable, non-empty list', () => {
    const invalidUtf8 = Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x7d]).toString('base64url');
    for (const value of [
      invalidUtf8,
      'not base64 JSON',
      encodeBase64UrlJson({ reason: 'only a reason' }),
      encodeBase64UrlJson({ permissions: [] }),
      encodeBase64UrlJson({ permissions: { service: 'tinycloud.kv' } }),
      // A malformed entry (no path, non-string space, non-string actions)
      // must be refused as unreadable rather than reach the page.
      encodeBase64UrlJson({ permissions: [{ service: 'tinycloud.encryption', space: 'encryption', actions: ['tinycloud.encryption/decrypt'] }] }),
      encodeBase64UrlJson({ permissions: [{ ...requested[0], space: 7 }] }),
      encodeBase64UrlJson({ permissions: [{ ...requested[0], actions: [1] }] }),
      encodeBase64UrlJson({ permissions: [null] }),
      encodeBase64UrlJson(null),
    ]) {
      expect(() => decodeDelegatePermissionsParam(value)).toThrow();
    }
    expect(decodeDelegatePermissionsParam(encodeBase64UrlJson({ permissions: requested, reason: '公開' })))
      .toEqual({ permissions: requested, reason: '公開' });
  });

  test('reads the permissions parameter by presence: only an absent one means default abilities', () => {
    expect(readDelegatePermissionsParam(new URLSearchParams('did=x&host=h'))).toBeNull();
    for (const query of ['permissions=', 'permissions', 'did=x&permissions=&host=h']) {
      expect(() => readDelegatePermissionsParam(new URLSearchParams(query)), query).toThrow();
    }
    expect(readDelegatePermissionsParam(new URLSearchParams({ permissions: encodeBase64UrlJson({ permissions: requested }) })))
      .toEqual({ permissions: requested, reason: undefined });
  });
});

const day = 86_400;
function record(overrides: Partial<DeviceRequestRecord> = {}): DeviceRequestRecord {
  return {
    id: 'transaction-1',
    userCode: 'ABCDEFGH',
    sessionDid: 'did:key:z6Mk#z6Mk',
    publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'x' },
    relayPublicJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    permissions: requested,
    nodeOrigin: 'https://tee.node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
    transactionExpiresAt: '2026-10-02T12:10:00.000Z',
    delegationExpiresAt: new Date(Date.parse('2026-10-02T12:10:00.000Z') + 7 * day * 1000).toISOString(),
    ...overrides,
  };
}

describe('device request lifetime', () => {
  test('uses the requested TTL, or derives it from an older API\'s padded deadline', () => {
    expect(deviceRequestTtlSeconds(record({ delegationTtlSeconds: 60 }))).toBe(60);
    // Older API: no delegationTtlSeconds; deadline = transaction deadline + TTL.
    expect(deviceRequestTtlSeconds(record())).toBe(7 * day);
    expect(deviceRequestTtlSeconds(record({
      delegationExpiresAt: new Date(Date.parse('2026-10-02T12:10:00.000Z') + 90 * day * 1000).toISOString(),
    }))).toBe(30 * day);
  });

  test('never offers more than the requested lifetime', () => {
    expect(deviceLifetimeOptions(60)).toEqual([{ seconds: 60, label: '1 minute (requested maximum)' }]);
    expect(deviceLifetimeOptions(30 * day).map((option) => option.seconds)).toEqual([day, 7 * day, 30 * day]);
  });
});

describe('device consent text', () => {
  test('older APIs: the legacy request falls back to the Share copy', () => {
    const share = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    expect(deviceRequestReason(record({ permissions: share }))).toBe(SHARE_ONLY_DEVICE_REASON);
    expect(deviceRequestReason(record({ reason: 'Publish notes' }))).toBe('Publish notes');
  });

  test('strips bidirectional and invisible characters', () => {
    expect(cleanConsentText(' Pay\u202e me\u200b\u2060\u061c\u180e\ufeff\u00ad\u034f\u115f\u1160\u3164\uffa0\u{e0041}\u{e007f}\n now ')).toBe('Pay me now');
    // Any other format or default-ignorable character: U+FFF9, U+1D173, U+180B, U+FE00.
    expect(cleanConsentText('Pay\ufff9\u{1d173}\u180b\ufe00 me')).toBe('Pay me');
    expect(cleanConsentText('公開 résumé')).toBe('公開 résumé');
  });
});

describe('loadVerifiedDeviceRequest', () => {
  const server = record({ reason: 'Publish notes' });
  const link = {
    transactionId: server.id,
    sessionDid: server.sessionDid,
    publicJwk: { x: 'x', crv: 'Ed25519', kty: 'OKP' },
    relayPublicJwk: server.relayPublicJwk,
    nodeOrigin: server.nodeOrigin,
    shareOrigin: server.shareOrigin,
    permissions: requested,
    expiry: `${7 * day}s`,
  };
  const withLookup = async <T>(body: DeviceRequestRecord | null, run: () => Promise<T>) => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify(body ?? { error: 'not_found' }), { status: body ? 200 : 404 })) as unknown as typeof fetch;
    try {
      return await run();
    } finally {
      globalThis.fetch = original;
    }
  };

  test('returns the server request when every link binding matches', async () => {
    expect(await withLookup(server, () => loadVerifiedDeviceRequest('', 'ABCD-EFGH', link))).toEqual(server);
  });

  test('refuses links that differ from the server request or have no live request', async () => {
    const tampered = [
      { ...link, relayPublicJwk: { kty: 'EC', crv: 'P-256', x: 'attacker', y: 'y' } },
      { ...link, permissions: [...requested, { service: 'tinycloud.kv', space: 'default', path: 'extra/', actions: ['tinycloud.kv/get'] }] },
      { ...link, transactionId: 'other-transaction' },
      { ...link, nodeOrigin: 'https://evil.example' },
      { ...link, expiry: `${7 * day + 1}s` },
      { ...link, expiry: `${90 * day}s` },
      { ...link, expiry: '90d' },
      { ...link, expiry: '' },
    ];
    for (const candidate of tampered) {
      await expect(withLookup(server, () => loadVerifiedDeviceRequest('', 'ABCD-EFGH', candidate))).rejects.toThrow('does not match');
    }
    await expect(withLookup(null, () => loadVerifiedDeviceRequest('', 'ABCD-EFGH', link))).rejects.toThrow('invalid or expired');
    await expect(withLookup(server, () => loadVerifiedDeviceRequest('', '', link))).rejects.toThrow('invalid or expired');
  });
});
