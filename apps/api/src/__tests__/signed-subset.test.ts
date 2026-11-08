// The pre-sign rule: what OpenKey signs is a subset of what the app requested
// (including requester and requestee) and of what the owner left selected.
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { FIXTURE as URN_FORM } from './authorize-sign-urn-form.fixture';
import { actionKey, parsePreparedRecap } from '../routes/delegate-session';
import { narrowSiwePreservingImmutable } from '../services/siwe-narrow';
import { extractRecapAttenuationFromSiwe } from '../services/authorization-signing';
import { checkSignedSubset, parseStrictSiwe, recapStatement, serializeSiwe, type SignedSubsetInput } from '../services/signed-subset';

const address = '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const issuedAt = '2026-11-08T00:00:00.000Z';
const expirationTime = '2026-11-15T00:00:00.000Z';
const later = '2026-12-15T00:00:00.000Z';
const shorter = '2026-11-09T00:00:00.000Z';

function request(extra: Record<string, unknown> = {}): string {
  return prepareSession({
    address, chainId: 1, domain: 'app.example.com', issuedAt, expirationTime, spaceId: space, jwk,
    abilities: {
      kv: { 'notes/': ['tinycloud.kv/get', 'tinycloud.kv/put'], '': ['tinycloud.kv/list'] },
      capabilities: { '': ['tinycloud.capabilities/read'] },
    },
    rawAbilities: { [network]: ['tinycloud.encryption/decrypt'] },
    ...extra,
  }).siwe as string;
}

const requested = request();
const allIds = new Set(parsePreparedRecap(requested).flatMap((e) => e.actions.map((a) => actionKey(e, a))));
const withoutPut = new Set([...allIds].filter((id) => !id.endsWith('tinycloud.kv/put')));

function narrowed(original: string, selected: Set<string>): string {
  const entries = parsePreparedRecap(original)
    .map((e) => ({ ...e, actions: e.actions.filter((a) => selected.has(actionKey(e, a))) }))
    .filter((e) => e.actions.length > 0);
  const notBefore = original.match(/^Not Before: (.+)$/m)?.[1];
  const result = narrowSiwePreservingImmutable({
    originalSiwe: original, narrowedEntries: entries, address, chainId: 1, domain: 'app.example.com',
    issuedAt, expirationTime, spaceId: space, jwk,
    baselineCaveats: extractRecapAttenuationFromSiwe(original),
    ...(notBefore ? { notBefore } : {}),
  });
  if (!result.ok) throw new Error(result.message);
  return result.siwe;
}

/** The message with its ReCap payload rewritten and the statement written for the new capabilities. */
function withRecap(siwe: string, edit: (payload: { att: Record<string, Record<string, unknown[]>>; prf: unknown[] }) => void): string {
  const line = siwe.split('\n').find((l) => l.startsWith('- urn:recap:'))!;
  const payload = JSON.parse(Buffer.from(line.slice(12), 'base64url').toString('utf8'));
  edit(payload);
  const parsed = parseStrictSiwe(siwe.replace(line, `- urn:recap:${Buffer.from(JSON.stringify(payload)).toString('base64url')}`));
  if (!parsed.ok || !parsed.siwe.recap) throw new Error('rewritten ReCap did not parse');
  return serializeSiwe({ ...parsed.siwe, statement: recapStatement(parsed.siwe.recap.att) });
}

function recapJson(siwe: string, json: string): string {
  const line = siwe.split('\n').find((l) => l.startsWith('- urn:recap:'))!;
  return siwe.replace(line, `- urn:recap:${Buffer.from(json).toString('base64url')}`);
}

function check(signed: string, options: Partial<SignedSubsetInput> = {}) {
  return checkSignedSubset({ requested, signed, selectedActionIds: allIds, longerExpiryAllowed: false, ...options });
}

describe('strict SIWE parser', () => {
  const fixtures: Array<[string, string]> = [
    ['a WASM request with a ReCap and Not Before', request({ notBefore: '2026-11-08T00:00:01.000Z' })],
    ['a WASM request narrowed by the splice', narrowed(requested, withoutPut)],
    ['the captured URN-form request', URN_FORM.preparedSiwe],
    ['the captured URN-form signed message', URN_FORM.signedMessage],
  ];
  for (const [name, message] of fixtures) {
    test(`${name} parses and re-serializes byte for byte`, () => {
      const parsed = parseStrictSiwe(message);
      if (!parsed.ok) throw new Error(parsed.message);
      expect(serializeSiwe(parsed.siwe)).toBe(message);
      expect(parsed.siwe.recap?.att.size).toBeGreaterThan(0);
    });
  }

  test('reads every field, the optional ones included', () => {
    const message = [
      'https://app.example.com wants you to sign in with your Ethereum account:', address, '',
      'Sign in.', '', 'URI: did:key:z6Mk#z6Mk', 'Version: 1', 'Chain ID: 137', 'Nonce: abcdef123456',
      `Issued At: ${issuedAt}`, `Expiration Time: ${expirationTime}`, 'Not Before: 2026-11-08T00:00:01Z',
      'Request ID: req-1', 'Resources:', 'https://example.com/a'.replace(/^/, '- '),
    ].join('\n');
    const parsed = parseStrictSiwe(message);
    if (!parsed.ok) throw new Error(parsed.message);
    expect(parsed.siwe).toEqual({
      scheme: 'https', domain: 'app.example.com', address, statement: 'Sign in.', uri: 'did:key:z6Mk#z6Mk',
      version: '1', chainId: '137', nonce: 'abcdef123456', issuedAt, expirationTime,
      notBefore: '2026-11-08T00:00:01Z', requestId: 'req-1', resources: ['https://example.com/a'],
    });
  });

  const refused: Array<[string, (siwe: string) => string]> = [
    ['a repeated field', (s) => s.replace(/^(Nonce: .+)$/m, '$1\n$1')],
    ['fields out of order', (s) => s.replace(/^(Version: 1)\n(Chain ID: 1)$/m, '$2\n$1')],
    ['an unknown field', (s) => s.replace(/^(Nonce: .+)$/m, '$1\nAudience: someone')],
    ['an unknown line after the resources', (s) => `${s}\nTrailer`],
    ['a final line feed', (s) => `${s}\n`],
    ['a carriage return', (s) => s.replace('\nVersion', '\r\nVersion')],
    ['a missing Issued At', (s) => s.replace(/^Issued At: .+\n/m, '')],
    ['a short nonce', (s) => s.replace(/^Nonce: .+$/m, 'Nonce: abc')],
    ['a timestamp that is not RFC 3339', (s) => s.replace(/^Issued At: .+$/m, 'Issued At: Nov 8 2026')],
    ['version 2', (s) => s.replace('Version: 1', 'Version: 2')],
    ['a chain id with a leading zero', (s) => s.replace('Chain ID: 1', 'Chain ID: 01')],
    ['a repeated resource', (s) => `${s}\n- https://example.com/a\n- https://example.com/a`],
    ['two ReCaps', (s) => `${s}\n- urn:recap:${Buffer.from(`{"att":{"${space}/sql":{"tinycloud.sql/read":[{}]}},"prf":[]}`).toString('base64url')}`],
    ['a padded ReCap payload', (s) => s.replace(/^(- urn:recap:.+)$/m, '$1==')],
    ['a ReCap that is not base64url', (s) => s.replace(/^- urn:recap:.+$/m, '- urn:recap:%%%')],
    ['a ReCap JSON with a repeated key', (s) => recapJson(s, `{"att":{"${space}/kv":{"tinycloud.kv/get":[{}]}},"prf":[],"prf":[]}`)],
    ['a ReCap resource with a repeated ability', (s) => recapJson(s, `{"att":{"${space}/kv":{"tinycloud.kv/get":[{}],"tinycloud.kv/get":[{}]}},"prf":[]}`)],
    ['a ReCap with an unknown member', (s) => recapJson(s, `{"att":{"${space}/kv":{"tinycloud.kv/get":[{}]}},"prf":[],"ext":1}`)],
    ['a ReCap without prf', (s) => recapJson(s, `{"att":{"${space}/kv":{"tinycloud.kv/get":[{}]}}}`)],
    ['a ReCap ability with no caveat object', (s) => recapJson(s, `{"att":{"${space}/kv":{"tinycloud.kv/get":[]}},"prf":[]}`)],
    ['a ReCap ability without a namespace', (s) => recapJson(s, `{"att":{"${space}/kv":{"get":[{}]}},"prf":[]}`)],
    ['a ReCap that is not JSON', (s) => recapJson(s, '{"att":')],
  ];
  for (const [name, mutate] of refused) {
    test(`refuses ${name}`, () => {
      const message = mutate(requested);
      expect(message).not.toBe(requested);
      expect(parseStrictSiwe(message).ok).toBe(false);
    });
  }
});

describe('signed ⊆ requested ⊆ selection', () => {
  test('the unchanged request passes', () => {
    expect(check(requested)).toEqual({ ok: true });
  });

  test('a narrowed request passes for the narrowed selection', () => {
    const signed = narrowed(requested, withoutPut);
    expect(signed).not.toBe(requested);
    expect(check(signed, { selectedActionIds: withoutPut })).toEqual({ ok: true });
  });

  test('the captured URN-form preview passes for its selection', () => {
    expect(checkSignedSubset({
      requested: URN_FORM.preparedSiwe, signed: URN_FORM.signedMessage,
      selectedActionIds: new Set(URN_FORM.previewSelectedActionKeys), longerExpiryAllowed: false,
    })).toEqual({ ok: true });
  });

  test('a narrowed request whose request carries a statement prefix keeps the prefix', () => {
    const prefixed = requested.replace('\n\nI further authorize', '\n\nSign in to App. I further authorize');
    const signed = narrowed(requested, withoutPut).replace('\n\nI further authorize', '\n\nSign in to App. I further authorize');
    expect(check(signed, { requested: prefixed, selectedActionIds: withoutPut })).toEqual({ ok: true });
    expect(check(narrowed(requested, withoutPut), { requested: prefixed, selectedActionIds: withoutPut }))
      .toMatchObject({ ok: false, reason: 'statement' });
  });

  const drift: Array<[string, string, (siwe: string) => string]> = [
    ['requester', 'the domain', (s) => s.replace(/^app\.example\.com /, 'evil.example.com ')],
    ['requester', 'a scheme', (s) => s.replace(/^app\.example\.com /, 'https://app.example.com ')],
    ['address', 'the account', (s) => s.replace(address, '0x0000000000000000000000000000000000000001')],
    ['address', 'the account spelling', (s) => s.replace(address, address.toLowerCase())],
    ['requestee', 'the URI', (s) => s.replace(/^URI: did:key:z6Mk/m, 'URI: did:key:z6Mx')],
    ['chain_id', 'the chain', (s) => s.replace('Chain ID: 1', 'Chain ID: 10')],
    ['nonce', 'the nonce', (s) => s.replace(/^(Nonce: .+)$/m, '$1x')],
    ['issued_at', 'the issued-at time', (s) => s.replace(issuedAt, '2026-11-07T00:00:00.000Z')],
    ['not_before', 'an added not-before time', (s) => s.replace(/^(Expiration Time: .+)$/m, '$1\nNot Before: 2026-11-08T00:00:01Z')],
    ['request_id', 'an added request id', (s) => s.replace(/^(Expiration Time: .+)$/m, '$1\nRequest ID: other')],
    ['expiration', 'a later expiration', (s) => s.replace(expirationTime, later)],
    ['expiration', 'a shorter expiration nobody picked', (s) => s.replace(expirationTime, shorter)],
    ['statement', 'the statement', (s) => s.replace('I further authorize', 'Also send all keys. I further authorize')],
    ['statement', 'a statement for other capabilities', (s) => s.replace("'get', 'put'", "'get'")],
    ['resources', 'an extra resource', (s) => `${s}\n- https://example.com/extra`],
  ];
  for (const [reason, name, mutate] of drift) {
    test(`a change to ${name} is refused (${reason})`, () => {
      const signed = mutate(requested);
      expect(signed).not.toBe(requested);
      expect(check(signed)).toMatchObject({ ok: false, code: 'signed_exceeds_request', reason });
    });
  }

  test('the version field is compared (requested 1, any other value is unreadable)', () => {
    expect(check(requested.replace('Version: 1', 'Version: 2'))).toMatchObject({ ok: false, reason: 'signed_unparsable' });
  });

  const widening: Array<[string, string, (p: { att: Record<string, Record<string, unknown[]>>; prf: unknown[] }) => void]> = [
    ['capability', 'an added ability', (p) => { p.att[`${space}/kv`]!['tinycloud.kv/del'] = [{}]; }],
    ['capability', 'an added resource', (p) => { p.att[`${space}/sql`] = { 'tinycloud.sql/read': [{}] }; }],
    ['capability', 'a changed caveat', (p) => { p.att[`${space}/kv`]!['tinycloud.kv/list'] = [{ path: 'x' }]; }],
    ['proof', 'an added proof', (p) => { p.prf.push('bafyproof'); }],
  ];
  for (const [reason, name, edit] of widening) {
    test(`${name} is refused (${reason})`, () => {
      expect(check(withRecap(requested, edit))).toMatchObject({ ok: false, reason });
    });
  }

  test('a dropped caveat on a surviving ability is refused', () => {
    const withCaveat = withRecap(requested, (p) => { p.att[`${space}/kv`]!['tinycloud.kv/list'] = [{ path: 'x' }]; });
    expect(check(requested, { requested: withCaveat })).toMatchObject({ ok: false, reason: 'capability' });
  });

  test('an item the owner unchecked is refused', () => {
    expect(check(requested, { selectedActionIds: withoutPut })).toMatchObject({ ok: false, reason: 'selection' });
  });

  test('unreadable bytes are refused before anything else', () => {
    expect(check(`${requested}\n`)).toMatchObject({ ok: false, reason: 'signed_unparsable' });
    expect(check(requested, { requested: `${requested}\n` })).toMatchObject({ ok: false, reason: 'request_unparsable' });
  });
});

describe('expiry: the owner may pick another time; longer only with the app opt-in', () => {
  const at = (time: string) => requested.replace(expirationTime, time);

  test('an owner-picked longer expiry passes when the app opted in', () => {
    expect(check(at(later), { ownerPickedExpiration: later, longerExpiryAllowed: true })).toEqual({ ok: true });
  });

  test('a longer expiry the owner did not pick is refused, opt-in or not', () => {
    expect(check(at(later), { longerExpiryAllowed: true })).toMatchObject({ ok: false, reason: 'expiration' });
  });

  test('an owner-picked longer expiry is refused without the app opt-in (and for a CLI handoff)', () => {
    expect(check(at(later), { ownerPickedExpiration: later, longerExpiryAllowed: false }))
      .toMatchObject({ ok: false, reason: 'expiration' });
  });

  test('an owner-picked shorter expiry passes without the opt-in', () => {
    expect(check(at(shorter), { ownerPickedExpiration: shorter })).toEqual({ ok: true });
  });

  test('a picked expiry beyond the latest SIWE time is refused', () => {
    const beyond = '+010000-01-01T00:00:00.000Z';
    const bytes = requested.replace(expirationTime, '9999-12-31T23:59:59.001Z');
    expect(check(bytes, { ownerPickedExpiration: '9999-12-31T23:59:59.001Z', longerExpiryAllowed: true }))
      .toMatchObject({ ok: false, reason: 'expiration' });
    expect(check(requested.replace(expirationTime, beyond), { ownerPickedExpiration: beyond, longerExpiryAllowed: true }))
      .toMatchObject({ ok: false, reason: 'signed_unparsable' });
  });

  test('a picked expiry not after the issue time is refused', () => {
    expect(check(at(issuedAt), { ownerPickedExpiration: issuedAt })).toMatchObject({ ok: false, reason: 'expiration' });
  });

  test('signed bytes that do not carry the picked expiry are refused', () => {
    expect(check(at(later), { ownerPickedExpiration: shorter, longerExpiryAllowed: true }))
      .toMatchObject({ ok: false, reason: 'expiration' });
  });
});
