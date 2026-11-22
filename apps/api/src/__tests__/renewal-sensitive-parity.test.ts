// TC-3821: the web asks "Renew sensitive access?" wherever the API requires that confirm for a renewal lease. Both
// rules run over the one shared list of grants in packages/capability-review/test/fixtures/renewal-sensitive-grants.ts,
// on the same signed message bytes, built by the real WASM signer: the API's `leaseReachesSecrets` reads its ReCap,
// the web's `renewalNeedsSensitiveConfirm` reads the review model the approval screen shows.
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META } from '../../../../packages/capability-review/test/fixtures/index';
import { RENEWAL_SENSITIVE_CASES, type RenewalSensitiveCase } from '../../../../packages/capability-review/test/fixtures/renewal-sensitive-grants';
import { renewalNeedsSensitiveConfirm } from '../../../web/src/lib/renewal-default';
import { RenewalLeaseError, assertLeaseableGrant, leaseReachesSecrets } from '../services/renewal-lease';
import { renewalWindowExpiryAt } from '../../../web/src/lib/approval-expiry';

const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };

/** The row's grant as OpenKey signs it: a 7-day message, so the API's window cap never decides it. */
function signedMessage(row: RenewalSensitiveCase): string {
  const issuedAt = Date.parse('2026-11-22T00:00:00.000Z');
  return prepareSession({
    address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, domain: 'openkey.so', spaceId: FIXTURE_META.ownSpace, jwk,
    issuedAt: new Date(issuedAt).toISOString(), expirationTime: new Date(issuedAt + 7 * 86_400_000).toISOString(),
    abilities: {},
    rawAbilities: row.att,
  } as unknown as Parameters<typeof prepareSession>[0]).siwe;
}

function server(message: string): boolean | 'unreadable' {
  try {
    return leaseReachesSecrets(message);
  } catch (error) {
    expect(error).toBeInstanceOf(RenewalLeaseError);
    expect(error).toMatchObject({ code: 'renewal_refused', status: 400 });
    return 'unreadable';
  }
}

function review(message: string) {
  return parseCapabilityReview({
    message,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'app.example', verifiedOrigin: 'https://app.example', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function web(message: string): boolean {
  return renewalNeedsSensitiveConfirm(review(message).permissions);
}

describe('the web renewal confirm and the API lease rule agree on the shared grants', () => {
  for (const row of RENEWAL_SENSITIVE_CASES) {
    test(row.name, () => {
      const message = signedMessage(row);
      const api = server(message);
      const page = web(message);
      expect({ api, page }).toEqual({ api: row.server, page: row.web });
      // Wherever the API would refuse an unconfirmed lease, the page asks for the confirm first.
      if (api !== false) expect(page).toBe(true);
    });
  }
});

// TC-3826: a fake `Expiration Time:` line in the statement, behind a line separator the node's reader does not treat
// as a line break, must never be read as the grant's window. The message's real expiry is 400 days out and the fake
// line says 1 day, so a reader fooled by it would see a short window on a long grant.
describe('a fake Expiration Time line behind a line separator', () => {
  const issuedAt = Date.parse('2026-11-22T00:00:00.000Z');
  const FAKE = new Date(issuedAt + 86_400_000).toISOString();

  function attack(att: Record<string, string[]>, separator: string): string {
    const real = prepareSession({
      address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, domain: 'openkey.so', spaceId: FIXTURE_META.ownSpace, jwk,
      issuedAt: new Date(issuedAt).toISOString(), expirationTime: new Date(issuedAt + 400 * 86_400_000).toISOString(),
      abilities: {},
      rawAbilities: att,
    } as unknown as Parameters<typeof prepareSession>[0]).siwe;
    const lines = real.split('\n');
    // The statement sits between the address and the URI line; the fake line goes in front of it.
    const at = lines.indexOf('') + 1;
    lines[at] = `Expiration Time: ${FAKE}${separator} ${lines[at]}`;
    return lines.join('\n');
  }
  const SECRET = RENEWAL_SENSITIVE_CASES.find((row) => row.server === true)!.att;

  for (const [name, separator] of [['CR', '\r'], ['U+2028', '\u2028'], ['U+2029', '\u2029']] as const) {
    test(`${name}: the API refuses the lease as unreadable, sensitive grant or not, confirmed or not`, () => {
      for (const att of [SECRET, {}]) {
        const message = attack(att, separator);
        expect(server(message)).toBe('unreadable');
        // The web agrees the message is unreadable: the review model marks it non-signable (`malformed-recap`, warning
        // `unparseable-siwe`) and reads no permissions, so the page never reaches a renewal confirm (TC-3826).
        const model = review(message);
        expect(model.protocol).toBe('malformed-recap');
        expect(model.parseWarnings.map((warning) => warning.code)).toContain('unparseable-siwe');
        expect(model.permissions).toEqual([]);
        for (const confirmed of [true, false]) {
          let thrown: unknown = null;
          try {
            assertLeaseableGrant(message, confirmed);
          } catch (error) {
            thrown = error;
          }
          expect(thrown).toBeInstanceOf(RenewalLeaseError);
          expect(thrown).toMatchObject({ code: 'renewal_refused', status: 400 });
          if (att === SECRET) expect((thrown as Error).message).toContain("couldn't read one of its permissions");
        }
      }
    });

    test(`${name}: the web counts a chosen window from now, never from the fake line`, () => {
      const message = attack(SECRET, separator);
      const now = Date.parse('2026-11-22T12:00:00.000Z');
      expect(renewalWindowExpiryAt(7 * 86_400_000, message, now)).toBe(new Date(now + 7 * 86_400_000).toISOString());
    });
  }
});
