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
import { RenewalLeaseError, leaseReachesSecrets } from '../services/renewal-lease';

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

function web(message: string): boolean {
  const model = parseCapabilityReview({
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
  return renewalNeedsSensitiveConfirm(model.permissions);
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
