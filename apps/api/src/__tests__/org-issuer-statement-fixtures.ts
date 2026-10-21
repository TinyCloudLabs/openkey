import { canonicalJson, parseIssuerStatement, renderIssuerStatement } from '../services/org-issuer-statement';
import { ISSUER_DID, ORIGIN, SLUG } from './org-keys-fixtures';

// Canonical authorize statement for an org key. The controller comes from the key
// that setupOrgKey generated (a fresh key per call), so it is read from the key
// rather than pinned. `overrides` varies one field, for tests that need two
// distinct statements.
export function statementFor(
  key: { controllerDid: string },
  overrides: Record<string, unknown> = {},
): string {
  return canonicalJson({
    action: 'authorize',
    alg: 'EdDSA',
    audience: ORIGIN,
    controller: key.controllerDid,
    issuerDid: ISSUER_DID,
    kid: `${ISSUER_DID}#issuing-1`,
    nonce: '00112233445566778899aabbccddeeff',
    notBefore: '2026-10-20T09:00:00Z',
    orgId: 'org_1',
    profiles: ['tinycloud.org-membership/v1'],
    publicKey: 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI',
    seq: 1,
    slug: SLUG,
    type: 'tinycloud.org-issuer-authorization/v1',
    vcts: ['opencredentials.org-membership/v1', 'tinycloud.org-badge/v1'],
    ...overrides,
  });
}

// The text the org key signs (EIP-191). The server renders it from the same canonical input.
export function signedTextFor(message: string): string {
  return renderIssuerStatement(parseIssuerStatement(message, [ORIGIN]), message);
}
