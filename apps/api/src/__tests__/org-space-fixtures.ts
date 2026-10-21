import { adminAccountFor, renderOrgSpaceMessage, spaceIdFor } from '../services/org-space-signing';

export const ORG_SPACE_TEST_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
export const ORG_SPACE_TEST_ORIGIN = 'https://internal.tinycloud.xyz';

// A rendered kind 2 (org-space) SIWE message for the org key, used to prove the personal
// routes refuse org-space content. The personal SIWE origin gate runs before the
// org-space guard and requires SIWE domain and URI to match the requesting origin, so
// the fixture takes that origin. The org-space guard detects content by `fct`/`att`,
// not by URI, so it still fires for a message shaped like this.
export function orgSpaceMessageText(origin = ORG_SPACE_TEST_ORIGIN, address = ORG_SPACE_TEST_ADDRESS): string {
  const space = spaceIdFor(address);
  return renderOrgSpaceMessage({
    domain: new URL(origin).host,
    address,
    uri: origin,
    nonce: 'abcdefgh12',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    att: [
      { resource: `${space}/space`, ability: 'tinycloud.space/host' },
      { resource: `${space}/sql/shared-index`, ability: 'tinycloud.sql/admin' },
    ],
    fact: { adminAccount: adminAccountFor(address), class: 'space-host', grantId: 'grant_1' },
  });
}
