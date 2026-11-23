import { REGISTRY_RECORD_SIGN_ORIGINS } from '@openkey/capability-review';
import type { TinyCloudBootstrapSweepClaim } from './tinycloud-bootstrap';

/**
 * What lets OpenKey set up an account on the node (host a space, run the account bootstrap) as a side effect of a
 * signature or consent. Only TinyCloud's own apps do. Each list below is the whole of what the server counts as
 * first-party for that source; adding an entry is a one-line change here.
 */

/**
 * Exact web origins. The origins that may ask for a registry record signature (reused, not copied) and TinyChat web.
 * The registry record list in capability-review is not changed by the second one.
 */
export const FIRST_PARTY_PROVISION_ORIGINS: readonly string[] = [...REGISTRY_RECORD_SIGN_ORIGINS, 'https://tinycloud.chat'];

/** OAuth clients of the signer route (`/api/delegate/sign`), by client id. Empty. `skipConsent` is not a marker: an organization can set it on its own client. */
export const FIRST_PARTY_PROVISION_OAUTH_CLIENT_IDS: readonly string[] = [];

/** Native clients, by exact client id and exact registered redirect URI together; neither alone, never a prefix. */
export const FIRST_PARTY_PROVISION_NATIVE_CLIENTS: readonly { clientId: string; redirectUri: string }[] = [
  { clientId: 'ok_e1d13d0b220379f37a553aa0391d28a4', redirectUri: 'xyz.tinycloud.exo://openkey/callback' },
];

/**
 * The three cases where the owner approves on OpenKey's own page and OpenKey sets their space up with it. One line
 * each: set a case to `false` to turn it off.
 * - `approval-request`: a signed approval request approved at openkey.so/a/<id>.
 * - `device-approval`: a device authorization approved on OpenKey's page.
 * - `delegate-link-local`: the legacy /delegate link, only when it returns to a loopback address or by paste.
 *   COMPATIBILITY allowance for the CLI and Courier, not a security boundary: any app can send a link that names a
 *   loopback callback, so the page tells the owner what approving does and that the requester's words are unchecked.
 */
export const OWN_PAGE_APPROVAL_ENABLED = {
  'approval-request': true,
  'device-approval': true,
  'delegate-link-local': true,
} as const satisfies Record<string, boolean>;

export type OwnPageApproval = keyof typeof OWN_PAGE_APPROVAL_ENABLED;

/**
 * Who asked, as the server bound it to the approved request. Never the `Origin` header, a `reportedOrigin` or the
 * SIWE domain.
 * - `origin`: the sender-checked origin sealed into the authorization context at prepare time, or the origin the
 *   sign route checked the SIWE against.
 * - `oauth-client`: the OAuth client id of the authenticated principal.
 * - `native-client`: the client id and the validated redirect URI of a native consent request.
 * - `own-page`: an approval the session's user made on OpenKey's own page, taken from a completed, single-use,
 *   unexpired record and never from a request field (see `OwnPageApproval`).
 * - `sweep`: the background retry of a row OpenKey already created, carrying the claim it holds on that row. The sweep
 *   reads only rows whose stored authority is first-party (`retryableStoredAuthorities`); without the claim there is
 *   no sweep run to allow, so a sweep authority with no claim is refused.
 * - `unattributed`: any path that binds no authority. Treated as third-party.
 */
export type ProvisionAuthority =
  | { kind: 'origin'; origin: string | null | undefined }
  | { kind: 'oauth-client'; clientId: string | null | undefined }
  | { kind: 'native-client'; clientId: string | null | undefined; redirectUri: string | null | undefined }
  | { kind: 'own-page'; approval: OwnPageApproval }
  | { kind: 'sweep'; claim: TinyCloudBootstrapSweepClaim }
  | { kind: 'unattributed' };

export const UNATTRIBUTED_PROVISION_AUTHORITY: ProvisionAuthority = { kind: 'unattributed' };

export function sweepProvisionAuthority(claim: TinyCloudBootstrapSweepClaim): ProvisionAuthority {
  return { kind: 'sweep', claim };
}

export function originProvisionAuthority(origin: string | null | undefined): ProvisionAuthority {
  return { kind: 'origin', origin };
}

export function oauthClientProvisionAuthority(clientId: string | null | undefined): ProvisionAuthority {
  return { kind: 'oauth-client', clientId };
}

export function nativeClientProvisionAuthority(clientId: string | null | undefined, redirectUri: string | null | undefined): ProvisionAuthority {
  return { kind: 'native-client', clientId, redirectUri };
}

export function ownPageProvisionAuthority(approval: OwnPageApproval): ProvisionAuthority {
  return { kind: 'own-page', approval };
}

/** May OpenKey provision on the node for this authority? Fails closed: anything not first-party is refused. */
export function mayProvision(authority: ProvisionAuthority): boolean {
  switch (authority.kind) {
    case 'origin':
      return typeof authority.origin === 'string' && FIRST_PARTY_PROVISION_ORIGINS.includes(authority.origin);
    case 'oauth-client':
      return typeof authority.clientId === 'string' && FIRST_PARTY_PROVISION_OAUTH_CLIENT_IDS.includes(authority.clientId);
    case 'native-client':
      return FIRST_PARTY_PROVISION_NATIVE_CLIENTS.some(
        (client) => client.clientId === authority.clientId && client.redirectUri === authority.redirectUri,
      );
    case 'own-page':
      return OWN_PAGE_APPROVAL_ENABLED[authority.approval] === true;
    case 'sweep':
      // The retry is allowed only as a claim on a row the sweep's query read: a sweep authority with no claim is refused.
      return typeof authority.claim?.onClaimed === 'function' && authority.claim.observed != null;
    case 'unattributed':
    default:
      return false;
  }
}

/**
 * What a bootstrap row stores (`tinycloud_bootstrap_state.authority`): a small closed set. A row with no stored
 * authority (every row made before this column) is NOT first-party: the sweep does not retry it and nothing may read
 * it as evidence that a first-party approval made it.
 */
export const STORED_PROVISION_AUTHORITIES = [
  'first-party-origin',
  'first-party-client',
  'first-party-native-client',
  'approval-request',
  'device-approval',
  'delegate-link-local',
] as const;

export type StoredProvisionAuthority = (typeof STORED_PROVISION_AUTHORITIES)[number];

/** The value to store for an authority that may provision; null for one that may not and for the sweep (it keeps the row's own). */
export function storedProvisionAuthority(authority: ProvisionAuthority): StoredProvisionAuthority | null {
  if (!mayProvision(authority)) return null;
  switch (authority.kind) {
    case 'origin':
      return 'first-party-origin';
    case 'oauth-client':
      return 'first-party-client';
    case 'native-client':
      return 'first-party-native-client';
    case 'own-page':
      return authority.approval;
    case 'sweep':
    case 'unattributed':
    default:
      return null;
  }
}

/** The stored authorities the sweep may retry: those that are first-party now (a turned-off case is not retried). */
export function retryableStoredAuthorities(): StoredProvisionAuthority[] {
  const own = (approval: OwnPageApproval): boolean => OWN_PAGE_APPROVAL_ENABLED[approval] === true;
  return STORED_PROVISION_AUTHORITIES.filter((stored) => {
    switch (stored) {
      case 'first-party-origin':
        return FIRST_PARTY_PROVISION_ORIGINS.length > 0;
      case 'first-party-client':
        return FIRST_PARTY_PROVISION_OAUTH_CLIENT_IDS.length > 0;
      case 'first-party-native-client':
        return FIRST_PARTY_PROVISION_NATIVE_CLIENTS.length > 0;
      default:
        return own(stored);
    }
  });
}
