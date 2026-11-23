import { REGISTRY_RECORD_SIGN_ORIGINS } from '@openkey/capability-review';

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
 * Who asked, as the server bound it to the approved request. Never the `Origin` header, a `reportedOrigin` or the
 * SIWE domain.
 * - `origin`: the sender-checked origin sealed into the authorization context at prepare time, or the origin the
 *   sign route checked the SIWE against.
 * - `oauth-client`: the OAuth client id of the authenticated principal.
 * - `native-client`: the client id and the validated redirect URI of a native consent request.
 * - `sweep`: the background retry of a row OpenKey already created. A row does not store who asked yet, so this
 *   retry is not attributed.
 * - `unattributed`: link, device and CLI flows, and any path that binds no origin. Treated as third-party.
 */
export type ProvisionAuthority =
  | { kind: 'origin'; origin: string | null | undefined }
  | { kind: 'oauth-client'; clientId: string | null | undefined }
  | { kind: 'native-client'; clientId: string | null | undefined; redirectUri: string | null | undefined }
  | { kind: 'sweep' }
  | { kind: 'unattributed' };

export const UNATTRIBUTED_PROVISION_AUTHORITY: ProvisionAuthority = { kind: 'unattributed' };

export const SWEEP_PROVISION_AUTHORITY: ProvisionAuthority = { kind: 'sweep' };

export function originProvisionAuthority(origin: string | null | undefined): ProvisionAuthority {
  return { kind: 'origin', origin };
}

export function oauthClientProvisionAuthority(clientId: string | null | undefined): ProvisionAuthority {
  return { kind: 'oauth-client', clientId };
}

export function nativeClientProvisionAuthority(clientId: string | null | undefined, redirectUri: string | null | undefined): ProvisionAuthority {
  return { kind: 'native-client', clientId, redirectUri };
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
    case 'sweep':
      return true;
    case 'unattributed':
    default:
      return false;
  }
}
