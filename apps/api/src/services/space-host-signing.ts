// Who may have the owner's key sign a message that hosts (creates) a space on the node (POST /api/keys/:id/sign).
//
// Hosting the owner's primary space (`default`) for an owner who has no account on the node creates that account, so
// only TinyCloud's own apps get that signature. An app from another site gets a host message signed for the owner's
// own spaces, `default` included, when the owner's primary space is already hosted: a stored bootstrap row that is
// complete. Every target is read from the message's own ReCap.

import { ensureEip55 } from '@tinycloud/node-sdk-wasm';
import { mayProvision, type ProvisionAuthority } from './provision-authority';
import { isTinyCloudBootstrapComplete, trustedTinyCloudBootstrapHost, type PrismaLike } from './tinycloud-bootstrap';
import { spaceHostRequest } from './tinycloud-siwe';

const PRIMARY_SPACE = 'default';

export const HOST_SIGNING_FIRST_PARTY_ONLY = 'host_signing_first_party_only';
export const HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE = "This app can't create your first TinyCloud space. Sign in once at tinycloud.one to set up your account, then sign in here.";

export const HOST_SIGNING_REFUSAL_BODY = { error: HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE, code: HOST_SIGNING_FIRST_PARTY_ONLY } as const;

/**
 * The refusal body of a host-signing refusal the sign widget shows. `accountSetup: 'required'` when the managed key's
 * account is not set up on TinyCloud hosting (no complete setup row on the trusted node for chain 1): the widget then
 * offers OpenKey's own account setup page. The code is `host_signing_first_party_only` either way.
 */
export async function hostSigningRefusalBody(prisma: PrismaLike, key: { id: string; keyType: string }) {
  if (key.keyType !== 'MANAGED') return HOST_SIGNING_REFUSAL_BODY;
  try {
    if (await isTinyCloudBootstrapComplete(prisma, { keyId: key.id, chainId: 1, host: trustedTinyCloudBootstrapHost() })) {
      return HOST_SIGNING_REFUSAL_BODY;
    }
    return { ...HOST_SIGNING_REFUSAL_BODY, accountSetup: 'required' as const };
  } catch {
    return HOST_SIGNING_REFUSAL_BODY;
  }
}

/**
 * Must the key refuse to sign this message? The one decision every signing route and branch uses (`/api/keys/:id/sign`,
 * `/api/delegate/sign` for a cookie session, an OAuth session-scope token and an OAuth manage-key token).
 *
 * `authorities` are the first-party facts the route knows server-side (a checked origin, an OAuth client id, a
 * registered client origin); none of them comes from the message. If any of them may provision, the message is signed.
 * Otherwise it is signed when it asks for no space ability, or when every `host` target is a space of this key's owner
 * (`default` included) and the owner's primary space is hosted. "Hosted" is a stored bootstrap row that is `complete`
 * for each target's chain on the trusted node, whoever set it up: a missing, pending or failed row is not hosted, so
 * a third party never creates the owner's first space. The guard writes no row and asks no node, so there is no answer
 * to mistake (a 404, a 401, a timeout). A request with `noBoundContext` is never signed for a `default` target.
 * Anything that cannot be read or checked refuses.
 */
export async function refusesThirdPartySpaceHost(input: {
  prisma: PrismaLike;
  message: string;
  key: { id: string; address: string };
  authorities: readonly ProvisionAuthority[];
  /**
   * The request carries no bound context (no token that ties it to an approved request). Such a request is signed
   * only for the owner's non-default spaces; a `default` target is refused whatever the stored row says.
   */
  noBoundContext?: true;
}): Promise<boolean> {
  if (input.authorities.some(mayProvision)) return false;
  const request = spaceHostRequest(input.message);
  if (request.kind === 'none') return false;
  if (request.kind === 'unreadable') return true;
  try {
    const owner = ensureEip55(input.key.address);
    if (request.targets.some((target) => target.address !== owner)) return true;
    if (input.noBoundContext && request.targets.some((target) => target.name.toLowerCase() === PRIMARY_SPACE)) return true;
    const host = trustedTinyCloudBootstrapHost();
    for (const chainId of new Set(request.targets.map((target) => target.chainId))) {
      if (!(await isTinyCloudBootstrapComplete(input.prisma, { keyId: input.key.id, chainId, host }))) return true;
    }
    return false;
  } catch {
    return true;
  }
}
