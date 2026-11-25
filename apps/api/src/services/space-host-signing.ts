// Who may have the owner's key sign a message that hosts (creates) a space on the node (POST /api/keys/:id/sign).
//
// Hosting the owner's primary space (`default`) is what creates an account on the node, so only TinyCloud's own apps
// get that signature. An app from another site may have its own non-primary spaces hosted (public, a registry space)
// once the owner's primary space is known to be hosted. Every target is read from the message's own ReCap.

import { ensureEip55 } from '@tinycloud/node-sdk-wasm';
import { mayProvision, type ProvisionAuthority } from './provision-authority';
import { isTinyCloudBootstrapComplete, trustedTinyCloudBootstrapHost, type PrismaLike } from './tinycloud-bootstrap';
import { spaceHostRequest } from './tinycloud-siwe';

const PRIMARY_SPACE = 'default';

export const HOST_SIGNING_FIRST_PARTY_ONLY = 'host_signing_first_party_only';
export const HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE = 'Only TinyCloud\'s own apps can have OpenKey sign a request that creates your first TinyCloud space.';

/**
 * Must the key refuse to sign this message? The one decision every signing route and branch uses (`/api/keys/:id/sign`,
 * `/api/delegate/sign` for a cookie session, an OAuth session-scope token and an OAuth manage-key token).
 *
 * `authorities` are the first-party facts the route knows server-side (a checked origin, an OAuth client id, a
 * registered client origin); none of them comes from the message. If any of them may provision, the message is signed.
 * Otherwise it is signed when it asks for no space ability, or when every `host` target is a non-primary space of this
 * key's owner and the owner's primary space is hosted. "Hosted" is a stored bootstrap row that is `complete` for the
 * target's chain on the trusted node, whoever set it up: a missing, pending or failed row is not hosted, and no node
 * is asked, so there is no answer to mistake (a 404, a 401, a timeout). Anything that cannot be read or checked
 * refuses.
 */
export async function refusesThirdPartySpaceHost(input: {
  prisma: PrismaLike;
  message: string;
  key: { id: string; address: string };
  authorities: readonly ProvisionAuthority[];
}): Promise<boolean> {
  if (input.authorities.some(mayProvision)) return false;
  const request = spaceHostRequest(input.message);
  if (request.kind === 'none') return false;
  if (request.kind === 'unreadable') return true;
  try {
    const owner = ensureEip55(input.key.address);
    if (request.targets.some((target) => target.address !== owner || target.name.toLowerCase() === PRIMARY_SPACE)) return true;
    const host = trustedTinyCloudBootstrapHost();
    for (const chainId of new Set(request.targets.map((target) => target.chainId))) {
      if (!(await isTinyCloudBootstrapComplete(input.prisma, { keyId: input.key.id, chainId, host }))) return true;
    }
    return false;
  } catch {
    return true;
  }
}
