import { getAddress, verifyMessage } from 'ethers';
import { parseStrictSiwe } from './signed-subset';
import { checkSiweOrigin } from './siwe-origin';
import { strictSessionDid } from './device-authorization';
import { ShareApprovalError, type ShareApprovalBinding } from './share-approval';

export interface ShareSessionProof {
  siwe: string;
  signature: string;
  publicJwk: unknown;
}

/** Verify existing owner authorization; this does not replace the new approval's passkey check. */
export function shareSessionBinding(proof: ShareSessionProof, account: {
  userId: string; keyId: string; address: string;
}, origin: string, now = Date.now()): ShareApprovalBinding {
  const parsed = parseStrictSiwe(proof.siwe);
  const originCheck = checkSiweOrigin(proof.siwe, origin);
  if (!parsed.ok || !originCheck.siwe || !originCheck.ok || new URL(origin).protocol !== 'https:') {
    throw new ShareApprovalError('invalid_share_session');
  }
  const session = parsed.siwe;
  const sessionDid = strictSessionDid(proof.publicJwk);
  const principal = (did: string) => did.split('#', 1)[0];
  const sessionExpiresAt = Date.parse(session.expirationTime ?? '');
  if (principal(session.uri) !== principal(sessionDid) ||
    !Number.isFinite(sessionExpiresAt) || sessionExpiresAt <= now ||
    Date.parse(session.issuedAt) > now ||
    (session.notBefore !== undefined && Date.parse(session.notBefore) > now) ||
    getAddress(session.address) !== getAddress(account.address) ||
    getAddress(verifyMessage(proof.siwe, proof.signature)) !== getAddress(account.address)) {
    throw new ShareApprovalError('invalid_share_session');
  }
  return { userId: account.userId, keyId: account.keyId,
    ownerDid: `did:pkh:eip155:${session.chainId}:${getAddress(account.address)}`,
    sessionDid, origin, sessionExpiresAt };
}
