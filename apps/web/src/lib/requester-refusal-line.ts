import { UNVERIFIED_REQUESTER, fill } from '@openkey/sdk/approval-copy';
import { requesterRefusal, type OneVerifiedRequesterEntry, type VerifiedRequesterEntry } from './delegate-link-policy';
import type { RequesterScopeRefusal, RequesterScopeRequest } from './requester-scope-policy';

const LINE_OF: Record<RequesterScopeRefusal, keyof typeof UNVERIFIED_REQUESTER.reasons> = {
  lifetime: 'lifetime',
  service: 'service',
  action: 'action',
  path: 'path',
  space: 'space',
  renewal: 'renewal',
  context: 'context',
  malformed: 'unreadable',
  'no-permissions': 'unreadable',
};

/**
 * The one line under "OpenKey can't confirm who made this link" when the link's signer is a listed requester and its
 * request or prepared message is outside that requester's policy; null for any other link. The caller shows it only
 * while no requester is named.
 */
export function requesterRefusalLine(
  issuer: string,
  oneRequesters: readonly OneVerifiedRequesterEntry[],
  verifiedRequesters: readonly VerifiedRequesterEntry[],
  request: RequesterScopeRequest | null,
  signed: RequesterScopeRequest | null,
): string | null {
  const refusal = requesterRefusal(issuer, oneRequesters, verifiedRequesters, request, signed);
  return refusal && fill(UNVERIFIED_REQUESTER.reasons[LINE_OF[refusal.reason]], { app: refusal.app });
}
