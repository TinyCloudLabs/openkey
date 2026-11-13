import { validatePermissions, type DelegationPermissionEntry } from '../routes/delegate-session';
import { strictSessionDid } from './device-authorization';
import { ShareApprovalError } from './share-approval';
import type { ShareSessionProof } from './share-approval-session';

export interface ShareApprovalIntent {
  origin: string;
  keyId: string;
  session: ShareSessionProof;
  permissions: DelegationPermissionEntry[];
  expiresAt: string;
}

/** The server chooses the share id; there is no id or caller SIWE-to-sign in this protocol. */
export function parseShareApprovalIntent(value: unknown): ShareApprovalIntent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ShareApprovalError('invalid_share_intent');
  const body = value as Record<string, unknown>;
  if (Object.keys(body).some(key => !['origin', 'keyId', 'session', 'permissions', 'expiresAt'].includes(key)) ||
    typeof body.origin !== 'string' || typeof body.keyId !== 'string' || !body.keyId ||
    typeof body.expiresAt !== 'string' || !Number.isFinite(Date.parse(body.expiresAt)) ||
    !body.session || typeof body.session !== 'object' || Array.isArray(body.session)) {
    throw new ShareApprovalError('invalid_share_intent');
  }
  const session = body.session as Record<string, unknown>;
  if (Object.keys(session).sort().join(',') !== 'publicJwk,signature,siwe' ||
    typeof session.siwe !== 'string' || typeof session.signature !== 'string') {
    throw new ShareApprovalError('invalid_share_session');
  }
  strictSessionDid(session.publicJwk);
  const permissions = body.permissions === undefined ? [] : validatePermissions(body.permissions);
  // This request may carry only the exact ordinary file rows the app requested.
  if (permissions.length > 16 || permissions.some(entry => entry.service !== 'tinycloud.kv' ||
    !entry.path || entry.path.endsWith('/') || entry.path.includes('*') ||
    entry.actions.length === 0 || entry.actions.some(action =>
      action !== 'tinycloud.kv/get' && action !== 'tinycloud.kv/metadata'))) {
    throw new ShareApprovalError('invalid_share_file_permissions');
  }
  return { origin: body.origin, keyId: body.keyId,
    session: { siwe: session.siwe, signature: session.signature, publicJwk: structuredClone(session.publicJwk) },
    permissions: structuredClone(permissions), expiresAt: body.expiresAt };
}
