import { randomBytes } from 'node:crypto';
import {
  COORDINATIONOS_POLICY_VERSION,
  type CoordinationosPolicyEvidence,
} from './coordinationos-session-policy';

export const COORDINATIONOS_DENIAL_STATUS = {
  malformed_json: 400,
  missing_field: 400,
  invalid_siwe: 400,
  invalid_nonce: 400,
  missing_authorization: 401,
  malformed_authorization: 401,
  multiple_authorization: 401,
  unknown_token: 401,
  token_expired: 401,
  token_too_old: 401,
  wrong_client: 403,
  client_disabled: 403,
  client_misconfigured: 403,
  missing_scope: 403,
  user_not_found: 403,
  email_not_verified: 403,
  key_not_found: 403,
  wrong_user: 403,
  wrong_key_purpose: 403,
  external_key_denied: 403,
  key_archived: 403,
  key_address_mismatch: 403,
  key_unavailable: 403,
  missing_origin: 403,
  wrong_origin: 403,
  siwe_domain_mismatch: 403,
  wrong_chain: 403,
  chain_mismatch: 403,
  wrong_type: 403,
  wrong_purpose: 403,
  siwe_uri_mismatch: 403,
  wrong_capability: 403,
  capability_escalation: 403,
  issued_at_invalid: 403,
  session_expired: 403,
  session_ttl_exceeded: 403,
  nonce_replayed: 409,
  token_consumed: 409,
  audit_write_failed: 500,
  signer_failed: 500,
} as const;

export type CoordinationosDenialCode = keyof typeof COORDINATIONOS_DENIAL_STATUS;
export type CoordinationosDecision = 'ALLOW' | 'DENY' | 'ERROR';

const REASONS: Record<CoordinationosDenialCode, string> = {
  malformed_json: 'The request body must be a JSON object.',
  missing_field: 'The request is missing a required field.',
  invalid_siwe: 'The signing message is not a valid SIWE message.',
  invalid_nonce: 'The SIWE nonce is invalid.',
  missing_authorization: 'A CoordinationOS OAuth bearer token is required.',
  malformed_authorization: 'The Authorization header is malformed.',
  multiple_authorization: 'Exactly one Authorization value is required.',
  unknown_token: 'The OAuth bearer token is unknown.',
  token_expired: 'The OAuth bearer token has expired.',
  token_too_old: 'The OAuth bearer token is too old.',
  wrong_client: 'The token was not issued to the registered CoordinationOS client.',
  client_disabled: 'The registered CoordinationOS client is disabled.',
  client_misconfigured: 'The registered CoordinationOS client is misconfigured.',
  missing_scope: 'The OAuth token does not include tinycloud:session.',
  user_not_found: 'The token user no longer exists.',
  email_not_verified: 'The token user email is not verified.',
  key_not_found: 'The requested key does not exist.',
  wrong_user: 'The requested key is not owned by the token user.',
  wrong_key_purpose: 'The requested key is not a personal key.',
  external_key_denied: 'External keys cannot authorize a CoordinationOS session.',
  key_archived: 'The requested key is archived.',
  key_address_mismatch: 'The request address does not match the managed key.',
  key_unavailable: 'The managed key is unavailable for signing.',
  missing_origin: 'The browser Origin header is required.',
  wrong_origin: 'The request origin is not registered for this client.',
  siwe_domain_mismatch: 'The SIWE domain does not match the registered origin.',
  wrong_chain: 'Only EIP-155 chain 1 is allowed.',
  chain_mismatch: 'The SIWE or capability chain does not match the request.',
  wrong_type: 'Only SIWE signing requests are allowed.',
  wrong_purpose: 'Only sign-in session delegation is allowed.',
  siwe_uri_mismatch: 'The SIWE URI is not the required session verification method.',
  wrong_capability: 'The request does not match the approved CoordinationOS storage records.',
  capability_escalation: 'The request includes capabilities beyond the approved CoordinationOS storage records.',
  issued_at_invalid: 'The SIWE Issued At value is outside the allowed window.',
  session_expired: 'The requested TinyCloud session has expired.',
  session_ttl_exceeded: 'The requested TinyCloud session lifetime exceeds one hour.',
  nonce_replayed: 'This SIWE nonce has already been used.',
  token_consumed: 'This OAuth token has already delegated a TinyCloud session.',
  audit_write_failed: 'The signing decision could not be recorded.',
  signer_failed: 'The managed signer failed after the grant was consumed.',
};

export interface CoordinationosDecisionEvidence extends CoordinationosPolicyEvidence {
  decisionId: string;
  occurredAt: string;
  policyVersion: typeof COORDINATIONOS_POLICY_VERSION;
  decision: CoordinationosDecision;
  reasonCode: string;
  requestId: string | null;
}

type Database = any;

function decisionId(): string {
  return `csd_${randomBytes(16).toString('hex')}`;
}

function decisionData(evidence: CoordinationosDecisionEvidence) {
  return {
    id: evidence.decisionId,
    occurredAt: new Date(evidence.occurredAt),
    policyVersion: evidence.policyVersion,
    decision: evidence.decision,
    reasonCode: evidence.reasonCode,
    requestId: evidence.requestId,
    oauthAccessTokenId: evidence.oauthAccessTokenId,
    tokenDigest: evidence.tokenDigest,
    clientId: evidence.clientId,
    userId: evidence.userId,
    keyId: evidence.keyId,
    origin: evidence.origin,
    chainId: evidence.chainId,
    purpose: evidence.purpose,
    type: evidence.type,
    siweDigest: evidence.siweDigest,
    capabilityDigest: evidence.capabilityDigest,
    nonceDigest: evidence.nonceDigest,
    issuedAt: evidence.issuedAt,
    expirationTime: evidence.expirationTime,
    sessionTtlSeconds: evidence.sessionTtlSeconds,
    evidence,
  };
}

export function sparseCoordinationosEvidence(
  values: Partial<CoordinationosPolicyEvidence> = {},
): CoordinationosPolicyEvidence {
  return {
    oauthAccessTokenId: values.oauthAccessTokenId ?? null,
    tokenDigest: values.tokenDigest ?? null,
    clientId: values.clientId ?? null,
    userId: values.userId ?? null,
    keyId: values.keyId ?? null,
    origin: values.origin ?? null,
    chainId: values.chainId ?? null,
    purpose: values.purpose ?? null,
    type: values.type ?? null,
    siweDigest: values.siweDigest ?? null,
    capabilityDigest: values.capabilityDigest ?? null,
    nonceDigest: values.nonceDigest ?? null,
    issuedAt: values.issuedAt ?? null,
    expirationTime: values.expirationTime ?? null,
    sessionTtlSeconds: values.sessionTtlSeconds ?? null,
  };
}

export function coordinationosDenialResponse(code: CoordinationosDenialCode, id: string) {
  return {
    approved: false,
    needsApproval: false,
    code,
    reason: REASONS[code],
    decisionId: id,
    policyVersion: COORDINATIONOS_POLICY_VERSION,
  };
}

export function coordinationosStatus(code: CoordinationosDenialCode): number {
  return COORDINATIONOS_DENIAL_STATUS[code];
}

export async function recordCoordinationosDecision(
  database: Database,
  input: {
    evidence: CoordinationosPolicyEvidence;
    decision: CoordinationosDecision;
    reasonCode: string;
    requestId?: string | null;
    id?: string;
    occurredAt?: Date;
  },
): Promise<CoordinationosDecisionEvidence> {
  const evidence: CoordinationosDecisionEvidence = {
    decisionId: input.id ?? decisionId(),
    occurredAt: (input.occurredAt ?? new Date()).toISOString(),
    policyVersion: COORDINATIONOS_POLICY_VERSION,
    decision: input.decision,
    reasonCode: input.reasonCode,
    requestId: input.requestId ?? null,
    ...input.evidence,
  };
  await database.coordinationosSigningDecision.create({ data: decisionData(evidence) });
  return evidence;
}

export async function recordCoordinationosDenial(
  database: Database,
  code: CoordinationosDenialCode,
  evidence: CoordinationosPolicyEvidence,
  requestId?: string | null,
): Promise<CoordinationosDecisionEvidence> {
  return recordCoordinationosDecision(database, {
    evidence,
    decision: 'DENY',
    reasonCode: code,
    requestId,
  });
}

function isUniqueConstraintError(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error
    && (error as { code?: unknown }).code === 'P2002');
}

export type CoordinationosGrantResult =
  | { allowed: true; decision: CoordinationosDecisionEvidence }
  | {
      allowed: false;
      code: 'token_consumed' | 'nonce_replayed';
      decision: CoordinationosDecisionEvidence;
    };

export async function consumeCoordinationosGrant(
  database: Database,
  input: {
    evidence: CoordinationosPolicyEvidence;
    oauthAccessTokenId: string;
    nonceDigest: string;
    clientId: string;
    userId: string;
    keyId: string;
    requestId?: string | null;
  },
): Promise<CoordinationosGrantResult> {
  const id = decisionId();
  const occurredAt = new Date();
  const allowEvidence: CoordinationosDecisionEvidence = {
    decisionId: id,
    occurredAt: occurredAt.toISOString(),
    policyVersion: COORDINATIONOS_POLICY_VERSION,
    decision: 'ALLOW',
    reasonCode: 'allow',
    requestId: input.requestId ?? null,
    ...input.evidence,
  };
  try {
    await database.$transaction(async (transaction: Database) => {
      await transaction.coordinationosSigningDecision.create({
        data: decisionData(allowEvidence),
      });
      await transaction.coordinationosSessionGrant.create({
        data: {
          oauthAccessTokenId: input.oauthAccessTokenId,
          nonceDigest: input.nonceDigest,
          clientId: input.clientId,
          userId: input.userId,
          keyId: input.keyId,
          decisionId: id,
        },
      });
    }, { isolationLevel: 'Serializable' });
    return { allowed: true, decision: allowEvidence };
  } catch (error) {
    if (!isUniqueConstraintError(error)) throw error;
    const tokenGrant = await database.coordinationosSessionGrant.findUnique({
      where: { oauthAccessTokenId: input.oauthAccessTokenId },
      select: { id: true },
    });
    const code = tokenGrant ? 'token_consumed' : 'nonce_replayed';
    const denial = await recordCoordinationosDenial(
      database,
      code,
      input.evidence,
      input.requestId,
    );
    return { allowed: false, code, decision: denial };
  }
}

export async function recordCoordinationosSignerError(
  database: Database,
  evidence: CoordinationosPolicyEvidence,
  requestId?: string | null,
): Promise<CoordinationosDecisionEvidence> {
  return recordCoordinationosDecision(database, {
    evidence,
    decision: 'ERROR',
    reasonCode: 'signer_failed',
    requestId,
  });
}
