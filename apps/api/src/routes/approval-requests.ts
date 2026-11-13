import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { parseLink, resolveLink, parseApprovalRequest, validateLinkHeader, verifyHeader, linkIssuerPublicKey } from '@tinycloud/share-envelope/links';
import { ApprovalResultError, ApprovalResultService, linkRequiredError, type ApprovalRequestRecord } from '../services/approval-results';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import { requireSession } from '../middleware/session';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { verifySessionProofClaims } from '../services/native-delegation/session-proof';
import { createHash } from 'node:crypto';
import { createPrismaDelegationCodeStore, type ApprovalCode } from './delegation-codes';
import { verifyMessage } from 'ethers';
import { logError } from '../log';
import {
  RENEWAL_FAILED_MESSAGE,
  RenewalLeaseError,
  admitLease,
  parseRenewalChoice,
  prepareRenewalStage,
  signLease,
  type RenewalStage,
} from '../services/renewal-lease';

const prisma = createPrismaClient();
const store = createPrismaApprovalRequestStore(prisma);
const codeStore = createPrismaDelegationCodeStore(prisma);
const linksOrigin = process.env.APPROVAL_LINKS_API_ORIGIN ?? 'https://api.tinycloud.xyz';
const viewerOrigin = process.env.APPROVAL_OPENKEY_ORIGIN ?? 'https://openkey.so';
const apiOrigin = process.env.BETTER_AUTH_URL ?? 'http://localhost:3001';

// No implicit production retention policy. Ten minutes is a synthetic-local
// engineering choice derived from the existing device transaction duration.
export function approvalResultService(): ApprovalResultService {
  const configured = process.env.APPROVAL_RESULT_RETENTION_SECONDS;
  if (!configured && (process.env.NODE_ENV === 'production' || process.env.TEE_MODE === 'production')) {
    throw new ApprovalResultError('retention_not_configured', 'Approval result retention requires explicit configuration', 503);
  }
  return new ApprovalResultService(store, { apiOrigin, retentionSeconds: configured === undefined ? 600 : Number(configured), codeStore });
}

async function fetchLink(input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> {
  const source = new URL(input instanceof Request ? input.url : String(input));
  if (source.origin !== linksOrigin || !/^\/v1\/links\/[a-z2-7]{26}$/.test(source.pathname) || source.search) {
    throw new ApprovalResultError('invalid_request', 'Approval link transport is not permitted', 400);
  }
  const override = process.env.APPROVAL_LINKS_LOCAL_TRANSPORT;
  if (override) {
    const local = new URL(override);
    if (process.env.NODE_ENV === 'production' || process.env.TEE_MODE === 'production' || local.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(local.hostname) || local.origin !== override) {
      throw new ApprovalResultError('invalid_request', 'Approval local transport must be explicitly configured loopback', 400);
    }
    source.protocol = local.protocol; source.host = local.host;
  }
  return fetch(source, { ...init, redirect: 'error', credentials: 'omit' });
}

export const approvalRequestRouter = new Hono();
approvalRequestRouter.use('*', async (c, next) => { c.header('Cache-Control', 'no-store'); await next(); });
approvalRequestRouter.onError((error, c) => {
  if (error instanceof ApprovalResultError) return c.json({ error: error.message, code: error.code, ...error.extra }, error.status);
  // Decoder failures deliberately do not reflect a URL/key/plaintext in logs.
  if (error && 'code' in error) return c.json({ error: 'Approval request could not be verified', code: String(error.code) }, 400);
  throw error;
});

// Loading is read-only with respect to the Worker; tab previews can repeat it.
approvalRequestRouter.post('/approval-requests/:id/load', async (c) => {
  approvalResultService();
  const id = c.req.param('id');
  const body = await c.req.json();
  if (typeof body.reference !== 'string') throw new ApprovalResultError('invalid_request', 'Approval request reference is required', 400);
  const link = viewerOrigin + body.reference;
  const parsed = parseLink(link, { trustedOrigins: [viewerOrigin] });
  if (parsed.form !== 'short' || parsed.pathType !== 'openkey-approval-request' || parsed.id !== id) {
    throw new ApprovalResultError('invalid_request', 'Approval request reference does not match this request', 400);
  }
  const opened = await resolveLink(link, { trustedOrigins: [viewerOrigin], apiOrigin: linksOrigin, fetch: Object.assign(fetchLink, { preconnect: fetch.preconnect }) });
  if (opened.type !== 'openkey-approval-request') throw new ApprovalResultError('invalid_request', 'Not an approval request', 400);
  const request = parseApprovalRequest(opened.value, { issuer: opened.header.issuer });
  const record = await store.register({ id, bodyCid: opened.header.bodyCid, issuer: opened.header.issuer, request, expiresAt: new Date(opened.header.expiresAt), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null });
  // `denied` is additive (TC-2459): a reopened declined link can say so. `approved` keeps its meaning.
  return c.json({ request: record.request, requestId: id, bodyCid: record.bodyCid, expiresAt: record.expiresAt.toISOString(), approved: !!record.resultRef, denied: !!record.deniedAt });
});

approvalRequestRouter.post('/approval-requests/:id/result', async (c) => {
  const service = approvalResultService();
  const id = c.req.param('id');
  const body = await c.req.json();
  const proof = c.req.header('OpenKey-Session-Proof');
  if (!/^[a-z2-7]{26}$/.test(id) || typeof body.bodyCid !== 'string') throw new ApprovalResultError('invalid_request', 'Approval reference is invalid', 400);
  const record = await store.findById(id);
  if (!record) {
    if (body.approvalCode !== undefined) throw new ApprovalResultError('not_found', 'Saved approval request not found', 404);
    // Before a browser opens the sealed request, authenticate only the
    // issuer-signed public header. No client-supplied DID or JWK is trusted.
    const header = validateLinkHeader(body.header, { mode: 'signed', audience: linksOrigin });
    const bytes = linkIssuerPublicKey(header.issuer);
    if (!bytes || !verifyHeader(header, body.signature) || header.type !== 'openkey-approval-request' || header.bodyCid !== body.bodyCid || Date.parse(header.expiresAt) - Date.parse(header.issuedAt) > 86400_000) {
      throw new ApprovalResultError('invalid_request', 'Signed approval request header is invalid', 400);
    }
    const x = Buffer.from(bytes).toString('base64url');
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
    if (!verifySessionProofClaims(proof, { sessionJwk: { x }, sessionJkt: jkt, htu: `${apiOrigin}/api/approval-requests/${id}/result`, clientId: 'openkey-approval-result-v1', credential: JSON.stringify(['discover', id, body.bodyCid, '', '']) })) {
      throw new ApprovalResultError('invalid_proof', 'Requester proof is invalid', 401);
    }
    if (Date.parse(header.expiresAt) <= Date.now()) {
      throw new ApprovalResultError('expired_request', 'Approval request expired. Start a new request.', 410);
    }
    return c.json({ status: 'pending' }, 202);
  }
  const result = await service.discover(id, body, proof, c.req.header('OpenKey-Delegation-Claim'));
  return c.json(result, result.status === 'pending' ? 202 : 200);
});

approvalRequestRouter.post('/approval-results/:ref/fetch', async (c) => c.json(await approvalResultService().fetch(c.req.param('ref'), await c.req.json(), c.req.header('OpenKey-Session-Proof'))));
approvalRequestRouter.post('/approval-results/:ref/ack', async (c) => c.json(await approvalResultService().acknowledge(c.req.param('ref'), await c.req.json(), c.req.header('OpenKey-Session-Proof'))));

/**
 * Declining. Requests carry no owner account, so the capability is the same as for approving: the complete
 * approval link. The body must hold the `reference` that /load takes (path and key fragment); it is
 * re-resolved here with its key, so a signed-in caller who only knows the request id is refused (403
 * `link_required`) and the request stays open. The reference is never logged or echoed.
 */
approvalRequestRouter.post('/approval-requests/:id/deny', requireAccountOriginForBearer, requireSession, async (c) => {
  const id = c.req.param('id');
  const service = approvalResultService();
  const body: unknown = await c.req.json().catch(() => null);
  const reference = body && typeof body === 'object' && 'reference' in body ? body.reference : undefined;
  if (typeof reference !== 'string') throw linkRequiredError();
  let header: { bodyCid: string; issuer: string };
  try {
    const link = viewerOrigin + reference;
    const parsed = parseLink(link, { trustedOrigins: [viewerOrigin] });
    if (parsed.form !== 'short' || parsed.pathType !== 'openkey-approval-request' || parsed.id !== id) throw linkRequiredError();
    const opened = await resolveLink(link, { trustedOrigins: [viewerOrigin], apiOrigin: linksOrigin, fetch: Object.assign(fetchLink, { preconnect: fetch.preconnect }) });
    if (opened.type !== 'openkey-approval-request') throw linkRequiredError();
    header = opened.header;
  } catch (error) {
    // A link that does not parse or open is not a link the caller holds, except where the links service
    // is the problem (503, nothing was refused) or the link is over (410, as for an expired request).
    if (error instanceof ApprovalResultError) throw error;
    if (error && typeof error === 'object' && 'code' in error) {
      const status = 'status' in error && typeof error.status === 'number' ? error.status : 0;
      if (error.code === 'service_unavailable' || (error.code === 'service_refused' && status >= 500)) {
        throw new ApprovalResultError('service_unavailable', 'The approval link service is unavailable. Try again.', 503);
      }
      if (error.code === 'expired' || error.code === 'gone') throw new ApprovalResultError('expired_request', 'Approval request expired', 410);
      throw linkRequiredError();
    }
    throw error;
  }
  return c.json(await service.deny(id, header));
});

/** Rechecked immediately before signing, not only when the browser loads. */
export async function checkApprovalDelegation(body: { approvalRequestId?: unknown; jwk: unknown; host: unknown; permissions?: unknown }, input: { expiryMs?: number; signedSiwe?: string }): Promise<void> {
  if (body.approvalRequestId === undefined) return;
  await approvalResultService().assertDelegationWindow(body.approvalRequestId, { ...body, permissions: body.permissions, ...input });
}

const admissions = new WeakMap<object, Date>();

/** Admits the approval right before signing starts: expiry is decided here and deny is held off until it is saved. */
export async function admitApprovalDelegation(body: { approvalRequestId?: unknown }): Promise<void> {
  if (body.approvalRequestId === undefined) return;
  admissions.set(body, await approvalResultService().admit(String(body.approvalRequestId)));
}

/** After a failed attempt: gives the admission back so deny and a retry need not wait. Never throws. */
export async function releaseApprovalDelegation(body: { approvalRequestId?: unknown }): Promise<void> {
  const marker = admissions.get(body);
  if (!marker) return;
  admissions.delete(body);
  await approvalResultService().release(String(body.approvalRequestId), marker).catch(() => undefined);
}

/** Turns a renewal failure into what the owner sees; a caller error keeps its own answer. */
function renewalFailure(error: unknown): never {
  if (error instanceof ApprovalResultError) throw error;
  if (error instanceof RenewalLeaseError && error.status !== 503) throw new ApprovalResultError(error.code, error.message, error.status);
  logError('warn', 'approval_renewal_failed', error);
  throw new ApprovalResultError('renewal_failed', RENEWAL_FAILED_MESSAGE, 503);
}

/** What an approval returns: the saved result, or (external wallet) the renewal lease the owner must sign next. */
export type SavedApproval = (Record<string, unknown> & { approvalCode?: ApprovalCode | null }) | { renewalSignature: { message: string } };

/**
 * Saves the approved grant as the request's result. When the request signed a renewal request and the owner
 * left renewal on, the result also carries the node-admitted owner lease (TC-2933): `signOwner` signs it with
 * the owner's managed key; without it (an external wallet) the lease message is returned for the owner to sign
 * and nothing is saved yet. A step already saved for this request is reused, never signed again.
 */
export async function saveApprovalDelegation(
  body: { approvalRequestId?: unknown; jwk: unknown; host: unknown; permissions?: unknown; renewal?: unknown },
  userId: string,
  delegation: Record<string, unknown>,
  signOwner?: (message: string) => Promise<string>,
): Promise<SavedApproval> {
  if (body.approvalRequestId === undefined) return delegation;
  const id = String(body.approvalRequestId);
  const service = approvalResultService();
  const marker = admissions.get(body);
  const record = await service.store.findById(id);
  if (!record) throw new ApprovalResultError('expired_request', 'Approval request is no longer pending', 410);
  let choice;
  try {
    choice = parseRenewalChoice(body.renewal, record.request.renewal);
  } catch (error) {
    renewalFailure(error);
  }
  // A lease this owner already signed for the request is the approval (C5): a retry collects it, never a different grant.
  if (record.renewal?.leaseAuthorization && marker) {
    if (record.renewal.userId !== userId) throw new ApprovalResultError('request_binding', 'Another account is approving this request', 409);
    return finishLeasedApproval(id, userId, record.request, record.renewal, marker);
  }
  if (choice?.choice !== 'leased') {
    const approvalCode = await service.approve(id, userId, { ...body, permissions: body.permissions }, delegation, marker, choice ?? undefined);
    return { ...delegation, approvalCode };
  }
  if (!marker) throw new ApprovalResultError('request_binding', 'Renewal needs an admitted approval', 409);
  let stage: RenewalStage;
  try {
    stage = record.renewal ?? await prepareRenewalStage({ userId, host: record.request.nodeOrigin, leaseLifetimeSeconds: choice.leaseLifetimeSeconds, delegation, now: new Date() });
    if (stage.userId !== userId) throw new RenewalLeaseError('request_binding', 'Another account is approving this request', 409);
    if (!record.renewal) await service.saveRenewal(id, stage, marker);
    if (!stage.leaseAuthorization) {
      if (!signOwner) {
        // The owner's wallet signs the lease next; the request stays open for that step.
        await releaseApprovalDelegation(body);
        return { renewalSignature: { message: stage.leaseSiwe } };
      }
      stage = signLease(stage, await signOwner(stage.leaseSiwe));
      await service.saveRenewal(id, stage, marker);
    }
  } catch (error) {
    renewalFailure(error);
  }
  return finishLeasedApproval(id, userId, record.request, stage, marker);
}

async function finishLeasedApproval(id: string, userId: string, request: ApprovalRequestRecord['request'], stage: RenewalStage, marker: Date) {
  let renewal;
  try {
    renewal = await admitLease(stage, request);
  } catch (error) {
    renewalFailure(error);
  }
  // The result carries the saved grant, the one the lease names, whatever this attempt signed.
  const approvalCode = await approvalResultService().approve(id, userId, { jwk: request.targetPublicJwk, host: request.nodeOrigin, permissions: request.permissions }, stage.delegation, marker, { choice: 'leased', renewal });
  return { ...stage.delegation, approvalCode };
}

/**
 * The external wallet's signature on the renewal lease (TC-2933), after `/api/delegate/complete` returned it to
 * sign. Checked against the owner of the saved grant, then the lease is admitted and the result saved.
 */
approvalRequestRouter.post('/approval-requests/:id/renewal-signature', requireAccountOriginForBearer, requireSession, async (c) => {
  const id = c.req.param('id');
  const userId: string = c.get('user').id;
  const body: unknown = await c.req.json().catch(() => null);
  const signature = body && typeof body === 'object' && 'signature' in body ? body.signature : undefined;
  if (typeof signature !== 'string') throw new ApprovalResultError('invalid_request', 'A signature is required', 400);
  const service = approvalResultService();
  const record = await service.store.findById(id);
  const saved = record?.renewal;
  if (!record || !saved || saved.userId !== userId || record.resultRef) throw new ApprovalResultError('expired_request', 'Approval request is no longer pending', 410);
  const marker = await service.admit(id);
  try {
    let stage = saved;
    if (!stage.leaseAuthorization) {
      let signer = '';
      try { signer = verifyMessage(stage.leaseSiwe, signature); } catch { /* refused below */ }
      if (signer.toLowerCase() !== stage.ownerAddress.toLowerCase()) throw new ApprovalResultError('invalid_signature', 'The renewal signature is not from this account', 400);
      try {
        stage = signLease(stage, signature);
        await service.saveRenewal(id, stage, marker);
      } catch (error) {
        renewalFailure(error);
      }
    }
    return c.json(await finishLeasedApproval(id, userId, record.request, stage, marker));
  } catch (error) {
    await service.release(id, marker).catch(() => undefined);
    throw error;
  }
});
