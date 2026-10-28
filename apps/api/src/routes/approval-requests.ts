import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { parseLink, resolveLink, parseApprovalRequest, validateLinkHeader, verifyHeader, linkIssuerPublicKey } from '@tinycloud/share-envelope/links';
import { ApprovalResultError, ApprovalResultService } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { verifySessionProofClaims } from '../services/native-delegation/session-proof';
import { createHash } from 'node:crypto';

const prisma = createPrismaClient();
const store = createPrismaApprovalRequestStore(prisma);
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
  return new ApprovalResultService(store, { apiOrigin, retentionSeconds: configured === undefined ? 600 : Number(configured) });
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
  if (error instanceof ApprovalResultError) return c.json({ error: error.message, code: error.code }, error.status);
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
  return c.json({ request: record.request, requestId: id, bodyCid: record.bodyCid, expiresAt: record.expiresAt.toISOString(), approved: !!record.resultRef });
});

approvalRequestRouter.post('/approval-requests/:id/result', async (c) => {
  const service = approvalResultService();
  const id = c.req.param('id');
  const body = await c.req.json();
  const proof = c.req.header('OpenKey-Session-Proof');
  if (!/^[a-z2-7]{26}$/.test(id) || typeof body.bodyCid !== 'string') throw new ApprovalResultError('invalid_request', 'Approval reference is invalid', 400);
  const record = await store.findById(id);
  if (!record) {
    // Before a browser opens the sealed request, authenticate only the
    // issuer-signed public header. No client-supplied DID or JWK is trusted.
    const header = validateLinkHeader(body.header, { mode: 'signed', audience: linksOrigin });
    const bytes = linkIssuerPublicKey(header.issuer);
    if (!bytes || !verifyHeader(header, body.signature) || header.type !== 'openkey-approval-request' || header.bodyCid !== body.bodyCid || Date.parse(header.expiresAt) <= Date.now() || Date.parse(header.expiresAt) - Date.parse(header.issuedAt) > 86400_000) {
      throw new ApprovalResultError('invalid_request', 'Signed approval request header is invalid or expired', 400);
    }
    const x = Buffer.from(bytes).toString('base64url');
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
    if (!verifySessionProofClaims(proof, { sessionJwk: { x }, sessionJkt: jkt, htu: `${apiOrigin}/api/approval-requests/${id}/result`, clientId: 'openkey-approval-result-v1', credential: JSON.stringify(['discover', id, body.bodyCid, '', '']) })) {
      throw new ApprovalResultError('invalid_proof', 'Requester proof is invalid', 401);
    }
    return c.json({ status: 'pending' }, 202);
  }
  const result = await service.discover(id, body, proof);
  return c.json(result, result.status === 'pending' ? 202 : 200);
});

approvalRequestRouter.post('/approval-results/:ref/fetch', async (c) => c.json(await approvalResultService().fetch(c.req.param('ref'), await c.req.json(), c.req.header('OpenKey-Session-Proof'))));
approvalRequestRouter.post('/approval-results/:ref/ack', async (c) => c.json(await approvalResultService().acknowledge(c.req.param('ref'), await c.req.json(), c.req.header('OpenKey-Session-Proof'))));

/** Rechecked immediately before signing, not only when the browser loads. */
export async function checkApprovalDelegation(body: { approvalRequestId?: unknown; jwk: unknown; host: unknown; permissions?: unknown }, input: { expiryMs?: number; signedSiwe?: string }): Promise<void> {
  if (body.approvalRequestId === undefined) return;
  await approvalResultService().assertDelegationWindow(body.approvalRequestId, { ...body, permissions: body.permissions, ...input });
}

export async function saveApprovalDelegation<T extends Record<string, unknown>>(body: { approvalRequestId?: unknown; jwk: unknown; host: unknown; permissions?: unknown }, userId: string, delegation: T): Promise<T> {
  if (body.approvalRequestId !== undefined) {
    await approvalResultService().approve(String(body.approvalRequestId), userId, { ...body, permissions: body.permissions }, delegation);
  }
  return delegation;
}
