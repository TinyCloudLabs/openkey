// TC-3657: outside-app one-tap TinyCloud setup via OpenKey. Sam's TC-3620 pick (14:14:07Z);
// design + conditions at `/var/tmp/integ/outside-app-setup-design.md` §13/§13a. Approved by
// Bobbie 14:32:09Z + 14:58:08Z, Naomi 14:32:33Z + 14:58:46Z + 15:12:55Z. DRAFT PR; merge waits
// on Sam's card + Naomi's head-named GO; deploy waits on Amos + `TINYCLOUD_DEFAULT_NODE_DID` +
// `OPENKEY_SETUP_TICKET_SECRET`.
//
// Two endpoints:
//   POST /api/tinycloud-setup/mint-ticket
//     - requires an OpenKey session + `Origin: <openkey-origin>` (TC-688 via
//       `rejectNonOpenKeySignRequest`, F6 fix 15:16:27Z: fails closed when Origin is missing).
//     - body: `{ requestingOrigin: string }` — the outside app's origin as observed by the
//       widget via `postMessage event.origin` (Bobbie C3). The server trusts this because
//       the request itself is authenticated to have come from the OpenKey-origin widget page.
//     - rate limit: C5/N3 per-owner `mint` action (Prisma-backed; shared across replicas).
//     - returns `{ ticket, passkey, preview }`. `passkey` is either `{ required: true,
//       challengeToken, options }` when the owner's `passkeyApprovalMode` requires it, or
//       `{ required: false }`. The widget then shows the preview and, on approve, assembles
//       the publish request with any passkey assertion.
//
//   POST /api/tinycloud-setup/publish
//     - requires session + Origin check.
//     - body: `{ ticket, requestingOrigin, passkeyAssertion? }`.
//     - rate limit: C5/N3 per-owner `publish` action.
//     - **Bobbie C4 (14:53:16Z, confirmed via 15:14:23Z reviewer check):** calls
//       `checkApprovalPasskey(..., 'sensitive', passkeyAssertion)` before any signing.
//       `publishing a public record linking the owner's address to a server` is a sensitive
//       approval (same category as other OpenKey sign operations), so a `passkeyApprovalMode`
//       of ALWAYS or SENSITIVE requires a fresh passkey assertion bound to the request;
//       NEVER-mode owners get a user-gesture + session + ticket + Origin gate.
//     - consumes the ticket (Prisma single-use via unique constraint).
//     - signs the canonical payload via `signManagedKey` (owner's primary TEE-sealed key).
//     - publishes via `publishTinyCloudSetupRecord` (`onPrepared: current === null` fence).
//     - returns `TinyCloudSetupResultV1`.
//
// Fail-closed environment: without `TINYCLOUD_DEFAULT_NODE_DID` set, both endpoints return
// `{ error: 'setup_unavailable' }` and nothing is minted or signed.

import { Hono, type Context } from 'hono';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createHash } from 'node:crypto';
import { canonicalLocationPayloadV2 } from '@tinycloud/sdk-core';
import { requireSession, type SessionContext } from '../middleware/session';
import { rejectNonOpenKeySignRequest } from '../middleware/browser-control';
import {
  DEFAULT_TINYCLOUD_BOOTSTRAP_HOST,
  defaultTinyCloudBootstrapNode,
} from '../services/tinycloud-hosts';
import {
  SETUP_TICKET_TTL_MS,
  SetupTicketError,
  createSetupTicketStore,
  prismaSetupNonceStore,
  type SetupTicketStore,
} from '../services/tinycloud-setup-ticket';
import {
  createPrismaTinyCloudSetupLimiter,
  type TinyCloudSetupAction,
  type TinyCloudSetupLimiter,
} from '../services/tinycloud-setup-rate-limit';
import {
  TINYCLOUD_SETUP_PRIMARY_SPACE,
  buildTinyCloudSetupPayload,
  publishTinyCloudSetupRecord,
} from '../services/tinycloud-registry-client';
import { primaryKeyWhere } from '../services/primary-key';
import { signManagedKey } from '../services/managed-key-signing';
import {
  approvalPasskeyOffer,
  approvalRequestDigest,
  checkApprovalPasskey,
  type ApprovalPasskeyOffer,
} from '../services/approval-passkey';
import { LocationRecordValidationError, LocationRegistryHttpError } from '@tinycloud/sdk-core';

import type { MiddlewareHandler } from 'hono';

export interface TinyCloudSetupRouterDeps {
  readonly ticketStore: SetupTicketStore;
  readonly retryAfter: TinyCloudSetupLimiter;
  readonly getServerTime?: () => Date;
  readonly configuredHost?: string;
  readonly registryUrl?: string;
  readonly fetch?: typeof fetch;
  readonly prisma: PrismaClient;
  /** For tests. In production the default `rejectNonOpenKeySignRequest` runs. */
  readonly originMiddleware?: MiddlewareHandler<SessionContext>;
  /** For tests. In production the default `requireSession` runs. */
  readonly sessionMiddleware?: MiddlewareHandler<SessionContext>;
}

/** Default dependency wiring. The signing secret for the setup ticket store comes from
 *  `OPENKEY_SETUP_TICKET_SECRET` (hex, >= 32 bytes). When the var is unset or too short,
 *  this throws; the router catches it and returns 503 per request (F5 15:16:27Z lazy init
 *  so an unset env does NOT crash OpenKey boot). Nonce persistence + rate-limit buckets
 *  use Prisma. */
export function defaultDeps(): TinyCloudSetupRouterDeps {
  const prisma = createPrismaClient();
  const rawSecret = process.env.OPENKEY_SETUP_TICKET_SECRET ?? '';
  const secret = Buffer.from(rawSecret, 'hex');
  const ticketStore = createSetupTicketStore(secret, prismaSetupNonceStore(prisma));
  const retryAfter = createPrismaTinyCloudSetupLimiter(prisma);
  return { ticketStore, retryAfter, prisma };
}

export function createTinyCloudSetupRouter(injected?: Partial<TinyCloudSetupRouterDeps>): Hono<SessionContext> {
  // Resolve deps lazily per request so a missing OPENKEY_SETUP_TICKET_SECRET turns into a
  // 503 on the endpoint, not a crash on process boot (F5 15:16:27Z).
  let cached: TinyCloudSetupRouterDeps | null = null;
  const resolveDeps = (): TinyCloudSetupRouterDeps | null => {
    if (cached) return cached;
    try {
      cached = injected && injected.ticketStore && injected.retryAfter && injected.prisma
        ? (injected as TinyCloudSetupRouterDeps)
        : { ...defaultDeps(), ...injected };
      return cached;
    } catch {
      return null;
    }
  };
  const router = new Hono<SessionContext>();
  const originGuard: MiddlewareHandler<SessionContext> = injected?.originMiddleware ?? (async (c, next) => {
    const refusal = rejectNonOpenKeySignRequest(c);
    if (refusal) return refusal;
    await next();
  });
  const sessionGuard: MiddlewareHandler<SessionContext> = injected?.sessionMiddleware ?? requireSession;
  router.use('*', originGuard);
  router.use('*', sessionGuard);

  router.post('/mint-ticket', async (c: Context<SessionContext>) => {
    const deps = resolveDeps();
    if (!deps) return c.json({ error: 'setup_unavailable' }, 503);
    const node = defaultTinyCloudBootstrapNode(deps.configuredHost ?? DEFAULT_TINYCLOUD_BOOTSTRAP_HOST);
    if (!node) return c.json({ error: 'setup_unavailable' }, 503);
    const body = await readJsonBody(c);
    if (!body) return c.json({ error: 'malformed_body' }, 400);
    const requestingOrigin = parseRequestingOrigin(body);
    if (!requestingOrigin) return c.json({ error: 'requesting_origin_required' }, 400);
    const userId = c.get('user').id;
    const sessionId = c.get('session').id;
    const primary = await deps.prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true },
    });
    if (!primary) return c.json({ error: 'no_primary_key' }, 404);
    const subject = subjectFromAddress(primary.address);
    const now = deps.getServerTime?.() ?? new Date();
    const retryAfterSec = await deps.retryAfter(subject, 'mint', now.getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }
    const { hash, space } = buildTinyCloudSetupPayload({ subject, node, now });
    const ticket = deps.ticketStore.mint(
      { subject, verifiedRequestingOrigin: requestingOrigin, recordHash: hash },
      now,
    );
    const passkeyBinding = setupPasskeyBinding(subject, requestingOrigin, hash);
    const passkey: { required: false } | ({ required: true } & ApprovalPasskeyOffer) =
      await approvalPasskeyOffer(deps.prisma, { sessionId, userId }, passkeyBinding, 'sensitive');
    return c.json({
      ticket,
      ttlMs: SETUP_TICKET_TTL_MS,
      passkey,
      preview: { subject, nodeDid: node.nodeDid, nodeOrigin: node.origin, space, primarySpaceName: TINYCLOUD_SETUP_PRIMARY_SPACE },
    });
  });

  router.post('/publish', async (c: Context<SessionContext>) => {
    const deps = resolveDeps();
    if (!deps) return c.json({ error: 'setup_unavailable' }, 503);
    const node = defaultTinyCloudBootstrapNode(deps.configuredHost ?? DEFAULT_TINYCLOUD_BOOTSTRAP_HOST);
    if (!node) return c.json({ error: 'setup_unavailable' }, 503);
    const body = await readJsonBody(c);
    if (!body) return c.json({ error: 'malformed_body' }, 400);
    const ticket = parseTicket(body);
    const requestingOrigin = parseRequestingOrigin(body);
    if (!ticket || !requestingOrigin) return c.json({ error: 'ticket_and_origin_required' }, 400);
    const userId = c.get('user').id;
    const sessionId = c.get('session').id;
    const primary = await deps.prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true, sealedPrivateKey: true, sealingContext: true, userId: true },
    });
    if (!primary || !primary.sealedPrivateKey) return c.json({ error: 'no_primary_key' }, 404);
    const subject = subjectFromAddress(primary.address);
    const now = deps.getServerTime?.() ?? new Date();
    const retryAfterSec = await deps.retryAfter(subject, 'publish', now.getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }
    // F3 fix (Bobbie 15:16:27Z): decode the ticket to recover `mintedAt`, then rebuild the
    // canonical payload at that same moment so its hash matches what the ticket was bound to.
    // The earlier draft used `now` for both the ticket mint hash and the publish rebuild;
    // because `updated_at` depended on wall-clock, the hashes diverged and every real publish
    // failed with 403 `record_mismatch`. Decoding does NOT consume the nonce.
    let decoded: ReturnType<typeof deps.ticketStore.decode>;
    try {
      decoded = deps.ticketStore.decode(ticket);
    } catch (error) {
      if (error instanceof SetupTicketError) return c.json({ error: error.code }, error.status);
      throw error;
    }
    if (decoded.subject !== subject) {
      return c.json({ error: 'subject_mismatch' }, 403);
    }
    if (decoded.verifiedRequestingOrigin !== requestingOrigin) {
      return c.json({ error: 'origin_mismatch' }, 403);
    }
    const { hash } = buildTinyCloudSetupPayload({ subject, node, now: decoded.mintedAt });
    if (hash !== decoded.recordHash) {
      // Belt-and-braces: should be impossible if mint and publish use the same canonicaliser,
      // but we check anyway so a future change that drifts the recipe fails loudly.
      return c.json({ error: 'record_mismatch' }, 403);
    }
    // Bobbie C4 (14:53:16Z + 15:14:23Z): passkey assertion required for owners whose mode is
    // ALWAYS or SENSITIVE. NEVER-mode owners pass through on session + ticket + origin alone.
    const passkeyBinding = setupPasskeyBinding(subject, requestingOrigin, hash);
    const passkeyAssertion = (body as { passkeyAssertion?: unknown }).passkeyAssertion;
    const passkeyRefusal = await checkApprovalPasskey(
      deps.prisma, { sessionId, userId }, passkeyBinding, 'sensitive', passkeyAssertion,
    );
    if (passkeyRefusal) return c.json({ error: passkeyRefusal.code, message: passkeyRefusal.error }, 403);
    try {
      await deps.ticketStore.consume(ticket, { subject, verifiedRequestingOrigin: requestingOrigin, recordHash: hash }, now);
    } catch (error) {
      if (error instanceof SetupTicketError) return c.json({ error: error.code }, error.status);
      throw error;
    }
    const sealedBlob = primary.sealedPrivateKey;
    const sealingContextValue: string | null = primary.sealingContext ?? null;
    const keyDescriptor = { userId: primary.userId, sealingContext: sealingContextValue };
    try {
      await publishTinyCloudSetupRecord({
        subject,
        node,
        now: decoded.mintedAt,
        ...(deps.registryUrl ? { registryUrl: deps.registryUrl } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
        onPrepared: async (prepared, current) => {
          if (current !== null) return false;
          // Bobbie 15:16:27Z explicit onPrepared assert: the bytes we're about to sign must
          // match the ticket's recordHash exactly. Both the server and the client invariants
          // depend on this.
          const preparedHash = createHash('sha256').update(canonicalLocationPayloadV2(prepared), 'utf8').digest('hex');
          return preparedHash === decoded.recordHash;
        },
        signer: {
          type: 'did:pkh',
          signMessage: async (message: string) => signManagedKey(keyDescriptor, sealedBlob, message),
        },
      });
      return c.json({ status: 'published', subject });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return c.json({ status: 'already-current', subject });
      }
      if (error instanceof LocationRecordValidationError) return c.json({ status: 'unavailable', reason: 'registry-error' }, 502);
      if (error instanceof LocationRegistryHttpError) return c.json({ status: 'unavailable', reason: 'registry-error' }, 502);
      return c.json({ status: 'unavailable', reason: 'node-unreachable' }, 502);
    }
  });

  return router;
}

async function readJsonBody(c: Context): Promise<unknown | null> {
  try { return await c.req.json(); } catch { return null; }
}

function parseRequestingOrigin(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const raw = (body as { requestingOrigin?: unknown }).requestingOrigin;
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const url = new URL(raw);
    return url.origin === raw ? raw : null;
  } catch { return null; }
}

function parseTicket(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const raw = (body as { ticket?: unknown }).ticket;
  return typeof raw === 'string' && raw.length > 0 ? raw : null;
}

function subjectFromAddress(address: string): string {
  // TODO(TC-3657 follow-up): respect the account's configured chainId once OpenKey models it.
  return `did:pkh:eip155:1:${address}`;
}

/** The passkey challenge binding for this request: unique per owner + verified requesting
 *  origin + canonical record hash, so a passkey assertion for one setup request cannot be
 *  replayed as an assertion for another request (Bobbie C4 bound-to-request semantics). */
function setupPasskeyBinding(subject: string, requestingOrigin: string, recordHash: string) {
  return {
    purpose: 'tinycloud_setup_publish',
    requestDigest: approvalRequestDigest('tinycloud_setup_publish', subject, requestingOrigin, recordHash),
  };
}

/** Exported for test construction only. */
export const _testing = {
  parseRequestingOrigin,
  parseTicket,
  subjectFromAddress,
  setupPasskeyBinding,
};
