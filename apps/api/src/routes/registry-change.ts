// TC-3893: registry-change API routes.
//
//   POST /api/registry-change/prepare
//     - `rejectNonBrowserControlRequest` (same-site OpenKey browser Origin, NO Bearer) + `requireSession`
//     - Requesting app origin MUST come from `X-OpenKey-Requesting-Origin` (400 if missing/non-canonical),
//       NEVER from any request body field and with no fallback to HTTP `Origin`.
//     - In production, refuses with 503 `registry_change_notice_unavailable` if email sender is unconfigured.
//     - Enforces request caps (nodes <= 16, spaces <= 64) before any fetch.
//     - Per-owner rate limit (`registry_change_prepare`, default 20/h).
//     - Reads current verified v2 record (409 `registry_record_missing` when absent).
//     - Canonicalises node URLs (400 `registry_change_invalid_node` on unparseable),
//       probes node identity with SSRF filter + concurrency <= 4 (`ok | mismatch | unreachable`, warn-only),
//       returns 422 `registry_change_node_did_required` for a new unreachable host with no DID,
//       merges spaces without dropping unrelated spaces, sets sequence = current + 1 and updated_at = now.
//     - Mints single-use HMAC `changeId` ticket and ALWAYS creates a passkey offer bound to
//       `{ purpose: 'registry_change', requestDigest: approvalRequestDigest(subject, requestingOrigin, recordHash) }`.
//
//   POST /api/registry-change/undo/prepare
//     - `rejectNonBrowserControlRequest` + `requireSession` + `X-OpenKey-Requesting-Origin`
//     - Loads any owned history row and builds an exact REPLACE payload from `previousRecord` at seq = current + 1.
//
//   POST /api/registry-change/publish
//     - `rejectNonBrowserControlRequest` + `requireSession`
//     - Body: `{ changeId, passkeyAssertion }` (any origin in the body is ignored).
//     - Per-owner rate limit (`registry_change_publish`, default 5/h).
//     - Passkey ALWAYS required regardless of `passkeyApprovalMode` (`NEVER` does not apply).
//     - Re-reads current v2 record; sequence/payload drift -> 409 `registry_change_stale`.
//     - Consumes single-use `changeId` nonce (`rc:` prefix in `TinyCloudSetupConsumedNonce`).
//     - Stores `previousRecord` (full signed current JSON) in `RegistryChangeHistory` BEFORE PUT;
//       deletes that row if PUT or accepted==prepared verification fails (no phantom history).
//     - Signs with `signManagedKey`, PUTs directly to the registry, verifies accepted == prepared.
//     - Sends notice email via Resend with Monica's wording.
//
//   GET /api/registry-change/history?limit=10
//     - `requireSession` (owner's own history rows, newest first, excluding rows with newSequence > current.sequence).
//     - Credentialed CORS limited exclusively to TinyCloud One origins.

import { Hono, type Context, type MiddlewareHandler } from 'hono';
import { cors } from 'hono/cors';
import { createHash, randomUUID } from 'node:crypto';
import { Resend } from 'resend';
import { createPrismaClient, type Prisma, type PrismaClient } from '@openkey/db';
import { canonicalLocationPayloadV2, validateLocationRecordV2Payload, type LocationRecordV2Payload } from '@tinycloud/sdk-core';
import { API_EXPOSED_HEADERS } from '../origin-policy';
import { requireSession, type SessionContext } from '../middleware/session';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';
import { primaryKeyWhere } from '../services/primary-key';
import { signManagedKey } from '../services/managed-key-signing';
import {
  PASSKEY_APPROVAL_REQUIRED,
  approvalRequestDigest,
  checkRequiredApprovalPasskey,
  relyingParty,
  requiredApprovalPasskeyOffer,
  type RelyingParty,
} from '../services/approval-passkey';
import {
  createPrismaPerOwnerLimiter,
  type PerOwnerLimiter,
} from '../services/tinycloud-setup-rate-limit';
import { prismaSetupNonceStore } from '../services/tinycloud-setup-ticket';
import {
  REGISTRY_CHANGE_TICKET_PURPOSE,
  RegistryChangeTicketError,
  createRegistryChangeTicketStore,
  type RegistryChangeTicketStore,
} from '../services/registry-change-ticket';
import {
  RegistryChangeError,
  payloadWithoutSignature,
  prepareRegistryChangeRecord,
  prepareRegistryUndoRecord,
  publishSignedLocationRecordV2,
  readCurrentLocationRecordV2,
  validateRequestBounds,
  type HostResolver,
} from '../services/registry-change-client';
import { sendRegistryChangeNoticeEmail } from '../services/registry-change-email';
import type { EmailSender } from '../services/email-otp-delivery';

export const REQUESTING_ORIGIN_HEADER = 'x-openkey-requesting-origin';

/** TinyCloud One origins permitted to read `/api/registry-change/history` with credentials. */
export const REGISTRY_HISTORY_ALLOWED_ORIGINS: ReadonlySet<string> = new Set([
  'https://tinycloud.one',
  'https://home.tinycloud.xyz',
]);

/**
 * Credentialed CORS middleware restricted exclusively to TinyCloud One origins.
 * Origins outside `REGISTRY_HISTORY_ALLOWED_ORIGINS` receive no `Access-Control-Allow-Origin`
 * or `Access-Control-Allow-Credentials` header.
 */
export function createRegistryHistoryCorsMiddleware(): MiddlewareHandler {
  return cors({
    origin: (origin) => (REGISTRY_HISTORY_ALLOWED_ORIGINS.has(origin) ? origin : undefined),
    credentials: true,
    allowMethods: ['GET', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    exposeHeaders: API_EXPOSED_HEADERS,
  });
}

export type RegistryChangeRateAction = 'registry_change_prepare' | 'registry_change_publish';

export const DEFAULT_REGISTRY_CHANGE_LIMITS: Record<RegistryChangeRateAction, number> = {
  registry_change_prepare: 20,
  registry_change_publish: 5,
};

export interface RegistryChangeRouterDeps {
  readonly ticketStore: RegistryChangeTicketStore;
  readonly retryAfter: PerOwnerLimiter<RegistryChangeRateAction>;
  readonly prisma: PrismaClient;
  readonly emailSender: EmailSender | null;
  readonly isProduction?: boolean;
  readonly getServerTime?: () => Date;
  readonly registryUrl?: string;
  readonly fetch?: typeof fetch;
  readonly resolveHost?: HostResolver;
  readonly rp?: RelyingParty;
  /** Override signer for tests; defaults to TEE `signManagedKey`. */
  readonly signMessage?: (
    keyDescriptor: { userId: string; sealingContext: string | null },
    sealedBlob: string,
    message: string,
  ) => Promise<string>;
  /** For tests. In production the default `rejectNonBrowserControlRequest` runs. */
  readonly originMiddleware?: MiddlewareHandler<SessionContext>;
  /** For tests. In production the default `requireSession` runs. */
  readonly sessionMiddleware?: MiddlewareHandler<SessionContext>;
}

export function registryChangePasskeyBinding(subject: string, requestingOrigin: string, recordHash: string) {
  return {
    purpose: REGISTRY_CHANGE_TICKET_PURPOSE,
    requestDigest: approvalRequestDigest(subject, requestingOrigin, recordHash),
  };
}

function defaultIsProduction(): boolean {
  return process.env.NODE_ENV === 'production' || process.env.TEE_MODE === 'production';
}

function defaultEmailSender(): EmailSender | null {
  return process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
}

export function defaultRegistryChangeDeps(): RegistryChangeRouterDeps {
  const prisma = createPrismaClient();
  const rawSecret = process.env.OPENKEY_REGISTRY_CHANGE_TICKET_SECRET ?? process.env.OPENKEY_SETUP_TICKET_SECRET ?? '';
  const secret = Buffer.from(rawSecret, 'hex');
  const ticketStore = createRegistryChangeTicketStore(secret, prismaSetupNonceStore(prisma));
  const retryAfter = createPrismaPerOwnerLimiter<RegistryChangeRateAction>(prisma, DEFAULT_REGISTRY_CHANGE_LIMITS);
  return {
    ticketStore,
    retryAfter,
    prisma,
    emailSender: defaultEmailSender(),
  };
}

function registryErrorResponse(c: Context, error: RegistryChangeError) {
  return c.json(
    {
      error: error.code,
      message: error.message,
      ...(error.host !== undefined ? { host: error.host } : {}),
    },
    error.status,
  );
}

export function createRegistryChangeRouter(injected?: Partial<RegistryChangeRouterDeps>): Hono<SessionContext> {
  let cached: RegistryChangeRouterDeps | null = null;
  const resolveDeps = (): RegistryChangeRouterDeps | null => {
    if (cached) return cached;
    try {
      if (injected?.ticketStore && injected.retryAfter && injected.prisma) {
        cached = {
          emailSender: injected.emailSender ?? null,
          ...injected,
          ticketStore: injected.ticketStore,
          retryAfter: injected.retryAfter,
          prisma: injected.prisma,
        };
      } else {
        cached = { ...defaultRegistryChangeDeps(), ...injected };
      }
      return cached;
    } catch {
      return null;
    }
  };

  let cachedPrisma: PrismaClient | null = null;
  const resolvePrisma = (): PrismaClient => {
    if (injected?.prisma) return injected.prisma;
    if (cached?.prisma) return cached.prisma;
    cachedPrisma ??= createPrismaClient();
    return cachedPrisma;
  };

  const router = new Hono<SessionContext>();
  // F4: reject any request carrying an Authorization header (cookie-session only from OpenKey origin).
  const originGuard: MiddlewareHandler<SessionContext> = injected?.originMiddleware ?? (async (c, next) => {
    const refusal = rejectNonBrowserControlRequest(c);
    if (refusal) return refusal;
    await next();
  });
  const sessionGuard: MiddlewareHandler<SessionContext> = injected?.sessionMiddleware ?? requireSession;

  router.use('/history', createRegistryHistoryCorsMiddleware());
  router.use('*', sessionGuard);
  router.use('/prepare', originGuard);
  router.use('/undo/prepare', originGuard);
  router.use('/publish', originGuard);

  router.post('/prepare', async (c: Context<SessionContext>) => {
    const deps = resolveDeps();
    if (!deps) return c.json({ error: 'registry_change_unavailable' }, 503);

    const isProd = deps.isProduction ?? defaultIsProduction();
    // F7: email notice is a required mitigation in production; refuse prepare when unconfigured.
    if (isProd && !deps.emailSender) {
      return c.json({ error: 'registry_change_notice_unavailable' }, 503);
    }

    // F4: require X-OpenKey-Requesting-Origin (no fallback to HTTP Origin, never from body).
    const requestingOrigin = parseRequiredRequestingOriginHeader(c);
    if (!requestingOrigin) {
      return c.json({ error: 'requesting_origin_required' }, 400);
    }

    const body = await readJsonBody(c);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({ error: 'malformed_body' }, 400);
    }
    const requestPayload = (body as { request?: unknown }).request;
    if (!requestPayload || typeof requestPayload !== 'object' || Array.isArray(requestPayload)) {
      return c.json({ error: 'registry_change_invalid_node', message: 'Missing request object' }, 400);
    }

    // F1: enforce node (<=16) and space (<=64) caps + URL syntax BEFORE any fetch!
    try {
      validateRequestBounds(requestPayload);
    } catch (error) {
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      throw error;
    }

    const userId = c.get('user').id;
    const sessionId = c.get('session').id;
    const primary = await deps.prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true },
    });
    if (!primary) return c.json({ error: 'no_primary_key' }, 404);

    const subject = subjectFromAddress(primary.address);
    const now = deps.getServerTime?.() ?? new Date();
    const retryAfterSec = await deps.retryAfter(subject, 'registry_change_prepare', now.getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }

    let current;
    try {
      current = await readCurrentLocationRecordV2({
        subject,
        ...(deps.registryUrl ? { registryUrl: deps.registryUrl } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
      });
    } catch (error) {
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      throw error;
    }
    if (!current) {
      return c.json({ error: 'registry_record_missing' }, 409);
    }

    let prepared;
    try {
      prepared = await prepareRegistryChangeRecord({
        current,
        request: requestPayload,
        now,
        allowLoopback: !isProd,
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
        ...(deps.resolveHost ? { resolveHost: deps.resolveHost } : {}),
      });
    } catch (error) {
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      throw error;
    }

    const passkeyBinding = registryChangePasskeyBinding(subject, requestingOrigin, prepared.recordHash);
    const passkey = await requiredApprovalPasskeyOffer(
      deps.prisma,
      { sessionId, userId },
      passkeyBinding,
      deps.rp ?? relyingParty(),
      now,
    );
    if (!passkey) {
      return c.json({
        error: PASSKEY_APPROVAL_REQUIRED.error,
        code: PASSKEY_APPROVAL_REQUIRED.code,
      }, 403);
    }

    const changeId = deps.ticketStore.mint(
      {
        subject,
        verifiedRequestingOrigin: requestingOrigin,
        currentSequence: current.sequence,
        beforeHash: prepared.beforeHash,
        recordHash: prepared.recordHash,
        payloadCanonical: prepared.payloadCanonical,
      },
      now,
    );

    return c.json({
      changeId,
      requestingOrigin,
      before: prepared.before,
      after: prepared.after,
      recordHash: prepared.recordHash,
      identity: prepared.identity,
      encryptionChanged: prepared.encryptionChanged,
      passkey,
    });
  });

  // TC-3893: restore any owned history row's previousRecord EXACTLY (REPLACE, not merge)
  // at sequence = current + 1, published through the standard `/publish` route.
  router.post('/undo/prepare', async (c: Context<SessionContext>) => {
    const deps = resolveDeps();
    if (!deps) return c.json({ error: 'registry_change_unavailable' }, 503);

    const isProd = deps.isProduction ?? defaultIsProduction();
    if (isProd && !deps.emailSender) {
      return c.json({ error: 'registry_change_notice_unavailable' }, 503);
    }

    const requestingOrigin = parseRequiredRequestingOriginHeader(c);
    if (!requestingOrigin) {
      return c.json({ error: 'requesting_origin_required' }, 400);
    }

    const body = await readJsonBody(c);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({ error: 'malformed_body' }, 400);
    }
    const historyId = (body as { historyId?: unknown }).historyId;
    if (typeof historyId !== 'string' || historyId.length === 0) {
      return c.json({ error: 'history_id_required' }, 400);
    }

    const userId = c.get('user').id;
    const sessionId = c.get('session').id;
    const primary = await deps.prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true },
    });
    if (!primary) return c.json({ error: 'no_primary_key' }, 404);

    const subject = subjectFromAddress(primary.address);
    const now = deps.getServerTime?.() ?? new Date();
    const retryAfterSec = await deps.retryAfter(subject, 'registry_change_prepare', now.getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }

    const row = await deps.prisma.registryChangeHistory.findUnique({
      where: { id: historyId },
      select: {
        id: true,
        userId: true,
        subject: true,
        previousRecord: true,
        newSequence: true,
        createdAt: true,
      },
    });
    if (!row || row.userId !== userId || row.subject !== subject) {
      return c.json({ error: 'history_not_found' }, 404);
    }

    let current;
    try {
      current = await readCurrentLocationRecordV2({
        subject,
        ...(deps.registryUrl ? { registryUrl: deps.registryUrl } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
      });
    } catch (error) {
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      throw error;
    }
    if (!current) {
      return c.json({ error: 'registry_record_missing' }, 409);
    }

    let prepared;
    try {
      prepared = await prepareRegistryUndoRecord({
        current,
        previousRecord: row.previousRecord,
        now,
        allowLoopback: !isProd,
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
        ...(deps.resolveHost ? { resolveHost: deps.resolveHost } : {}),
      });
    } catch (error) {
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      throw error;
    }

    const latestRow = (await deps.prisma.registryChangeHistory.findMany({
      where: { userId },
      orderBy: [{ createdAt: 'desc' }, { newSequence: 'desc' }],
      take: 1,
      select: { id: true },
    }))[0];
    const isLatestUndo = latestRow?.id === row.id && row.newSequence === current.sequence;

    const passkeyBinding = registryChangePasskeyBinding(subject, requestingOrigin, prepared.recordHash);
    const passkey = await requiredApprovalPasskeyOffer(
      deps.prisma,
      { sessionId, userId },
      passkeyBinding,
      deps.rp ?? relyingParty(),
      now,
    );
    if (!passkey) {
      return c.json({
        error: PASSKEY_APPROVAL_REQUIRED.error,
        code: PASSKEY_APPROVAL_REQUIRED.code,
      }, 403);
    }

    const changeId = deps.ticketStore.mint(
      {
        subject,
        verifiedRequestingOrigin: requestingOrigin,
        currentSequence: current.sequence,
        beforeHash: prepared.beforeHash,
        recordHash: prepared.recordHash,
        payloadCanonical: prepared.payloadCanonical,
      },
      now,
    );

    return c.json({
      changeId,
      requestingOrigin,
      before: prepared.before,
      after: prepared.after,
      recordHash: prepared.recordHash,
      identity: prepared.identity,
      encryptionChanged: prepared.encryptionChanged,
      passkey,
      undoKind: isLatestUndo ? 'undo-last' : 'restore',
      restoredBeforeDate: row.createdAt.toISOString(),
    });
  });

  router.post('/publish', async (c: Context<SessionContext>) => {
    const deps = resolveDeps();
    if (!deps) return c.json({ error: 'registry_change_unavailable' }, 503);

    const body = await readJsonBody(c);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({ error: 'malformed_body' }, 400);
    }
    const changeId = (body as { changeId?: unknown }).changeId;
    if (typeof changeId !== 'string' || changeId.length === 0) {
      return c.json({ error: 'change_id_required' }, 400);
    }
    const passkeyAssertion = (body as { passkeyAssertion?: unknown }).passkeyAssertion;

    const user = c.get('user');
    const userId = user.id;
    const sessionId = c.get('session').id;
    const primary = await deps.prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true, sealedPrivateKey: true, sealingContext: true, userId: true },
    });
    if (!primary || !primary.sealedPrivateKey) {
      return c.json({ error: 'no_primary_key' }, 404);
    }

    const subject = subjectFromAddress(primary.address);
    const now = deps.getServerTime?.() ?? new Date();
    const retryAfterSec = await deps.retryAfter(subject, 'registry_change_publish', now.getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }

    let decoded;
    try {
      decoded = deps.ticketStore.decode(changeId);
    } catch (error) {
      if (error instanceof RegistryChangeTicketError) {
        return c.json({ error: error.code }, error.status);
      }
      throw error;
    }
    if (decoded.subject !== subject) {
      return c.json({ error: 'subject_mismatch' }, 403);
    }

    // ALWAYS require a fresh passkey assertion bound to (subject, verifiedRequestingOrigin, recordHash).
    const passkeyBinding = registryChangePasskeyBinding(
      subject,
      decoded.verifiedRequestingOrigin,
      decoded.recordHash,
    );
    const passkeyRefusal = await checkRequiredApprovalPasskey(
      deps.prisma,
      { sessionId, userId },
      passkeyBinding,
      passkeyAssertion,
      deps.rp ?? relyingParty(),
      now,
    );
    if (passkeyRefusal) {
      return c.json({ error: passkeyRefusal.code, code: passkeyRefusal.code, message: passkeyRefusal.error }, 403);
    }

    // Re-read current from registry immediately before consuming/signing; refuse on any drift.
    let current;
    try {
      current = await readCurrentLocationRecordV2({
        subject,
        ...(deps.registryUrl ? { registryUrl: deps.registryUrl } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
      });
    } catch (error) {
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      throw error;
    }
    if (!current) {
      return c.json({ error: 'registry_record_missing' }, 409);
    }
    const currentBeforeHash = createHash('sha256')
      .update(canonicalLocationPayloadV2(payloadWithoutSignature(current)), 'utf8')
      .digest('hex');
    if (current.sequence !== decoded.currentSequence || currentBeforeHash !== decoded.beforeHash) {
      return c.json({ error: 'registry_change_stale' }, 409);
    }

    let payload: LocationRecordV2Payload;
    try {
      payload = validateLocationRecordV2Payload(JSON.parse(decoded.payloadCanonical));
    } catch {
      return c.json({ error: 'record_mismatch' }, 403);
    }
    if (payload.sequence !== current.sequence + 1) {
      return c.json({ error: 'registry_change_stale' }, 409);
    }

    try {
      await deps.ticketStore.consume(
        changeId,
        {
          subject,
          verifiedRequestingOrigin: decoded.verifiedRequestingOrigin,
          recordHash: decoded.recordHash,
          currentSequence: current.sequence,
        },
        now,
      );
    } catch (error) {
      if (error instanceof RegistryChangeTicketError) {
        return c.json({ error: error.code }, error.status);
      }
      throw error;
    }

    // Store PREVIOUS record BEFORE PUT so undo data is durable if the connection drops right
    // after the registry accepts the PUT; clean up that row on PUT/verification failure (F2).
    const historyRowId = randomUUID();
    await deps.prisma.registryChangeHistory.create({
      data: {
        id: historyRowId,
        userId,
        subject,
        requestingOrigin: decoded.verifiedRequestingOrigin,
        previousRecord: current as unknown as Prisma.InputJsonValue,
        newRecordHash: decoded.recordHash,
        newSequence: payload.sequence,
        createdAt: now,
      },
    });

    const sealedBlob = primary.sealedPrivateKey;
    const keyDescriptor = { userId: primary.userId, sealingContext: primary.sealingContext ?? null };
    const signFn = deps.signMessage ?? signManagedKey;

    let accepted;
    try {
      accepted = await publishSignedLocationRecordV2({
        payload,
        payloadCanonical: decoded.payloadCanonical,
        ...(deps.registryUrl ? { registryUrl: deps.registryUrl } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
        signer: {
          type: 'did:pkh',
          signMessage: async (message: string) => signFn(keyDescriptor, sealedBlob, message),
        },
      });
    } catch (error) {
      // F2: remove phantom history row when PUT or accepted==prepared verification failed.
      await deps.prisma.registryChangeHistory.delete({ where: { id: historyRowId } }).catch(() => undefined);
      if (error instanceof RegistryChangeError) return registryErrorResponse(c, error);
      return c.json({ error: 'registry_publish_failed' }, 502);
    }

    // Send the post-publish notice email via Resend.
    const ownerEmail = user.email
      || (await deps.prisma.user.findUnique({ where: { id: userId }, select: { email: true } }))?.email
      || null;
    if (ownerEmail) {
      await sendRegistryChangeNoticeEmail(deps.emailSender, {
        to: ownerEmail,
        requestingOrigin: decoded.verifiedRequestingOrigin,
        before: payloadWithoutSignature(current),
        after: payload,
        publishedAt: now,
      });
    }

    return c.json({
      sequence: accepted.sequence,
      recordHash: decoded.recordHash,
    });
  });

  router.get('/history', async (c: Context<SessionContext>) => {
    const prisma = resolvePrisma();
    const userId = c.get('user').id;
    const rawLimit = c.req.query('limit');
    let limit = 10;
    if (rawLimit !== undefined) {
      const parsed = Number(rawLimit);
      if (!Number.isInteger(parsed) || parsed < 1) {
        return c.json({ error: 'invalid_limit' }, 400);
      }
      limit = Math.min(parsed, 50);
    }

    // F2 defense-in-depth: read current verified sequence best-effort so phantom rows with
    // newSequence > current.sequence are excluded from history responses.
    let currentSequence: number | null = null;
    const primary = await prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true },
    });
    if (primary) {
      const deps = resolveDeps();
      try {
        const current = await readCurrentLocationRecordV2({
          subject: subjectFromAddress(primary.address),
          ...(deps?.registryUrl ? { registryUrl: deps.registryUrl } : {}),
          ...(deps?.fetch ? { fetch: deps.fetch } : {}),
        });
        currentSequence = current?.sequence ?? null;
      } catch {
        currentSequence = null;
      }
    }

    const rows = await prisma.registryChangeHistory.findMany({
      where: {
        userId,
        ...(currentSequence !== null ? { newSequence: { lte: currentSequence } } : {}),
      },
      orderBy: [{ createdAt: 'desc' }, { newSequence: 'desc' }],
      take: limit,
      select: {
        id: true,
        requestingOrigin: true,
        previousRecord: true,
        newRecordHash: true,
        newSequence: true,
        createdAt: true,
      },
    });

    const filtered = currentSequence !== null
      ? rows.filter((row) => row.newSequence <= currentSequence!)
      : rows;

    return c.json({
      history: filtered.map((row) => ({
        id: row.id,
        requestingOrigin: row.requestingOrigin,
        previousRecord: row.previousRecord,
        newRecordHash: row.newRecordHash,
        newSequence: row.newSequence,
        createdAt: row.createdAt.toISOString(),
      })),
    });
  });

  return router;
}

async function readJsonBody(c: Context): Promise<unknown | null> {
  try {
    return await c.req.json();
  } catch {
    return null;
  }
}

function parseExactOrigin(raw: string | undefined): string | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const url = new URL(raw);
    if (url.origin === 'null' || url.origin !== raw) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * F4: require the `X-OpenKey-Requesting-Origin` header set by the OpenKey-origin widget
 * from the browser-verified `MessageEvent.origin`. Never falls back to HTTP `Origin`,
 * and never reads from the JSON request body.
 */
function parseRequiredRequestingOriginHeader(c: Context): string | null {
  return parseExactOrigin(c.req.header(REQUESTING_ORIGIN_HEADER));
}

function subjectFromAddress(address: string): string {
  return `did:pkh:eip155:1:${address}`;
}

export const _testing = {
  parseExactOrigin,
  parseRequiredRequestingOriginHeader,
  subjectFromAddress,
};
