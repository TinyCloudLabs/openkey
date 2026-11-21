// TC-3657: outside-app one-tap TinyCloud setup via OpenKey. Sam's TC-3620 pick (14:14:07Z);
// design + conditions at `/var/tmp/integ/outside-app-setup-design.md` §13/§13a. Approved by
// Bobbie 14:32:09Z + 14:58:08Z, Naomi 14:32:33Z + 14:58:46Z. DRAFT PR; merge waits on Sam's card
// + Naomi's head-named GO; deploy waits on Amos + the `TINYCLOUD_DEFAULT_NODE_DID` env.
//
// Two endpoints:
//   POST /api/tinycloud-setup/mint-ticket
//     - requires an OpenKey session.
//     - requires `Origin: <openkey-origin>` (browser-only; TC-688 pattern via
//       `requireAccountOriginForBearer`).
//     - body: `{ requestingOrigin: string }` — the outside app's origin as observed by the
//       widget via `postMessage event.origin` (Bobbie C3). The server trusts the widget's
//       claim because the request is authenticated to have come from the OpenKey-origin
//       widget page.
//     - rate limit: C5/N3 per-owner `mint` action.
//     - returns `{ ticket, preview: { subject, nodeDid, nodeOrigin, space } }`.
//
//   POST /api/tinycloud-setup/publish
//     - requires session + Origin check.
//     - body: `{ ticket: string }`.
//     - rate limit: C5/N3 per-owner `publish` action.
//     - consumes the ticket (binding check: subject + verifiedRequestingOrigin + recordHash).
//     - signs the canonical payload via `signManagedKey` (owner's primary TEE-sealed key).
//     - publishes via `publishTinyCloudSetupRecord` (`onPrepared: current === null` fence).
//     - returns `TinyCloudSetupResultV1`.
//
// Fail-closed environment: without `TINYCLOUD_DEFAULT_NODE_DID` set, both endpoints return
// `{ error: 'setup_unavailable' }` and nothing is minted or signed (Bobbie C1 the server never
// signs a record pointing at an unverified node).

import { Hono, type Context } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import {
  DEFAULT_TINYCLOUD_BOOTSTRAP_HOST,
  defaultTinyCloudBootstrapNode,
} from '../services/tinycloud-hosts';
import {
  SETUP_TICKET_TTL_MS,
  SetupTicketError,
  createSetupTicketStore,
  type SetupTicketStore,
} from '../services/tinycloud-setup-ticket';
import {
  createTinyCloudSetupLimiter,
  tinyCloudSetupRetryAfter,
  type TinyCloudSetupAction,
} from '../services/tinycloud-setup-rate-limit';
import {
  TINYCLOUD_SETUP_PRIMARY_SPACE,
  buildTinyCloudSetupPayload,
  publishTinyCloudSetupRecord,
} from '../services/tinycloud-registry-client';
import { primaryKeyWhere } from '../services/primary-key';
import { signManagedKey } from '../services/managed-key-signing';
import { LocationRecordValidationError, LocationRegistryHttpError } from '@tinycloud/sdk-core';

interface TinyCloudSetupRouterDeps {
  readonly ticketStore: SetupTicketStore;
  readonly retryAfter: (subject: string, action: TinyCloudSetupAction, now?: number) => number;
  readonly getServerTime?: () => Date;
  readonly configuredHost?: string;
  readonly registryUrl?: string;
  readonly fetch?: typeof fetch;
  readonly prisma?: ReturnType<typeof createPrismaClient>;
}

/** Default dependency wiring; tests inject their own. The signing secret for the setup ticket
 *  store comes from `OPENKEY_SETUP_TICKET_SECRET` (hex, >= 32 bytes). When absent, the store
 *  constructor throws, which keeps production honest. */
function defaultDeps(): TinyCloudSetupRouterDeps {
  const rawSecret = process.env.OPENKEY_SETUP_TICKET_SECRET ?? '';
  const secret = Buffer.from(rawSecret, 'hex');
  const ticketStore = createSetupTicketStore(secret);
  return {
    ticketStore,
    retryAfter: tinyCloudSetupRetryAfter,
  };
}

export function createTinyCloudSetupRouter(injected?: Partial<TinyCloudSetupRouterDeps>): Hono<SessionContext> {
  const base = injected && injected.ticketStore && injected.retryAfter
    ? ({ ...injected } as TinyCloudSetupRouterDeps)
    : { ...defaultDeps(), ...injected };
  const deps: TinyCloudSetupRouterDeps = base;
  const router = new Hono<SessionContext>();
  router.use('*', requireAccountOriginForBearer);
  router.use('*', requireSession);

  router.post('/mint-ticket', async (c: Context<SessionContext>) => {
    const node = defaultTinyCloudBootstrapNode(deps.configuredHost ?? DEFAULT_TINYCLOUD_BOOTSTRAP_HOST);
    if (!node) return c.json({ error: 'setup_unavailable' }, 503);
    let body: unknown;
    try { body = await c.req.json(); }
    catch { return c.json({ error: 'malformed_body' }, 400); }
    const requestingOrigin = parseRequestingOrigin(body);
    if (!requestingOrigin) return c.json({ error: 'requesting_origin_required' }, 400);
    const userId = c.get('user').id;
    const prisma = deps.prisma ?? createPrismaClient();
    const primary = await prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true },
    });
    if (!primary) return c.json({ error: 'no_primary_key' }, 404);
    const subject = subjectFromAddress(primary.address);
    const retryAfterSec = deps.retryAfter(subject, 'mint', (deps.getServerTime?.() ?? new Date()).getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }
    const now = deps.getServerTime?.() ?? new Date();
    const { hash, space } = buildTinyCloudSetupPayload({ subject, node, now });
    const ticket = deps.ticketStore.mint(
      { subject, verifiedRequestingOrigin: requestingOrigin, recordHash: hash },
      now,
    );
    return c.json({
      ticket,
      ttlMs: SETUP_TICKET_TTL_MS,
      preview: { subject, nodeDid: node.nodeDid, nodeOrigin: node.origin, space, primarySpaceName: TINYCLOUD_SETUP_PRIMARY_SPACE },
    });
  });

  router.post('/publish', async (c: Context<SessionContext>) => {
    const node = defaultTinyCloudBootstrapNode(deps.configuredHost ?? DEFAULT_TINYCLOUD_BOOTSTRAP_HOST);
    if (!node) return c.json({ error: 'setup_unavailable' }, 503);
    let body: unknown;
    try { body = await c.req.json(); }
    catch { return c.json({ error: 'malformed_body' }, 400); }
    const ticket = parseTicket(body);
    const requestingOrigin = parseRequestingOrigin(body);
    if (!ticket || !requestingOrigin) return c.json({ error: 'ticket_and_origin_required' }, 400);
    const userId = c.get('user').id;
    const prisma = deps.prisma ?? createPrismaClient();
    const primary = await prisma.ethereumKey.findFirst({
      where: primaryKeyWhere(userId),
      select: { address: true, sealedPrivateKey: true, sealingContext: true, userId: true },
    });
    if (!primary || !primary.sealedPrivateKey) return c.json({ error: 'no_primary_key' }, 404);
    const subject = subjectFromAddress(primary.address);
    const retryAfterSec = deps.retryAfter(subject, 'publish', (deps.getServerTime?.() ?? new Date()).getTime());
    if (retryAfterSec > 0) {
      c.header('retry-after', String(retryAfterSec));
      return c.json({ error: 'rate_limited' }, 429);
    }
    const now = deps.getServerTime?.() ?? new Date();
    const { hash } = buildTinyCloudSetupPayload({ subject, node, now });
    try {
      deps.ticketStore.consume(ticket, { subject, verifiedRequestingOrigin: requestingOrigin, recordHash: hash }, now);
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
        now,
        ...(deps.registryUrl ? { registryUrl: deps.registryUrl } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
        signer: {
          type: 'did:pkh',
          signMessage: async (message: string) => signManagedKey(keyDescriptor, sealedBlob, message),
        },
      });
      return c.json({ status: 'published', subject });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        // onPrepared returned false → a record now exists (TC-3547 C1 already-written case).
        return c.json({ status: 'already-current', subject });
      }
      if (error instanceof LocationRecordValidationError) return c.json({ status: 'unavailable', reason: 'registry-error' }, 502);
      if (error instanceof LocationRegistryHttpError) return c.json({ status: 'unavailable', reason: 'registry-error' }, 502);
      return c.json({ status: 'unavailable', reason: 'node-unreachable' }, 502);
    }
  });

  return router;
}

// Internal helpers kept small + pure for test reuse.

function parseRequestingOrigin(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const raw = (body as { requestingOrigin?: unknown }).requestingOrigin;
  if (typeof raw !== 'string' || raw.length === 0) return null;
  // Browser-derived origins are always canonical "scheme://host[:port]"; refuse anything that
  // doesn't round-trip through URL + origin parsing.
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
  // The owner's canonical did:pkh for TinyCloud registry lookups is eip155:1 by convention;
  // TODO(TC-3657 follow-up): respect the account's configured chainId if OpenKey ever supports it.
  return `did:pkh:eip155:1:${address}`;
}

/** Exported for tests only. Builds a limiter independent of the process-wide one. */
export const _testing = {
  createTinyCloudSetupLimiter,
  parseRequestingOrigin,
  parseTicket,
  subjectFromAddress,
};
