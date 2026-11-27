import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import { requireSessionBeforeTerms, type SessionContext } from '../middleware/session';
import { recordTermsAcceptance, termsRelease, termsStatus, type EmbedAcceptanceAudit } from '../services/terms';

/** A session token stands in for a person only while its sign-in is this recent. */
export const EMBED_ACCEPTANCE_SIGN_IN_MAX_AGE_MS = 10 * 60 * 1000;
const MAX_CLAIMED_ORIGIN_LENGTH = 2048;

/**
 * TC-3232: the required Terms screen's two calls. Mounted ahead of the account router, whose session check
 * refuses an account that has not accepted; these routes are what it accepts with.
 *
 * The browser (cookie session) records 'web' or 'native:<clientId>'. The embedded OpenKey frame holds only a
 * session token (Bearer, accepted from the OpenKey origin alone); it records 'embed', and only when that
 * session came from a sign-in in the last 10 minutes, so a person signed in just before agreeing. An older
 * session, or a reviewer session, answers `terms_step_up`: the frame signs in again and agrees.
 */
export function createAccountTermsRouter(database: PrismaClient) {
  const router = new Hono<SessionContext>();
  router.use('*', requireAccountOriginForBearer);
  router.use('*', requireSessionBeforeTerms);

  router.get('/', async (c) => {
    c.header('Cache-Control', 'no-store');
    return c.json(await termsStatus(database, c.get('user').id, termsRelease()));
  });

  // Only the version the screen showed, and only while it is current, is recorded.
  router.post('/accept', async (c) => {
    const bearer = c.req.header('authorization') !== undefined;
    const body = await c.req.json().catch(() => null) as {
      version?: unknown; surface?: unknown; clientId?: unknown; embedOrigin?: unknown;
    } | null;
    // The frame's surface is the server's to set: a token request carries no surface or client of its own.
    if (bearer && (body?.surface !== undefined || body?.clientId !== undefined)) {
      return c.json({ error: 'invalid_request' }, 400);
    }
    const release = termsRelease();
    if (!release || body?.version !== release.version) {
      return c.json({ error: 'terms_version_mismatch', version: release?.version ?? null }, 409);
    }
    if (bearer) {
      const audit = await embedAcceptanceAudit(database, c.get('session').id, c.req.header('origin'), body.embedOrigin);
      if (!audit) return c.json({ error: 'terms_step_up' }, 403);
      await recordTermsAcceptance(database, c.get('user').id, release, 'embed', audit);
      return c.json({ accepted: true, version: release.version });
    }
    let surface = 'web';
    if (body.surface === 'native') {
      const client = typeof body.clientId === 'string'
        ? await database.oauthClient.findUnique({ where: { clientId: body.clientId }, select: { clientId: true } })
        : null;
      if (!client) return c.json({ error: 'invalid_request' }, 400);
      surface = `native:${client.clientId}`;
    } else if (body.surface !== undefined && body.surface !== 'web') {
      return c.json({ error: 'invalid_request' }, 400);
    }
    await recordTermsAcceptance(database, c.get('user').id, release, surface);
    return c.json({ accepted: true, version: release.version });
  });

  return router;
}

/**
 * The proof that a person is present behind a session token: the session itself was created by a sign-in
 * within the last 10 minutes. Refresh never moves `createdAt`. Reviewer sessions sign in with a shared code
 * and never count.
 */
async function embedAcceptanceAudit(
  database: PrismaClient,
  sessionId: string,
  requestOrigin: string | undefined,
  claimedOrigin: unknown,
): Promise<EmbedAcceptanceAudit | null> {
  const session = await database.session.findUnique({
    where: { id: sessionId },
    select: { createdAt: true, reviewerEpoch: true },
  });
  if (!session || session.reviewerEpoch !== null) return null;
  if (session.createdAt.getTime() < Date.now() - EMBED_ACCEPTANCE_SIGN_IN_MAX_AGE_MS) return null;
  return {
    sessionId,
    proof: 'session_created',
    proofAt: session.createdAt,
    requestOrigin: requestOrigin ?? null,
    embedOriginClaimed: claimedEmbedOrigin(claimedOrigin),
  };
}

/** The embedding page's origin as the frame reports it: unverifiable, so kept only as a well-formed origin. */
function claimedEmbedOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > MAX_CLAIMED_ORIGIN_LENGTH) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : null;
  } catch {
    return null;
  }
}
