// Session middleware - validates better-auth session
import { createMiddleware } from 'hono/factory';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { auth } from '../auth';
import { hasAcceptedTerms, termsRequired } from '../services/terms';

export type SessionContext = {
  Variables: {
    user: {
      id: string;
      email: string;
      name?: string;
    };
    session: {
      id: string;
      userId: string;
      expiresAt: Date;
    };
    /** Set by `allowBeforeTerms`: this route is a way out, so the Terms gate lets it through. */
    leaving?: true;
  };
};

let prisma: PrismaClient | undefined;

function sessionMiddleware(termsGate: boolean) {
  return createMiddleware<SessionContext>(async (c, next) => {
    const session = await auth.api.getSession({
      headers: c.req.raw.headers,
    });

    if (!session) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    if (termsGate && !c.get('leaving') && !await hasAcceptedTerms(prisma ??= createPrismaClient(), session.user.id)) {
      return c.json(termsRequired(), 403);
    }

    c.set('user', session.user);
    c.set('session', session.session);

    await next();
  });
}

/**
 * A signed-in session whose account has accepted the current Terms (TC-3232); 403 `terms_required` until then.
 * A way out marked by `allowBeforeTerms` (middleware/terms.ts) skips the Terms check.
 */
export const requireSession = sessionMiddleware(true);

/** A signed-in session, whether or not the account has accepted the current Terms. Only the Terms routes use it. */
export const requireSessionBeforeTerms = sessionMiddleware(false);
