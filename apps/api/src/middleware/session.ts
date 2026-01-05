// Session middleware - validates better-auth session
import { createMiddleware } from 'hono/factory';
import { auth } from '../auth';

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
  };
};

export const requireSession = createMiddleware<SessionContext>(async (c, next) => {
  const session = await auth.api.getSession({
    headers: c.req.raw.headers,
  });

  if (!session) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  c.set('user', session.user);
  c.set('session', session.session);

  await next();
});
