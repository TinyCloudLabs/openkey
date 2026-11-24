import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, getSessionFromCtx } from 'better-auth/api';
import { makeSignature } from 'better-auth/crypto';

/** A session token in the signed form the bearer plugin's `set-auth-token` header carries. */
export async function signedSessionToken(token: string, secret: string): Promise<string> {
  return `${token}.${await makeSignature(token, secret)}`;
}

/**
 * `GET /session-token` returns the current cookie session's token in its signed form, for OpenKey's
 * own pages to hand to its embedded widget after a sign-in whose response they could not read (a
 * Google or Apple redirect). Cookie sessions only: a request carrying a bearer is refused.
 */
export function sessionTokenPlugin() {
  return {
    id: 'openkey-session-token',
    endpoints: {
      sessionToken: createAuthEndpoint('/session-token', { method: 'GET', requireHeaders: true }, async (ctx) => {
        if (ctx.headers?.get('authorization')) {
          throw new APIError('FORBIDDEN', { message: 'The session token is available to cookie sessions only' });
        }
        const session = await getSessionFromCtx(ctx, { disableRefresh: true });
        if (!session) throw new APIError('UNAUTHORIZED');
        ctx.setHeader('Cache-Control', 'no-store');
        return ctx.json({ token: await signedSessionToken(session.session.token, ctx.context.secret) });
      }),
    },
  } satisfies BetterAuthPlugin;
}
