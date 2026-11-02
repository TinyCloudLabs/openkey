import { MCP_AUTHORIZE_MAX_SESSION_AGE_SECONDS } from './session-lifetime';

/**
 * A new MCP connection must not be approved on a sign-in with little life left:
 * a refresh can extend the session only up to the absolute cap after sign-in. An
 * authorize request for the MCP scope on a sign-in that is
 * `MCP_AUTHORIZE_MAX_SESSION_AGE_SECONDS` old or older is sent through the
 * provider's own login prompt first.
 *
 * The limit is inclusive: a sign-in that is exactly that old is too old, one
 * millisecond younger proceeds.
 */
export function mcpAuthorizeNeedsFreshSignIn(sessionCreatedAt: Date, now: Date): boolean {
  return sessionCreatedAt.getTime() + MCP_AUTHORIZE_MAX_SESSION_AGE_SECONDS * 1000 <= now.getTime();
}

/**
 * The `prompt` value that adds `login` to the request, or null when it cannot be
 * added. The provider validates `prompt` against a fixed list and only combines
 * `login` with `consent` (as `login consent`), so a request that names no prompt
 * gets `login`, `consent` becomes `login consent`, and one that already asks for
 * `login` is unchanged. `create` becomes `login`: it sends the user to the login
 * page too, but the provider resumes a `create` request when the user is
 * "created" (`/oauth2/continue`) on whatever session the cookie names, so it would
 * resume on the old sign-in. Any other value is not rewritten here:
 * `select_account` is the provider's to refuse, and `none` is answered with
 * `login_required` by the interceptor.
 *
 * With `login` the provider redirects to the login page with a signed copy of the
 * request and, once the user has signed in, resumes it with `login` removed, on the
 * new session.
 */
export function withLoginPrompt(prompt: string | null): string | null {
  const value = (prompt ?? '').split(' ').filter(Boolean).join(' ');
  if (value === '' || value === 'create') return 'login';
  if (value === 'consent') return 'login consent';
  if (value === 'login' || value === 'login consent') return value;
  return null;
}
