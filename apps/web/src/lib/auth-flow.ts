const OAUTH_AUTHORIZE_KEYS = new Set([
  'client_id',
  'redirect_uri',
  'response_type',
  'scope',
  'state',
  'code_challenge',
  'code_challenge_method',
  'nonce',
  'resource',
  'login_hint',
  'max_age',
  'ui_locales',
  'claims',
]);

const SAFE_RETURN_PREFIXES = [
  '/console',
  '/dashboard',
  '/delegate',
  '/oauth/',
  '/widget/',
];

export function normalizeAuthReturnTo(
  value: string | null | undefined,
  origin: string,
  allowedPrefixes: readonly string[] = SAFE_RETURN_PREFIXES,
): string | null {
  if (!value) return null;

  try {
    const url = new URL(value, origin);
    if (url.origin !== origin || url.username || url.password) return null;
    const allowed = allowedPrefixes.some((prefix) =>
      prefix.endsWith('/')
        ? url.pathname.startsWith(prefix)
        : url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)
    );
    return allowed ? `${url.pathname}${url.search}${url.hash}` : null;
  } catch {
    return null;
  }
}

export function safeOAuthAuthorizeQuery(searchParams: URLSearchParams): string | undefined {
  const nestedQuery = searchParams.get('oauth_query');
  const source = nestedQuery ? new URLSearchParams(nestedQuery) : searchParams;
  if (!source.get('client_id')) return undefined;

  const safe = new URLSearchParams();
  for (const [key, value] of source) {
    if (OAUTH_AUTHORIZE_KEYS.has(key)) safe.append(key, value);
  }
  return safe.get('client_id') ? safe.toString() : undefined;
}
