export type OriginPolicyEnvironment = Record<string, string | undefined>;

export const DEFAULT_CONSOLE_ORIGIN = 'https://console.openkey.so';

// Response headers the browser may read on credentialed cross-origin requests.
// `Date` is the server clock the delegate page uses to start the code countdown.
export const API_EXPOSED_HEADERS = ['set-auth-token', 'Date'];

function isProduction(env: OriginPolicyEnvironment): boolean {
  return env.NODE_ENV === 'production' || env.TEE_MODE === 'production';
}

export function resolveConsoleOrigin(
  env: OriginPolicyEnvironment = process.env,
): string | undefined {
  return env.CONSOLE_ORIGIN
    || (isProduction(env) ? DEFAULT_CONSOLE_ORIGIN : undefined);
}

/**
 * Resolves the browser origins shared by credentialed API CORS and Better Auth.
 * Explicit origins remain authoritative; the production console host is only a
 * fallback for the sealed environment that predates CONSOLE_ORIGIN.
 */
export function resolveOriginPolicy(
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): string[] {
  const origins = (env.CORS_ORIGIN || defaultOrigin)
    .split(',')
    .map((origin) => origin.trim());
  const consoleOrigin = resolveConsoleOrigin(env);

  if (consoleOrigin) origins.push(consoleOrigin);
  return [...new Set(origins)];
}

export function corsOriginPolicy(
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): string | string[] {
  const origins = resolveOriginPolicy(defaultOrigin, env);
  return origins.length === 1 ? origins[0]! : origins;
}

/**
 * Managed-key signing accepts only the account-facing web origins. The
 * console host keeps credentialed CORS and Better Auth for its own routes,
 * but its pages never call a signing route, so it drops out of this policy
 * no matter which source (CORS_ORIGIN, CONSOLE_ORIGIN, or the production
 * default) contributed it.
 */
export function resolveSigningOriginPolicy(
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): string[] {
  const consoleOrigin = resolveConsoleOrigin(env)?.toLowerCase().replace(/\/+$/, '');
  return resolveOriginPolicy(defaultOrigin, env).filter(
    (origin) => origin.toLowerCase().replace(/\/+$/, '') !== consoleOrigin,
  );
}
