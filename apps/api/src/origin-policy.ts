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
 * Managed-key signing excludes the configured console origin unless it is
 * also an account/default origin. CORS and Better Auth keep using the broader
 * shared policy.
 */
export function resolveSigningOriginPolicy(
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): string[] {
  const consoleOrigin = resolveConsoleOrigin(env);
  let normalizedConsoleOrigin: string | undefined;

  if (consoleOrigin) {
    try {
      normalizedConsoleOrigin = new URL(consoleOrigin.trim()).origin;
      if (normalizedConsoleOrigin === 'null') throw new Error();
    } catch {
      throw new TypeError('CONSOLE_ORIGIN must be a valid absolute URL');
    }
  }

  const accountOrigins = new Set(
    defaultOrigin.split(',').map((origin) => {
      try {
        return new URL(origin.trim()).origin;
      } catch {
        return undefined;
      }
    }).filter((origin): origin is string => origin !== undefined),
  );
  const origins = resolveOriginPolicy(defaultOrigin, env);
  const filtered = origins.flatMap((origin) => {
    try {
      const normalizedOrigin = new URL(origin.trim()).origin;
      if (normalizedOrigin === 'null') return [origin];
      if (
        normalizedOrigin === normalizedConsoleOrigin
        && !accountOrigins.has(normalizedOrigin)
      ) return [];
      return [normalizedOrigin];
    } catch {
      return [origin];
    }
  });

  // If the console was the only configured origin, keep it rather than
  // accidentally denying every signing request.
  return filtered.length > 0 || origins.length === 0 ? filtered : [origins[0]!];
}
