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
 * Filters a resolved origin list for signing. Malformed allowlist entries are
 * preserved unchanged; malformed console origins fail closed.
 */
export function filterSigningOrigins(
  allowlist: string[],
  accountOrigins: string[],
  consoleOrigin: string | undefined,
): string[] {
  let normalizedConsoleOrigin: string | undefined;
  if (consoleOrigin !== undefined) {
    try {
      normalizedConsoleOrigin = new URL(consoleOrigin.trim()).origin;
      if (normalizedConsoleOrigin === 'null') throw new Error();
    } catch {
      throw new TypeError('CONSOLE_ORIGIN must be a valid absolute URL');
    }
  }

  const normalizedAccountOrigins = new Set<string>();
  for (const origin of accountOrigins) {
    try {
      const normalized = new URL(origin.trim()).origin;
      if (normalized !== 'null') normalizedAccountOrigins.add(normalized);
    } catch {
      // An invalid account-origin value cannot preserve an allowlist entry.
    }
  }

  return allowlist.flatMap((origin) => {
    if (origin.trim() === 'null') return [];
    try {
      const normalized = new URL(origin.trim()).origin;
      if (normalized === 'null') return [];
      if (
        normalized === normalizedConsoleOrigin
        && !normalizedAccountOrigins.has(normalized)
      ) return [];
      return [normalized];
    } catch {
      return [origin];
    }
  });
}

/**
 * Resolves account-facing browser origins without inheriting CORS-only origins.
 * The console is accepted only when it is itself the account origin.
 */
export function resolveAccountOriginPolicy(
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): string[] {
  const accountOrigins = env.WEBAUTHN_ORIGIN ? [env.WEBAUTHN_ORIGIN] : [];
  if (!isProduction(env)) {
    accountOrigins.push(...defaultOrigin.split(',').map((origin) => origin.trim()));
  }
  return [...new Set(accountOrigins.flatMap((origin) => {
    try {
      const canonical = new URL(origin.trim()).origin;
      return canonical === 'null' ? [] : [canonical];
    } catch {
      return [];
    }
  }))];
}


export function isAccountOriginAllowed(
  origin: string | undefined,
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): boolean {
  if (!origin) return false;
  try {
    const canonical = new URL(origin).origin;
    return canonical !== 'null' && resolveAccountOriginPolicy(defaultOrigin, env).includes(canonical);
  } catch {
    return false;
  }
}
/**
 * Managed-key signing excludes the configured console origin unless it is
 * also an account origin. CORS and Better Auth keep using the broader policy.
 */
export function resolveSigningOriginPolicy(
  defaultOrigin: string,
  env: OriginPolicyEnvironment = process.env,
): string[] {
  const accountOrigins = env.WEBAUTHN_ORIGIN ? [env.WEBAUTHN_ORIGIN] : [];
  if (!isProduction(env)) {
    accountOrigins.push(...defaultOrigin.split(',').map((origin) => origin.trim()));
  }
  return filterSigningOrigins(
    resolveOriginPolicy(defaultOrigin, env),
    accountOrigins,
    resolveConsoleOrigin(env),
  );
}
