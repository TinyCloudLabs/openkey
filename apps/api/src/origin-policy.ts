export type OriginPolicyEnvironment = Record<string, string | undefined>;

export const DEFAULT_CONSOLE_ORIGIN = 'https://console.openkey.so';

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
