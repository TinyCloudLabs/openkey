/**
 * TC-3840: the settings that decide who can sign are written as fixed values in the measured compose
 * (docker-compose.prod.yml), not taken from the encrypted environment. compose_hash covers the compose text
 * but not encrypted env values, so a value set only in the env would change who can sign while nothing a
 * verifier sees changes.
 *
 * At boot inside the TEE the API reads the app-compose it was measured with and refuses to start unless
 * every setting below is a literal `NAME=value` entry of the `api` service and the process sees exactly
 * that value.
 */
export const MEASURED_SETTINGS = [
  'BETTER_AUTH_URL',
  'WEBAUTHN_RP_ID',
  'GOOGLE_CLIENT_ID',
  'OAUTH_DYNAMIC_CLIENT_REGISTRATION',
  'OAUTH_VALID_AUDIENCES',
  'APPLE_CLIENT_ID',
  'APPLE_TEAM_ID',
  'APPLE_KEY_ID',
  'APPLE_APP_BUNDLE_IDENTIFIERS',
  'APPLE_WEBHOOK_AUDIENCE',
  'OPENKEY_RENEWAL_LEASES',
  'OPENKEY_RENEWAL_NODE_DID',
  'OPENKEY_RENEWAL_RENEWER_DID',
  'OPENKEY_NATIVE_RENEW_DISABLED',
  'NODE_STATS_URL',
  'TEE_MODE',
] as const;

export type MeasuredSetting = (typeof MEASURED_SETTINGS)[number];

export type MeasuredSettingsResult =
  | { ok: true }
  | { ok: false; unreadable: true }
  | { ok: false; unreadable: false; settings: MeasuredSetting[] };

/** The `api` service's environment list from the measured app-compose JSON, or null when it has none. */
function apiEnvironment(appCompose: string): unknown[] | null {
  let compose: unknown;
  try {
    const parsed: unknown = JSON.parse(appCompose);
    if (typeof parsed !== 'object' || parsed === null || !('docker_compose_file' in parsed)) return null;
    if (typeof parsed.docker_compose_file !== 'string') return null;
    compose = Bun.YAML.parse(parsed.docker_compose_file);
  } catch {
    return null;
  }
  if (typeof compose !== 'object' || compose === null || !('services' in compose)) return null;
  const { services } = compose;
  if (typeof services !== 'object' || services === null || !('api' in services)) return null;
  const { api } = services;
  if (typeof api !== 'object' || api === null || !('environment' in api)) return null;
  return Array.isArray(api.environment) ? api.environment : null;
}

/**
 * Checks every measured setting against the app-compose this instance was measured with. A setting fails
 * when the `api` service has no entry for it, more than one, an entry that interpolates (`$`), or a value
 * other than the one in `env`. An unset variable counts as empty, as Compose passes `NAME=` through.
 */
export function checkMeasuredSettings(
  appCompose: string,
  env: Record<string, string | undefined>,
): MeasuredSettingsResult {
  const environment = apiEnvironment(appCompose);
  if (!environment) return { ok: false, unreadable: true };
  const failed = MEASURED_SETTINGS.filter((name) => {
    const entries = environment.filter((entry): entry is string => typeof entry === 'string' && entry.startsWith(`${name}=`));
    if (entries.length !== 1) return true;
    const value = entries[0]!.slice(name.length + 1);
    return value.includes('$') || value !== (env[name] ?? '');
  });
  return failed.length === 0 ? { ok: true } : { ok: false, unreadable: false, settings: failed };
}
