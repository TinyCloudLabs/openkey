// Registered resource servers: confidential OAuth clients that a hosted
// resource (for example the TinyCloud MCP server) uses to check the status of
// access tokens issued for it. The registration lives in the client's existing
// `metadata` JSON, so it needs no schema change.

import { createHash, timingSafeEqual } from 'node:crypto';

export const RESOURCE_SERVER_METADATA_KEY = 'tinycloudResourceServer';

/** Requests per minute a resource server may make unless its registration says otherwise. */
export const DEFAULT_RESOURCE_RATE_LIMIT_PER_MINUTE = 3000;
/** The most a registration may ask for. */
export const MAX_RESOURCE_RATE_LIMIT_PER_MINUTE = 100_000;

export interface ResourceServerPolicy {
  /** Canonical resource URLs (token `aud` values) this server may check tokens for. */
  allowedResources: string[];
  /** Requests per minute for this server; the default applies when absent. */
  rateLimitPerMinute?: number;
}

export function isValidRateLimit(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= MAX_RESOURCE_RATE_LIMIT_PER_MINUTE;
}

/** The client row fields that make a client a resource server. */
export function resourceServerMetadata(
  allowedResources: readonly string[],
  options: { rateLimitPerMinute?: number } = {},
): { [RESOURCE_SERVER_METADATA_KEY]: ResourceServerPolicy } {
  return {
    [RESOURCE_SERVER_METADATA_KEY]: {
      allowedResources: [...allowedResources],
      ...(options.rateLimitPerMinute === undefined ? {} : { rateLimitPerMinute: options.rateLimitPerMinute }),
    },
  };
}

/** The policy stored in a client's metadata, or null when the client is not a resource server. */
export function readResourceServerPolicy(metadata: unknown): ResourceServerPolicy | null {
  let value = metadata;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const entry = (value as Record<string, unknown>)[RESOURCE_SERVER_METADATA_KEY];
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return null;
  const record = entry as Record<string, unknown>;
  const allowed = record.allowedResources;
  if (!Array.isArray(allowed) || allowed.length === 0) return null;
  if (!allowed.every((resource) => typeof resource === 'string' && resource.length > 0)) return null;
  if (record.rateLimitPerMinute !== undefined && !isValidRateLimit(record.rateLimitPerMinute)) return null;
  return {
    allowedResources: [...new Set(allowed as string[])],
    ...(record.rateLimitPerMinute === undefined ? {} : { rateLimitPerMinute: record.rateLimitPerMinute as number }),
  };
}

/**
 * A resource URL as it appears in a token's `aud`: absolute https, no
 * credentials, query or fragment, and written exactly as `URL` normalises it
 * (so `https://host` must be `https://host/`).
 */
export function isCanonicalResourceUrl(value: string): boolean {
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  return url.protocol === 'https:' && url.hostname !== '' && !url.username && !url.password &&
    !url.search && !url.hash && url.href === value;
}

/** Validates a registration's allowed resources; returns the problems (empty when valid). */
export function validateAllowedResources(resources: readonly string[], validAudiences: readonly string[]): string[] {
  const problems: string[] = [];
  if (resources.length === 0) problems.push('at least one allowed resource is required');
  for (const resource of resources) {
    if (!isCanonicalResourceUrl(resource)) problems.push(`${resource} is not a canonical https resource URL`);
    else if (!validAudiences.includes(resource)) {
      problems.push(`${resource} is not an audience this server issues tokens for; add it to OAUTH_VALID_AUDIENCES (the API's setting, and the workflow's valid_audiences input) or register it once the API lists it`);
    }
  }
  return problems;
}

/** The stored form of a client secret (`storeClientSecret: 'hashed'`): base64url SHA-256. */
export function hashClientSecret(secret: string): string {
  return createHash('sha256').update(secret, 'utf8').digest('base64url');
}

/** Constant-time check of a presented secret against its stored hash. */
export function clientSecretMatches(presented: string, storedHash: string | null | undefined): boolean {
  const presentedHash = Buffer.from(hashClientSecret(presented));
  // Always compare equal-length buffers, so an unknown client costs the same as a wrong secret.
  const stored = Buffer.from(typeof storedHash === 'string' && storedHash.length === presentedHash.length
    ? storedHash
    : 'x'.repeat(presentedHash.length));
  const equal = timingSafeEqual(presentedHash, stored);
  return equal && typeof storedHash === 'string' && storedHash.length === presentedHash.length;
}
