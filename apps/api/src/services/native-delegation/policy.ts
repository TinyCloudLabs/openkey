import type { Prisma } from '@openkey/db';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from '../tinycloud-hosts';
import {
  TINYCLOUD_DELEGATED_PATH,
  TINYCLOUD_DELEGATED_PATH_MAX_LENGTH,
  TINYCLOUD_DENIED_PATH_ROOTS,
  hasDotSegment,
} from '../tinycloud-path-policy';

const KV_ACTIONS = new Set(['get', 'put', 'list', 'del', 'metadata']);
const SQL_ACTIONS = new Set(['read', 'write', 'schema']);
const PATH_SEGMENT = /^[A-Za-z0-9._~@+=,:-]+$/;
const APP_ID = /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/;
const DNS_NAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);
const MAX_LIST_ENTRIES = 32;
export const DEFAULT_MAX_DELEGATION_TTL_SECONDS = 3600;
export const DEFAULT_GRANT_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

/**
 * Admin-approved ceiling for a native client's TinyCloud delegations. It is
 * stored on `OauthClient.tinycloudNativeDelegation` and only ever written
 * through `validateNativeDelegationConfig`.
 */
export interface NativeDelegationConfig {
  version: 1;
  appId: string;
  tinycloudHost: string;
  kv: { paths: string[]; actions: string[] };
  sql: { databases: string[]; actions: string[] } | null;
  maxDelegationTtlSeconds: number;
  grantLifetimeSeconds: number;
  siweDomain?: string;
}

/** The JSON column value for a validated ceiling; shared by every writer. */
export function nativeDelegationJson(config: NativeDelegationConfig): Prisma.InputJsonObject {
  return config as unknown as Prisma.InputJsonObject;
}

export interface NativeDelegationClient {
  type: string | null;
  public: boolean;
  tokenEndpointAuthMethod: string | null;
  disabled?: boolean;
}

export interface NativeDelegationPolicyOptions {
  /** Accept loopback TinyCloud hosts; never in production. */
  allowLocalHosts?: boolean;
}

export class NativeDelegationPolicyError extends Error {}

function reject(message: string): never {
  throw new NativeDelegationPolicyError(message);
}

function object(value: unknown, label: string, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject(`${label} must be an object`);
  const entry = value as Record<string, unknown>;
  if (Object.keys(entry).some((key) => !allowed.includes(key))) reject(`${label} contains an unknown field`);
  return entry;
}

function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_LIST_ENTRIES ||
      value.some((part) => typeof part !== 'string') || new Set(value).size !== value.length) {
    reject(`${label} must be a non-empty list of unique strings`);
  }
  return [...value] as string[];
}

function actions(value: unknown, label: string, allowed: ReadonlySet<string>): string[] {
  const list = strings(value, label);
  if (list.some((part) => !allowed.has(part))) reject(`${label} contains an unsupported action`);
  return list;
}

function seconds(value: unknown, label: string, min: number, max: number, fallback: number): number {
  const resolved = value === undefined ? fallback : value;
  if (typeof resolved !== 'number' || !Number.isInteger(resolved) || resolved < min || resolved > max) {
    reject(`${label} must be an integer between ${min} and ${max} seconds`);
  }
  return resolved;
}

function localHostsAllowed(): boolean {
  return process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';
}

function trustedHost(value: unknown, allowLocalHosts: boolean): string {
  if (typeof value !== 'string') reject('tinycloudHost is required');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    reject('tinycloudHost is not trusted');
  }
  if (url.origin !== value) reject('tinycloudHost must be an origin without a path or trailing slash');
  if (TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(value)) return value;
  if (allowLocalHosts && LOCAL_HOSTNAMES.has(url.hostname)) return value;
  reject('tinycloudHost is not trusted');
}

function kvPath(path: string, appId: string): boolean {
  return path.startsWith(`${appId}/`) &&
    path.length <= TINYCLOUD_DELEGATED_PATH_MAX_LENGTH &&
    TINYCLOUD_DELEGATED_PATH.test(path) &&
    !hasDotSegment(path);
}

function sqlDatabase(path: string, appId: string): boolean {
  if (!path.startsWith(`${appId}/`)) return false;
  const name = path.slice(appId.length + 1);
  return PATH_SEGMENT.test(name) && name !== '.' && name !== '..';
}

/**
 * The only way a delegation ceiling is accepted. Enablement is limited to
 * enabled native public clients without a secret, and KV paths and SQL
 * databases stay in the client's own namespace. SQL ceilings validate under
 * the same rules as KV; isolating SQL databases by full path is the
 * TinyCloud node's job, same as it is for KV.
 */
export function validateNativeDelegationConfig(
  input: unknown,
  client: NativeDelegationClient,
  options: NativeDelegationPolicyOptions = {},
): NativeDelegationConfig {
  const allowLocalHosts = options.allowLocalHosts ?? localHostsAllowed();
  if (client.type !== 'native' || client.public !== true || client.tokenEndpointAuthMethod !== 'none') {
    reject('TinyCloud delegation requires a native public client with none token authentication');
  }
  if (client.disabled === true) reject('TinyCloud delegation cannot be enabled on a disabled client');
  const value = object(input, 'tinycloudNativeDelegation', [
    'version', 'appId', 'tinycloudHost', 'kv', 'sql', 'maxDelegationTtlSeconds', 'grantLifetimeSeconds', 'siweDomain',
  ]);
  if (value.version !== 1) reject('tinycloudNativeDelegation.version must be 1');
  if (typeof value.appId !== 'string' || value.appId.length > 128 || !APP_ID.test(value.appId) ||
      Object.hasOwn(TINYCLOUD_DENIED_PATH_ROOTS, value.appId.toLowerCase())) {
    reject('tinycloudNativeDelegation.appId is invalid');
  }
  const appId = value.appId;
  const host = trustedHost(value.tinycloudHost, allowLocalHosts);

  const kv = object(value.kv, 'kv', ['paths', 'actions']);
  const paths = strings(kv.paths, 'kv.paths');
  if (paths.some((path) => !kvPath(path, appId))) reject('kv.paths must be relative paths under the appId');
  const parsedKv = { paths, actions: actions(kv.actions, 'kv.actions', KV_ACTIONS) };

  let parsedSql: NativeDelegationConfig['sql'] = null;
  if (value.sql !== null && value.sql !== undefined) {
    const sql = object(value.sql, 'sql', ['databases', 'actions']);
    const databases = strings(sql.databases, 'sql.databases');
    if (databases.some((path) => !sqlDatabase(path, appId))) {
      reject('sql.databases must name exact databases under the appId');
    }
    parsedSql = { databases, actions: actions(sql.actions, 'sql.actions', SQL_ACTIONS) };
  }
  const maxDelegationTtlSeconds = seconds(
    value.maxDelegationTtlSeconds, 'maxDelegationTtlSeconds', 300, 86400, DEFAULT_MAX_DELEGATION_TTL_SECONDS,
  );
  const grantLifetimeSeconds = seconds(
    value.grantLifetimeSeconds, 'grantLifetimeSeconds', 300, DEFAULT_GRANT_LIFETIME_SECONDS, DEFAULT_GRANT_LIFETIME_SECONDS,
  );
  if (value.siweDomain !== undefined && (typeof value.siweDomain !== 'string' || !DNS_NAME.test(value.siweDomain))) {
    reject('siweDomain is invalid');
  }
  return {
    version: 1, appId, tinycloudHost: host, kv: parsedKv, sql: parsedSql,
    maxDelegationTtlSeconds, grantLifetimeSeconds,
    ...(value.siweDomain === undefined ? {} : { siweDomain: value.siweDomain as string }),
  };
}

/**
 * Runtime gate for PAR and renewal: the client's stored ceiling re-validated
 * against the current policy. A malformed row disables delegation.
 */
export function enabledNativeDelegation(client: NativeDelegationClient & {
  scopes: string[];
  disabled: boolean;
  tinycloudNativeDelegation: unknown;
}): NativeDelegationConfig | null {
  if (client.disabled || !client.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) || client.tinycloudNativeDelegation == null) {
    return null;
  }
  try {
    return validateNativeDelegationConfig(client.tinycloudNativeDelegation, client);
  } catch (error) {
    if (error instanceof NativeDelegationPolicyError) return null;
    throw error;
  }
}

/**
 * Whether provider endpoints must treat a client as a delegation client. This
 * is deliberately broader than `enabledNativeDelegation`: a stale scope or a
 * ceiling that no longer validates still marks the client, so the provider's
 * refresh and revoke paths stay closed for it.
 */
export function isNativeDelegationClient(client: { scopes: string[]; tinycloudNativeDelegation: unknown }): boolean {
  return client.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) || client.tinycloudNativeDelegation != null;
}
