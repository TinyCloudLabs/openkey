import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { LOCAL_HOSTNAMES, TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS, localHostsAllowed } from '../tinycloud-hosts';
import {
  TINYCLOUD_DELEGATED_PATH,
  TINYCLOUD_DELEGATED_PATH_MAX_LENGTH,
  TINYCLOUD_DENIED_PATH_ROOTS,
  hasDotSegment,
} from '../tinycloud-path-policy';

const KV_ACTIONS = new Set(['get', 'put', 'list', 'del', 'metadata']);
const SQL_ACTIONS = new Set(['read', 'write', 'schema']);
const HOOK_ACTIONS = new Set(['subscribe']);
const PATH_SEGMENT = /^[A-Za-z0-9._~@+=,:-]+$/;
const APP_ID = /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/;
const DNS_NAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const MAX_LIST_ENTRIES = 32;
export const DEFAULT_MAX_DELEGATION_TTL_SECONDS = 3600;
export const DEFAULT_GRANT_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

const STEP_UP_SPACES = ['public', 'account', 'agents', 'applications'] as const;
const STEP_UP_KV_ACTIONS = new Set(['get', 'list', 'metadata']);
const STEP_UP_SQL_ACTIONS = new Set(['read', 'schema']);
// A step-up never addresses the secrets roots; `variables` joins the shared denied roots.
const STEP_UP_DENIED_ROOTS = new Set([...Object.keys(TINYCLOUD_DENIED_PATH_ROOTS), 'variables']);
const MAX_STEP_UP_APPS = 16;

export type NativeStepUpSpace = (typeof STEP_UP_SPACES)[number];
export interface NativeStepUpSpaceCeiling {
  kv?: { paths: string[]; actions: string[] };
  sql?: { databases: string[]; actions: string[] };
}
export type NativeStepUpCeilings = Record<string, Partial<Record<NativeStepUpSpace, NativeStepUpSpaceCeiling>>>;

/**
 * Admin-approved ceiling for a native client's TinyCloud delegations. It is
 * stored on `OauthClient.tinycloudNativeDelegation` and only ever written
 * through `validateNativeDelegationConfig`.
 */
export interface NativeDelegationConfig {
  version: 1;
  appId: string;
  tinycloudHost: string;
  /** `root: true` also admits the whole applications-space KV (path `""`), as the web Home grant does. */
  kv: { paths: string[]; actions: string[]; root?: true };
  /**
   * `databases`: exact databases under the appId. `prefixes`: `<appId>/<name>/`
   * database prefixes. `foreignDatabases`: exact `<otherAppId>/<name>` databases,
   * each named explicitly.
   */
  sql: { databases: string[]; actions: string[]; prefixes?: string[]; foreignDatabases?: string[] } | null;
  /** Hook subscriptions, only on `sql/<database or prefix>` paths the SQL ceiling already holds. */
  hooks?: { paths: string[]; actions: string[] };
  maxDelegationTtlSeconds: number;
  grantLifetimeSeconds: number;
  siweDomain?: string;
  /**
   * Step-up ceilings by framed-app id (TC-3569). Read-only entries in spaces
   * beyond the sign-in grant's own; see `validateStepUps`.
   */
  stepUps?: NativeStepUpCeilings;
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

/** An exact database in another app's folder: `<otherAppId>/<name>`, never a secrets root or this app's own. */
function foreignSqlDatabase(path: string, appId: string): boolean {
  const slash = path.indexOf('/');
  if (slash <= 0) return false;
  const owner = path.slice(0, slash);
  return owner !== appId && owner.length <= 128 && APP_ID.test(owner) &&
    !Object.hasOwn(TINYCLOUD_DENIED_PATH_ROOTS, owner.toLowerCase()) && sqlDatabase(path, owner);
}

function stepUpRootAllowed(path: string): boolean {
  const root = path.split('/', 1)[0]!.toLowerCase();
  return !STEP_UP_DENIED_ROOTS.has(root);
}

/** `""` (the whole space) is admitted only in the public space; every other path is relative, dot-free and outside the secrets roots. */
function stepUpKvPath(path: string, space: NativeStepUpSpace): boolean {
  if (path === '') return space === 'public';
  return path.length <= TINYCLOUD_DELEGATED_PATH_MAX_LENGTH && TINYCLOUD_DELEGATED_PATH.test(path) &&
    !hasDotSegment(path) && stepUpRootAllowed(path);
}

/** An exact database: one segment, or `<folder>/<name>`; never a prefix or a secrets root. */
function stepUpSqlDatabase(path: string): boolean {
  const segments = path.split('/');
  return segments.length >= 1 && segments.length <= 2 &&
    segments.every((segment) => PATH_SEGMENT.test(segment) && segment !== '.' && segment !== '..') &&
    stepUpRootAllowed(path);
}

/**
 * Step-up ceilings (TC-3569): per framed app, what the owner may add on top of
 * the sign-in grant, by space. Read-only by construction: a write action, a
 * secrets-space or encryption entry, or a `get` on the secrets roots is
 * refused here and can never be stored. Nothing reads these until the step-up
 * endpoint ships.
 */
function validateStepUps(input: unknown): NativeStepUpCeilings {
  if (!input || typeof input !== 'object' || Array.isArray(input)) reject('stepUps must be an object');
  const apps = Object.keys(input);
  if (apps.length === 0 || apps.length > MAX_STEP_UP_APPS) reject(`stepUps must name 1 to ${MAX_STEP_UP_APPS} apps`);
  const parsed: NativeStepUpCeilings = {};
  for (const stepUpAppId of apps) {
    if (stepUpAppId.length > 128 || !APP_ID.test(stepUpAppId) ||
        Object.hasOwn(TINYCLOUD_DENIED_PATH_ROOTS, stepUpAppId.toLowerCase())) {
      reject('stepUps app id is invalid');
    }
    const spaces = object((input as Record<string, unknown>)[stepUpAppId], `stepUps.${stepUpAppId}`, STEP_UP_SPACES);
    if (Object.keys(spaces).length === 0) reject(`stepUps.${stepUpAppId} must name at least one space`);
    const parsedSpaces: Partial<Record<NativeStepUpSpace, NativeStepUpSpaceCeiling>> = {};
    for (const space of STEP_UP_SPACES) {
      if (spaces[space] === undefined) continue;
      const label = `stepUps.${stepUpAppId}.${space}`;
      const entry = object(spaces[space], label, ['kv', 'sql']);
      if (entry.kv === undefined && entry.sql === undefined) reject(`${label} must hold kv or sql`);
      const parsedSpace: NativeStepUpSpaceCeiling = {};
      if (entry.kv !== undefined) {
        const kv = object(entry.kv, `${label}.kv`, ['paths', 'actions']);
        const paths = strings(kv.paths, `${label}.kv.paths`);
        if (paths.some((path) => !stepUpKvPath(path, space))) {
          reject(`${label}.kv.paths must be relative paths outside the secrets roots; "" is only for the public space`);
        }
        parsedSpace.kv = { paths, actions: actions(kv.actions, `${label}.kv.actions`, STEP_UP_KV_ACTIONS) };
      }
      if (entry.sql !== undefined) {
        const sql = object(entry.sql, `${label}.sql`, ['databases', 'actions']);
        const databases = strings(sql.databases, `${label}.sql.databases`);
        if (databases.some((database) => !stepUpSqlDatabase(database))) {
          reject(`${label}.sql.databases must name exact databases outside the secrets roots`);
        }
        parsedSpace.sql = { databases, actions: actions(sql.actions, `${label}.sql.actions`, STEP_UP_SQL_ACTIONS) };
      }
      parsedSpaces[space] = parsedSpace;
    }
    parsed[stepUpAppId] = parsedSpaces;
  }
  return parsed;
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
    'version', 'appId', 'tinycloudHost', 'kv', 'sql', 'hooks', 'maxDelegationTtlSeconds', 'grantLifetimeSeconds', 'siweDomain', 'stepUps',
  ]);
  if (value.version !== 1) reject('tinycloudNativeDelegation.version must be 1');
  if (typeof value.appId !== 'string' || value.appId.length > 128 || !APP_ID.test(value.appId) ||
      Object.hasOwn(TINYCLOUD_DENIED_PATH_ROOTS, value.appId.toLowerCase())) {
    reject('tinycloudNativeDelegation.appId is invalid');
  }
  const appId = value.appId;
  const host = trustedHost(value.tinycloudHost, allowLocalHosts);
  const kv = object(value.kv, 'kv', ['paths', 'actions', 'root']);
  const paths = strings(kv.paths, 'kv.paths');
  if (paths.some((path) => !kvPath(path, appId))) reject('kv.paths must be relative paths under the appId');
  if (kv.root !== undefined && kv.root !== true) reject('kv.root must be true when present');
  const parsedKv: NativeDelegationConfig['kv'] = {
    paths, actions: actions(kv.actions, 'kv.actions', KV_ACTIONS), ...(kv.root === true ? { root: true as const } : {}),
  };

  let parsedSql: NativeDelegationConfig['sql'] = null;
  if (value.sql !== null && value.sql !== undefined) {
    const sql = object(value.sql, 'sql', ['databases', 'actions', 'prefixes', 'foreignDatabases']);
    const databases = strings(sql.databases, 'sql.databases');
    if (databases.some((path) => !sqlDatabase(path, appId))) {
      reject('sql.databases must name exact databases under the appId');
    }
    const prefixes = sql.prefixes === undefined ? undefined : strings(sql.prefixes, 'sql.prefixes');
    if (prefixes?.some((path) => !path.endsWith('/') || !sqlDatabase(path.slice(0, -1), appId))) {
      reject('sql.prefixes must be <appId>/<name>/ database prefixes');
    }
    const foreignDatabases = sql.foreignDatabases === undefined ? undefined : strings(sql.foreignDatabases, 'sql.foreignDatabases');
    if (foreignDatabases?.some((path) => !foreignSqlDatabase(path, appId))) {
      reject('sql.foreignDatabases must name exact databases in another app folder');
    }
    parsedSql = {
      databases, actions: actions(sql.actions, 'sql.actions', SQL_ACTIONS),
      ...(prefixes ? { prefixes } : {}), ...(foreignDatabases ? { foreignDatabases } : {}),
    };
  }

  let parsedHooks: NativeDelegationConfig['hooks'];
  if (value.hooks !== undefined) {
    const hooks = object(value.hooks, 'hooks', ['paths', 'actions']);
    const hookPaths = strings(hooks.paths, 'hooks.paths');
    const targets = parsedSql ? [...parsedSql.databases, ...(parsedSql.prefixes ?? []), ...(parsedSql.foreignDatabases ?? [])] : [];
    if (hookPaths.some((path) => !path.startsWith('sql/') || !targets.includes(path.slice('sql/'.length)))) {
      reject('hooks.paths must be sql/<database or prefix> already in the SQL ceiling');
    }
    parsedHooks = { paths: hookPaths, actions: actions(hooks.actions, 'hooks.actions', HOOK_ACTIONS) };
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
  const parsedStepUps = value.stepUps === undefined ? undefined : validateStepUps(value.stepUps);
  return {
    version: 1, appId, tinycloudHost: host, kv: parsedKv, sql: parsedSql,
    ...(parsedHooks ? { hooks: parsedHooks } : {}),
    ...(parsedStepUps ? { stepUps: parsedStepUps } : {}),
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
