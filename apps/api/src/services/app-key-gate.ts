// Admission of encryption key grants under `apps/` at the sign-in prepare step.
//
// A grant is admitted when the request comes from the app's own https site,
// the app id belongs to that site's host, the site's manifest (fetched from
// that origin and matched to the declared digest) declares the key or prefix
// and the abilities, and the grant names the signer's own `default` network.
// Nothing is looked up here: every input is a value the caller already holds.

import type { AdmittedAppKey, AppKeyRefusal } from './app-key-refusal';
import { appIdValid, isKeyPath, parseKeyResource, prefixCovers } from './key-resource';

/** The abilities a manifest may declare and a grant may carry, as written in the manifest. */
const MANIFEST_ABILITIES = ['key.create', 'decrypt', 'key.block', 'key.unblock'] as const;
const MAX_DECLARATIONS = 32;

export type ManifestKeyDeclaration =
  | { path: string; abilities: readonly string[] }
  | { prefix: string; abilities: readonly string[] };

/** `absent` = no `keys` field. `invalid` = the whole block is ignored. */
export type ManifestKeys =
  | { status: 'absent' }
  | { status: 'invalid' }
  | { status: 'valid'; declarations: readonly ManifestKeyDeclaration[] };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validAbilities(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const seen: string[] = [];
  for (const ability of value) {
    if (typeof ability !== 'string' || !(MANIFEST_ABILITIES as readonly string[]).includes(ability)) return null;
    if (seen.includes(ability)) return null;
    seen.push(ability);
  }
  return seen;
}

/**
 * The manifest `keys` block (`app_id` is the manifest's own field). An empty
 * array declares nothing and is valid. Any other problem makes the whole
 * block invalid.
 */
export function parseManifestKeys(appId: unknown, keys: unknown): ManifestKeys {
  if (keys === undefined) return { status: 'absent' };
  if (!Array.isArray(keys)) return { status: 'invalid' };
  if (keys.length === 0) return { status: 'valid', declarations: [] };
  if (keys.length > MAX_DECLARATIONS) return { status: 'invalid' };
  if (typeof appId !== 'string' || !appIdValid(appId)) return { status: 'invalid' };
  const declarations: ManifestKeyDeclaration[] = [];
  const paths = new Set<string>();
  let prefixSeen = false;
  for (const entry of keys) {
    if (!isPlainObject(entry)) return { status: 'invalid' };
    const fields = Object.keys(entry);
    const abilities = validAbilities(entry.abilities);
    if (!abilities || fields.some((field) => field !== 'path' && field !== 'prefix' && field !== 'abilities')) {
      return { status: 'invalid' };
    }
    const hasPath = Object.hasOwn(entry, 'path');
    const hasPrefix = Object.hasOwn(entry, 'prefix');
    if (hasPath === hasPrefix) return { status: 'invalid' };
    if (hasPath) {
      const path = entry.path;
      if (typeof path !== 'string' || paths.has(path)) return { status: 'invalid' };
      const segments = path.split('/');
      if (!isKeyPath(path) || segments[0] !== 'apps' || segments[1] !== appId) return { status: 'invalid' };
      paths.add(path);
      declarations.push({ path, abilities });
    } else {
      if (entry.prefix !== `apps/${appId}/` || prefixSeen) return { status: 'invalid' };
      prefixSeen = true;
      declarations.push({ prefix: entry.prefix, abilities });
    }
  }
  return { status: 'valid', declarations };
}

// One to 63 characters, no leading or trailing hyphen.
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^\d+\.\d+\.\d+\.\d+$/;

/**
 * The host of an https origin, reversed label by label (`listen.tinycloud.xyz`
 * is `xyz.tinycloud.listen`), or `null` when the host cannot name an app: not
 * https, a port, userinfo, a path, an IP address, a trailing dot, fewer than
 * two labels, a last label of `localhost`, or a label that is empty, longer than
 * 63 characters, starts or ends with a hyphen or has a character outside
 * `[a-z0-9-]` once the host is in its A-label form.
 */
function reversedHost(origin: string): string | null {
  if (origin.endsWith(':')) return null;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.port !== '' || url.username !== '' || url.password !== '') return null;
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') return null;
  const host = url.hostname;
  if (host.startsWith('[') || host.endsWith('.') || IPV4.test(host)) return null;
  const labels = host.split('.');
  if (labels.length < 2 || labels[labels.length - 1] === 'localhost') return null;
  if (!labels.every((label) => DOMAIN_LABEL.test(label))) return null;
  return labels.reverse().join('.');
}

/**
 * Is `appId` bound to the host of `origin`? True when the id equals the
 * reversed host or starts with it and a `.`. The origin is read through the
 * WHATWG URL parser, so an upper-case or Unicode host is compared in its
 * lower-case A-label form; ids are ASCII (`appIdValid`).
 */
export function hostBinding(origin: string, appId: string): boolean {
  if (!appIdValid(appId)) return false;
  const reversed = reversedHost(origin);
  return reversed !== null && (appId === reversed || appId.startsWith(`${reversed}.`));
}

/**
 * The requesting origin for an app key grant: the widget-verified request
 * origin and the origin the manifest was fetched from, both present, byte for
 * byte equal and in the exact serialisation of the URL parser (no case
 * folding), naming an https host that can bind app ids.
 */
export function appKeyOrigin(requestOrigin: unknown, reportedOrigin: unknown): string | null {
  if (typeof requestOrigin !== 'string' || typeof reportedOrigin !== 'string') return null;
  if (requestOrigin !== reportedOrigin) return null;
  let url: URL;
  try {
    url = new URL(requestOrigin);
  } catch {
    return null;
  }
  return url.origin === requestOrigin && reversedHost(requestOrigin) !== null ? requestOrigin : null;
}

const SIWE_HEADER = /^(?:([A-Za-z][A-Za-z0-9+.-]*):\/\/)?(\S+) wants you to sign in with your Ethereum account:$/;

/**
 * Is the SIWE header one that can bind an app id? The scheme is absent or
 * `https` in any case (`http`, `ws`, `wss` are not), and the domain carries no
 * port, not even an empty one.
 */
export function siweSchemeOk(siwe: string): boolean {
  const header = siwe.split(/\r\n|\n/, 1)[0] ?? '';
  const match = SIWE_HEADER.exec(header);
  if (!match) return false;
  const [, scheme, domain] = match;
  if (scheme !== undefined && scheme.toLowerCase() !== 'https') return false;
  return !domain!.includes(':');
}

export type AppKeyAdmissionFailure =
  /** Not a browser sign-in (a ticket). */
  | 'non_browser'
  /** Origin missing, mismatched, wrongly shaped or not fully checked. */
  | 'origin'
  /** The app id does not belong to the origin's host. */
  | 'app_id'
  /** The manifest was not fetched and matched to its digest. */
  | 'manifest_unverified'
  /** The manifest's `keys` block is not valid. */
  | 'keys_unreadable'
  /** The message has no usable `Expiration Time`. */
  | 'no_expiry'
  /** A resource is not the signer's own `default` network. */
  | 'account_mismatch'
  /** The manifest does not list the requested key, prefix or ability. */
  | 'not_declared';

export type AppKeyAdmission =
  | { ok: true; admitted: AdmittedAppKey[] }
  | { ok: false; reason: AppKeyAdmissionFailure };

export interface AppKeyAdmissionInput {
  siwe: string;
  /** The `apps/` resources of the message with their abilities, as written. */
  resources: ReadonlyArray<readonly [string, readonly string[]]>;
  requestOrigin: unknown;
  reportedOrigin: unknown;
  /** The message passed the origin check with no acknowledgement. */
  siweOriginChecked: boolean;
  ticket: boolean;
  /** The manifest was fetched from the reported origin and matched the declared digest. */
  manifestBound: boolean;
  /** The manifest's own `app_id` field, unmodified. */
  declaredAppId: string | undefined;
  declaredKeys: ManifestKeys | undefined;
  /** OpenKey's DID for the signing key: `did:pkh:eip155:<chain>:<address>`. */
  ownerDid: string;
  /** The message's `Expiration Time`. */
  expirationTime: string;
}

const ABILITY_NAMESPACES = ['tinycloud.encryption/', 'encryption/'] as const;

function manifestAbility(ability: string): string | null {
  for (const namespace of ABILITY_NAMESPACES) {
    if (!ability.startsWith(namespace)) continue;
    const name = ability.slice(namespace.length);
    return (MANIFEST_ABILITIES as readonly string[]).includes(name) ? name : null;
  }
  return null;
}

function covers(declaration: ManifestKeyDeclaration, keyPath: string, isPrefix: boolean): boolean {
  if ('prefix' in declaration) {
    return isPrefix ? declaration.prefix === `${keyPath}/` : prefixCovers(declaration.prefix, keyPath);
  }
  return !isPrefix && declaration.path === keyPath;
}

/** Decide whether the `apps/` grants of one sign-in message are admitted. */
export function admitAppKeys(input: AppKeyAdmissionInput): AppKeyAdmission {
  const fail = (reason: AppKeyAdmissionFailure): AppKeyAdmission => ({ ok: false, reason });
  if (input.ticket) return fail('non_browser');
  if (!input.siweOriginChecked) return fail('origin');
  const origin = appKeyOrigin(input.requestOrigin, input.reportedOrigin);
  if (origin === null || !siweSchemeOk(input.siwe)) return fail('origin');
  const appId = input.declaredAppId;
  if (!input.manifestBound) return fail('manifest_unverified');
  if (appId === undefined || !appIdValid(appId)) return fail('not_declared');
  if (!hostBinding(origin, appId)) return fail('app_id');
  const keys = input.declaredKeys;
  if (keys?.status === 'invalid') return fail('keys_unreadable');
  if (!keys || keys.status !== 'valid' || keys.declarations.length === 0) return fail('not_declared');
  if (input.expirationTime === '' || Number.isNaN(Date.parse(input.expirationTime))) return fail('no_expiry');
  if (input.resources.length === 0) return fail('not_declared');

  const admitted: AdmittedAppKey[] = [];
  for (const [resource, abilities] of input.resources) {
    const parsed = parseKeyResource(resource);
    if (!parsed) return fail('not_declared');
    if (parsed.owner !== input.ownerDid || parsed.network !== 'default') return fail('account_mismatch');
    if (abilities.length === 0) return fail('not_declared');
    for (const ability of abilities) {
      const name = manifestAbility(ability);
      const declared = name !== null && keys.declarations.some(
        (declaration) => declaration.abilities.includes(name) && covers(declaration, parsed.keyPath, parsed.isPrefix),
      );
      if (!declared) return fail('not_declared');
    }
    admitted.push({ resource, abilities: [...abilities] });
  }
  return { ok: true, admitted };
}

/** The refusal that answers an admission failure. */
export function appKeyAdmissionRefusal(reason: AppKeyAdmissionFailure): AppKeyRefusal {
  if (reason === 'origin') return { reason: 'apps_key_origin' };
  if (reason === 'app_id') return { reason: 'apps_key_app_id' };
  if (reason === 'manifest_unverified') return { reason: 'apps_key_manifest' };
  if (reason === 'keys_unreadable') return { reason: 'apps_key_keys' };
  if (reason === 'no_expiry') return { reason: 'apps_key_expiry' };
  if (reason === 'account_mismatch') return { reason: 'apps_key_account' };
  return { reason: 'apps_key' };
}
