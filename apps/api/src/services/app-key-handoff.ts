// A prepared command-line handoff (ticket) may ask for ONE exact app key:
// `appKey: { appId, key }`, `key` relative to `apps/<appId>/`. The request is
// admitted only when the app's own website lists that exact key in
// `https://<host>/.well-known/openkey-app-keys.json`, where `<host>` is the
// app id with its labels reversed. The file is fetched at every prepare and
// never cached; there is no unsigned or digest fallback.
//
// The signed message is the request SIWE: exactly one ReCap resource, the key
// on the signer's own `default` network, with `decrypt` and `key.create` and
// nothing else, ending within 7 days.

import { SiweMessage } from 'siwe';
import { parseManifestKeys, appIdForOrigin } from './app-key-gate';
import { recapResources, type AdmittedAppKey } from './app-key-refusal';
import { appIdValid, isKeyPath, parseKeyResource } from './key-resource';
import { fetchAppKeysFile, type AppKeysFileFetch } from './manifest-origin-fetch';

export interface AppKeyHandoffRequest {
  appId: string;
  /** Relative to `apps/<appId>/`. */
  key: string;
}

export type AppKeyHandoffReason =
  | 'request_invalid'
  | 'ticket_required'
  | 'app_id'
  | 'recap'
  | 'account'
  | 'expiry'
  | 'file_unavailable'
  | 'file_missing'
  | 'file_invalid'
  | 'file_app_mismatch'
  | 'key_not_listed';

export type AppKeyHandoffCode =
  | 'app_key_request_invalid'
  | 'app_keys_file_unavailable'
  | 'app_keys_file_missing'
  | 'app_keys_file_invalid'
  | 'app_key_not_listed';

const CODES: Record<AppKeyHandoffReason, AppKeyHandoffCode> = {
  request_invalid: 'app_key_request_invalid',
  ticket_required: 'app_key_request_invalid',
  app_id: 'app_key_request_invalid',
  recap: 'app_key_request_invalid',
  account: 'app_key_request_invalid',
  expiry: 'app_key_request_invalid',
  file_unavailable: 'app_keys_file_unavailable',
  file_missing: 'app_keys_file_missing',
  file_invalid: 'app_keys_file_invalid',
  file_app_mismatch: 'app_keys_file_invalid',
  key_not_listed: 'app_key_not_listed',
};

const STATUSES: Record<AppKeyHandoffReason, 400 | 403> = {
  request_invalid: 400,
  ticket_required: 400,
  app_id: 403,
  recap: 403,
  account: 403,
  expiry: 400,
  file_unavailable: 403,
  file_missing: 403,
  file_invalid: 403,
  file_app_mismatch: 403,
  key_not_listed: 403,
};

// Owner-visible lines. The file and key lines are the owner screen's words; `{host}` and `{keyName}` (the last
// segment of the key) are filled by `appKeyHandoffRefusal`. The other lines are placeholders. Clients key on `code`.
export const APP_KEY_HANDOFF_MESSAGES: Record<AppKeyHandoffReason, string> = {
  request_invalid: "This request names an app key that OpenKey can't read, so it didn't approve it.",
  ticket_required: "App keys can only be requested through a prepared command-line sign-in, so OpenKey didn't approve this request.",
  app_id: "This app id doesn't match a website address, so OpenKey didn't approve this request.",
  recap: "This request asks for more than the one app key it names, so OpenKey didn't approve it.",
  account: "This request doesn't match your account, so OpenKey didn't approve it.",
  expiry: "This request doesn't end within 7 days, so OpenKey didn't approve it.",
  file_unavailable: "OpenKey couldn't check {host}'s list of keys for command-line tools. Nothing was approved. Try again.",
  file_missing: "OpenKey can't approve this request: {host} doesn't list keys that command-line tools can ask for. Nothing was approved.",
  file_invalid: "OpenKey can't approve this request: {host}'s list of keys for command-line tools can't be read. Nothing was approved.",
  file_app_mismatch: "OpenKey can't approve this request: {host}'s list of keys for command-line tools can't be read. Nothing was approved.",
  key_not_listed: "OpenKey can't approve this request: {host} doesn't let command-line tools ask for the key {keyName}. Nothing was approved.",
};

export interface AppKeyHandoffRefusal {
  status: 400 | 403;
  body: { error: string; code: AppKeyHandoffCode; reason: AppKeyHandoffReason };
}

/** `appKey` names the host and key the owner-visible lines speak of; without it they say "this website". */
export function appKeyHandoffRefusal(reason: AppKeyHandoffReason, appKey?: AppKeyHandoffRequest): AppKeyHandoffRefusal {
  const host = appKey ? appKeyHandoffHost(appKey.appId) ?? appKey.appId : 'this website';
  const keyName = appKey ? appKey.key.slice(appKey.key.lastIndexOf('/') + 1) : 'this key';
  const error = APP_KEY_HANDOFF_MESSAGES[reason].replaceAll('{host}', host).replaceAll('{keyName}', keyName);
  return { status: STATUSES[reason], body: { error, code: CODES[reason], reason } };
}

/** The longest a command-line app key grant lasts. */
export const APP_KEY_HANDOFF_MAX_MS = 7 * 24 * 60 * 60 * 1000;
/** The grant the owner sees by default. */
export const APP_KEY_HANDOFF_DEFAULT_MS = 60 * 60 * 1000;
/** The server's clock may differ from the command line's by this much (the prepared claim allows 30 s of issuedAt). */
const CLOCK_SKEW_MS = 60_000;

export const APP_KEY_ABILITIES = ['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create'] as const;
const FILE_ABILITIES = ['decrypt', 'key.create'] as const;

/** `{ appId, key }` and nothing else, with a valid app id and a valid relative key under it. `null` otherwise. */
export function parseAppKeyHandoff(value: unknown): AppKeyHandoffRequest | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const fields = Object.keys(value);
  if (fields.length !== 2 || !fields.includes('appId') || !fields.includes('key')) return null;
  const { appId, key } = value as Record<string, unknown>;
  if (typeof appId !== 'string' || typeof key !== 'string' || !appIdValid(appId)) return null;
  // A key written in full (`apps/<appId>/...`) is a mistake, not a key that happens to start that way.
  if (key.startsWith(`apps/${appId}/`)) return null;
  return isKeyPath(`apps/${appId}/${key}`) ? { appId, key } : null;
}

/**
 * The website host an app id belongs to: the id's labels, reversed. Only an id
 * that IS the reversed host of a valid https host of at least two labels has
 * one; an id with extra labels after the reversed host does not.
 */
export function appKeyHandoffHost(appId: string): string | null {
  if (!appIdValid(appId)) return null;
  const host = appId.split('.').reverse().join('.');
  return appIdForOrigin(`https://${host}`) === appId ? host : null;
}

export interface AppKeyHandoffGrant {
  /** The one admitted key resource, as it must be written in the SIWE. */
  admitted: AdmittedAppKey;
  expirationTime: string;
}

/**
 * Is this SIWE exactly the request for the named key? `ownerDid` is the
 * signer's DID; when absent (the claim, before a signer is chosen) the SIWE's
 * own address and chain name it.
 */
export function checkAppKeyHandoffSiwe(input: {
  siwe: string;
  appKey: AppKeyHandoffRequest;
  ownerDid?: string;
  now: number;
}): { ok: true; grant: AppKeyHandoffGrant } | { ok: false; reason: AppKeyHandoffReason } {
  const fail = (reason: AppKeyHandoffReason) => ({ ok: false as const, reason });
  if (appKeyHandoffHost(input.appKey.appId) === null) return fail('app_id');
  let message: SiweMessage;
  try {
    message = new SiweMessage(input.siwe);
  } catch {
    return fail('recap');
  }
  // One resource in the whole message, and it is the one ReCap.
  if (!message.resources || message.resources.length !== 1 || !message.resources[0]!.startsWith('urn:recap:')) {
    return fail('recap');
  }
  const resources = recapResources(input.siwe);
  if (resources === null || resources.length !== 1) return fail('recap');
  const [resource, abilities] = resources[0]!;
  const ownerDid = input.ownerDid ?? `did:pkh:eip155:${message.chainId}:${message.address}`;
  const parsed = parseKeyResource(resource);
  if (!parsed || parsed.isPrefix || parsed.keyPath !== `apps/${input.appKey.appId}/${input.appKey.key}`) return fail('recap');
  if (parsed.owner !== ownerDid || parsed.network !== 'default') return fail('account');
  if (
    abilities.length !== APP_KEY_ABILITIES.length ||
    !APP_KEY_ABILITIES.every((ability) => abilities.includes(ability))
  ) {
    return fail('recap');
  }
  const end = Date.parse(message.expirationTime ?? '');
  if (!Number.isFinite(end) || end <= input.now || end > input.now + APP_KEY_HANDOFF_MAX_MS + CLOCK_SKEW_MS) {
    return fail('expiry');
  }
  return { ok: true, grant: { admitted: { resource, abilities: [...abilities] }, expirationTime: message.expirationTime! } };
}

/**
 * Read the app-keys file bytes: a JSON object whose `app_id` is the requested
 * id and whose `keys` block (same rules as the manifest's) has a `path` entry
 * for exactly this key with `decrypt` and `key.create`. A `prefix` entry never
 * counts.
 */
export function checkAppKeysFile(
  bytes: Uint8Array,
  appKey: AppKeyHandoffRequest,
): { ok: true } | { ok: false; reason: 'file_invalid' | 'file_app_mismatch' | 'key_not_listed' } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return { ok: false, reason: 'file_invalid' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { ok: false, reason: 'file_invalid' };
  const file = parsed as Record<string, unknown>;
  if (typeof file.app_id !== 'string') return { ok: false, reason: 'file_invalid' };
  if (file.app_id !== appKey.appId) return { ok: false, reason: 'file_app_mismatch' };
  const keys = parseManifestKeys(appKey.appId, file.keys);
  if (keys.status !== 'valid') return { ok: false, reason: 'file_invalid' };
  const path = `apps/${appKey.appId}/${appKey.key}`;
  const listed = keys.declarations.some(
    (declaration) => 'path' in declaration && declaration.path === path &&
      FILE_ABILITIES.every((ability) => declaration.abilities.includes(ability)),
  );
  return listed ? { ok: true } : { ok: false, reason: 'key_not_listed' };
}

/** Fetch the app's file now and read it. Never cached. `fetchFile` is for tests. */
export async function verifyAppKeyHandoffFile(
  appKey: AppKeyHandoffRequest,
  fetchFile: (host: string) => Promise<AppKeysFileFetch> = fetchAppKeysFile,
): Promise<{ ok: true; host: string } | { ok: false; reason: AppKeyHandoffReason }> {
  const host = appKeyHandoffHost(appKey.appId);
  if (host === null) return { ok: false, reason: 'app_id' };
  const fetched = await fetchFile(host);
  if (!fetched.ok) return { ok: false, reason: fetched.kind === 'missing' ? 'file_missing' : 'file_unavailable' };
  const read = checkAppKeysFile(fetched.bytes, appKey);
  return read.ok ? { ok: true, host } : { ok: false, reason: read.reason };
}
