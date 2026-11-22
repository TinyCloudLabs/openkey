// Per-secret encryption keys. A secret `NAME` is encrypted to its own key on the owner's `default` network:
// `secrets/<name>` for a global secret, `secrets/scoped/<scope>/<name>` for a scoped one, `<name>` being `NAME` in
// lowercase. Its ciphertext stays at the KV path `vault/secrets/NAME` (`vault/secrets/scoped/<scope>/NAME`).
//
// Two questions are answered here, for the review and the warning screen alike:
//   - which exact key belongs to one secret, and the secret's display name (from the paired KV path when present);
//   - whether a request can open all secrets: decrypt on a bare network, or on the `secrets/` prefix itself.

import { encryptionResourceOfEntry, elevatedAbilityVerb } from "./elevated.js";
import { parseEncryptionResource } from "./encryption-resource.js";

const SEGMENT = "[a-z0-9][a-z0-9._-]{0,63}";

/** The key path of one secret's key: `secrets/<name>` or `secrets/scoped/<scope>/<name>`. Nothing else. */
const SECRET_KEY_PATH = new RegExp(`^secrets/(?:${SEGMENT}|scoped/${SEGMENT}/${SEGMENT})$`);

/** The SDK's secret-name rule (`sdk-services` SECRET_NAME_RE). */
const SECRET_NAME = /^[A-Z][A-Z0-9_]*$/;
const SCOPE_SEGMENT = new RegExp(`^${SEGMENT}$`);

/** The network every secret key sits under. */
const SECRETS_NETWORK = "default";
/** The prefix that covers every secret key. */
const ALL_SECRETS_PREFIX = "secrets/";

/**
 * Is this key or prefix on the `default` network shown as all secrets: the `secrets` key itself (no trailing `/`), or
 * any prefix under `secrets/` (`secrets/`, `secrets/scoped/`, `secrets/scoped/<scope>/`)? A prefix opens every secret
 * key beneath it. The node reads the bare `secrets` key as one exact key that covers no secret, so showing it as all
 * secrets overstates it, the safe way. One secret's exact key (`isSecretKeyPath`) is not.
 */
export function coversManySecrets(parsed: { kind: "key" | "prefix"; network: string; keyPath: string }): boolean {
  if (parsed.network !== SECRETS_NETWORK) return false;
  const keyPath = parsed.keyPath.toLowerCase();
  return parsed.kind === "prefix" ? keyPath.startsWith(ALL_SECRETS_PREFIX) : keyPath === "secrets";
}

/** Is this the key path of one secret's key (global or scoped)? */
export function isSecretKeyPath(keyPath: string): boolean {
  return SECRET_KEY_PATH.test(keyPath);
}

/**
 * The key path of one secret's exact key named by this encryption URN, or null: an exact key (no trailing `/`) on the
 * `default` network whose path is `secrets/<name>` or `secrets/scoped/<scope>/<name>`. The owner is not checked here.
 */
export function exactSecretKeyPath(resource: string): string | null {
  const parsed = parseEncryptionResource(resource);
  if (parsed === null || parsed.kind !== "key" || parsed.network !== SECRETS_NETWORK) return null;
  return isSecretKeyPath(parsed.keyPath) ? parsed.keyPath : null;
}

/**
 * The secret behind a KV path, and the key path of its key: `vault/secrets/NAME` gives `secrets/<name>`,
 * `vault/secrets/scoped/<scope>/NAME` gives `secrets/scoped/<scope>/<name>`. Null for anything else, including a
 * name longer than a key segment allows (it has no key).
 */
export function secretOfKvPath(kvPath: string): { name: string; keyPath: string } | null {
  const parts = kvPath.split("/");
  let name: string | undefined;
  let keyPath: string;
  if (parts.length === 3 && parts[0] === "vault" && parts[1] === "secrets") {
    name = parts[2];
    keyPath = `secrets/${name?.toLowerCase()}`;
  } else if (parts.length === 5 && parts[0] === "vault" && parts[1] === "secrets" && parts[2] === "scoped" &&
    SCOPE_SEGMENT.test(parts[3]!)) {
    name = parts[4];
    keyPath = `secrets/scoped/${parts[3]}/${name?.toLowerCase()}`;
  } else {
    return null;
  }
  if (name === undefined || !SECRET_NAME.test(name) || !isSecretKeyPath(keyPath)) return null;
  return { name, keyPath };
}

/** The last segment of a secret key path: the name in lowercase, shown when no KV path in the request names it. */
export function secretKeyDisplayName(keyPath: string): string {
  return keyPath.slice(keyPath.lastIndexOf("/") + 1);
}

/** The part of a grant or ReCap entry these checks read. */
export interface SecretReachEntry {
  service?: string;
  space: string;
  path: string;
  actions: ReadonlyArray<{ ability: string } | string>;
}

/**
 * What a request reaches across all secrets, for the all-secrets card (first match wins):
 *   - `read-and-add`: `key.create` on the `secrets/` prefix, with a decrypt that opens every secret (on `secrets/` or
 *     on a bare network);
 *   - `read`: decrypt on the `secrets/` prefix;
 *   - `whole-account`: decrypt on a bare encryption network;
 * and `alsoWholeAccount` when a bare-network decrypt is in the same request beside the `secrets/` prefix. Null when
 * nothing in the request can open every secret (a `secrets/` prefix `key.create` alone reads nothing).
 */
export interface AllSecretsReach {
  kind: "read-and-add" | "read" | "whole-account";
  alsoWholeAccount: boolean;
}

/**
 * Would this encryption resource, which `parseEncryptionResource` cannot read, name `secrets` or a path under
 * `secrets/` on a `default` network once percent-decoded and lower-cased (`Secrets/`, `SECRETS/x`, `secrets%2F`)? Read
 * this way only to pick the all-secrets card; the grant and the bytes signed stay as written.
 */
function unreadableNamesSecrets(resource: string): boolean {
  let decoded = resource;
  for (let pass = 0; pass < 5; pass += 1) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      break;
    }
    if (next === decoded) break;
    decoded = next;
  }
  const path = /^urn:tinycloud:encryption:.+?:default\/(.*)$/s.exec(decoded.toLowerCase())?.[1];
  return path !== undefined && (path === "secrets" || path.startsWith(ALL_SECRETS_PREFIX));
}

/**
 * Does this entry's ability belong to the all-secrets card: decrypt on a bare network, decrypt or `key.create` on
 * `secrets` or a prefix under it, or on an unreadable path that names them (`unreadableNamesSecrets`)?
 */
export function allSecretsAbility(entry: Omit<SecretReachEntry, "actions">, ability: string): "network-decrypt" | "prefix-decrypt" | "prefix-create" | null {
  if (entry.service !== "encryption" && entry.service !== "tinycloud.encryption") return null;
  const resource = encryptionResourceOfEntry(entry);
  if (resource === null) return null;
  const parsed = parseEncryptionResource(resource);
  const verb = elevatedAbilityVerb(ability);
  if (parsed === null) {
    if (!unreadableNamesSecrets(resource)) return null;
  } else if (parsed.kind === "network") {
    return verb === "decrypt" ? "network-decrypt" : null;
  } else if (!coversManySecrets(parsed)) {
    return null;
  }
  return verb === "decrypt" ? "prefix-decrypt" : verb === "key.create" ? "prefix-create" : null;
}

export function allSecretsReach(entries: readonly SecretReachEntry[]): AllSecretsReach | null {
  const found = new Set<string>();
  for (const entry of entries) {
    for (const action of entry.actions) {
      const reach = allSecretsAbility(entry, typeof action === "string" ? action : action.ability);
      if (reach !== null) found.add(reach);
    }
  }
  const wholeAccount = found.has("network-decrypt");
  const readsAll = wholeAccount || found.has("prefix-decrypt");
  if (readsAll && found.has("prefix-create")) return { kind: "read-and-add", alsoWholeAccount: wholeAccount };
  if (found.has("prefix-decrypt")) return { kind: "read", alsoWholeAccount: wholeAccount };
  return wholeAccount ? { kind: "whole-account", alsoWholeAccount: false } : null;
}

/** The longest a signed approval request that decrypts secrets may last, whatever the app signs. */
export const SECRET_GRANT_MAX_SECONDS = 7 * 24 * 60 * 60;

/** Where an encryption entry's listed verbs reach, for the 7-day cap. */
type CapReach = "secrets" | "network" | null;

/**
 * Where this entry's `verbs` reach: `secrets` for a key or prefix under `default/secrets/` (one secret, a scope, or
 * every secret), `network` for a whole encryption network (which opens every secret kept under it), otherwise null.
 * Fails closed: an encryption entry with one of the verbs whose resource cannot be read counts as `secrets`.
 */
function capReachOf(entry: SecretReachEntry, verbs: readonly string[]): CapReach {
  if (!/^(?:tinycloud\.)?encryption$/i.test(entry.service ?? "")) return null;
  if (!entry.actions.some((action) => verbs.includes(elevatedAbilityVerb(typeof action === "string" ? action : action.ability)))) {
    return null;
  }
  const resource = encryptionResourceOfEntry(entry);
  const parsed = resource === null ? null : parseEncryptionResource(resource);
  if (parsed === null) return "secrets";
  if (parsed.kind === "network") return "network";
  return coversManySecrets(parsed) || (parsed.network === SECRETS_NETWORK && parsed.keyPath.toLowerCase().startsWith(ALL_SECRETS_PREFIX))
    ? "secrets"
    : null;
}

/** Does this entry decrypt secrets: a key or prefix under `secrets/`, or a whole network (fails closed)? */
function entryDecryptsSecrets(entry: SecretReachEntry): boolean {
  return capReachOf(entry, ["decrypt"]) !== null;
}

/** Does any entry decrypt secrets (`entryDecryptsSecrets`): a key or prefix under `secrets/`, or a whole network? */
export function decryptsSecrets(entries: readonly SecretReachEntry[]): boolean {
  return entries.some(entryDecryptsSecrets);
}

/**
 * The longest a signed approval request may last: what its requester signed, but never more than
 * `SECRET_GRANT_MAX_SECONDS` when it may `decrypt` or `key.create` on a key or prefix under `secrets/`, `decrypt` a
 * whole network, read the secrets vault in the KV store, or use the `secrets` service (`secretLifetimeCapApplies`, the
 * rule every other path holds, with the network always on here). The page offers no more and the server refuses more.
 */
export function approvalLifetimeCapSeconds(entries: readonly SecretReachEntry[], signedSeconds: number): number {
  return secretLifetimeCapApplies(entries, { networkDecrypt: true }) ? Math.min(signedSeconds, SECRET_GRANT_MAX_SECONDS) : signedSeconds;
}

/** The KV abilities that read what the secrets vault holds: a sealed value, the names, or the change feed. */
const KV_READ_VERBS: ReadonlySet<string> = new Set(["get", "list", "metadata", "sync"]);

/**
 * Does a KV path hold secrets: `vault/secrets` and everything under it (one secret, a scope, every secret), or
 * `secrets` and everything under it? A path above them (the whole space, `vault`) is not read here. A leading `/` is
 * ignored.
 */
function kvPathHoldsSecrets(path: string): boolean {
  const clean = path.replace(/^\/+/, "");
  return clean === "secrets" || clean.startsWith("vault/secrets") || clean.startsWith("secrets/");
}

/** Does this entry read the secrets vault in the KV store (`KV_READ_VERBS` on a path that `kvPathHoldsSecrets`)? */
function kvReadsSecrets(entry: SecretReachEntry): boolean {
  return /^(?:tinycloud\.)?kv$/i.test(entry.service ?? "") &&
    entry.actions.some((action) => KV_READ_VERBS.has(elevatedAbilityVerb(typeof action === "string" ? action : action.ability))) &&
    kvPathHoldsSecrets(entry.path);
}

/**
 * Is this a grant on the `secrets` service? Whatever its action or path, it counts: no action of that service is known
 * to return only ciphertext or names, so every one fails closed.
 */
function secretsServiceGrant(entry: SecretReachEntry): boolean {
  return /^(?:tinycloud\.)?secrets$/i.test(entry.service ?? "") && entry.actions.length > 0;
}

/**
 * Is a grant made outside a signed approval request (a sign-in popup or frame, a pasted link, a raw signature) held
 * to `SECRET_GRANT_MAX_SECONDS`? Yes when it may `decrypt` or `key.create` on a key or prefix under `secrets/` (or on
 * an encryption resource that cannot be read), read the secrets vault in the KV store (`kvReadsSecrets`), or use the
 * `secrets` service (`secretsServiceGrant`), and, only when `networkDecrypt` is on, when it may `decrypt` a whole
 * network (behind `OPENKEY_NETWORK_DECRYPT_CAP`).
 */
export function secretLifetimeCapApplies(entries: readonly SecretReachEntry[], options: { networkDecrypt: boolean }): boolean {
  return entries.some((entry) =>
    capReachOf(entry, ["decrypt", "key.create"]) === "secrets" ||
    kvReadsSecrets(entry) ||
    secretsServiceGrant(entry) ||
    (options.networkDecrypt && capReachOf(entry, ["decrypt"]) === "network"));
}
