// Per-secret encryption keys (TC-3800). A secret `NAME` is encrypted to its own key on the owner's `default` network:
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

/** Does this entry's ability belong to the all-secrets card: decrypt on a bare network, decrypt or `key.create` on `secrets/`? */
export function allSecretsAbility(entry: Omit<SecretReachEntry, "actions">, ability: string): "network-decrypt" | "prefix-decrypt" | "prefix-create" | null {
  if (entry.service !== "encryption" && entry.service !== "tinycloud.encryption") return null;
  const resource = encryptionResourceOfEntry(entry);
  if (resource === null) return null;
  const parsed = parseEncryptionResource(resource);
  if (parsed === null) return null;
  const verb = elevatedAbilityVerb(ability);
  if (parsed.kind === "network") return verb === "decrypt" ? "network-decrypt" : null;
  if (parsed.kind !== "prefix" || parsed.network !== SECRETS_NETWORK || parsed.keyPath !== ALL_SECRETS_PREFIX) return null;
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

/** The longest a signed approval request that decrypts secrets may last, whatever the app signs (Sam's D7, TC-3800). */
export const SECRET_GRANT_MAX_SECONDS = 7 * 24 * 60 * 60;

/**
 * Does this entry decrypt secrets: a key or prefix under `secrets/` (one secret, a scope, or every secret), or a
 * whole encryption network, which opens every secret kept under it?
 */
function entryDecryptsSecrets(entry: SecretReachEntry): boolean {
  if (entry.service !== "encryption" && entry.service !== "tinycloud.encryption") return false;
  const resource = encryptionResourceOfEntry(entry);
  const parsed = resource === null ? null : parseEncryptionResource(resource);
  if (parsed === null) return false;
  const onSecrets = parsed.kind === "network" ||
    (parsed.network === SECRETS_NETWORK && parsed.keyPath.startsWith(ALL_SECRETS_PREFIX));
  return onSecrets &&
    entry.actions.some((action) => elevatedAbilityVerb(typeof action === "string" ? action : action.ability) === "decrypt");
}

/**
 * The longest a signed approval request may last: what its requester signed, but never more than
 * `SECRET_GRANT_MAX_SECONDS` when any of its entries decrypts secrets (`entryDecryptsSecrets`, a whole network
 * included). The page offers no more and the server refuses more.
 */
export function approvalLifetimeCapSeconds(entries: readonly SecretReachEntry[], signedSeconds: number): number {
  return entries.some(entryDecryptsSecrets) ? Math.min(signedSeconds, SECRET_GRANT_MAX_SECONDS) : signedSeconds;
}
