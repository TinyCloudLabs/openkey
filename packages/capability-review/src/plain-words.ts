// Plain words for TinyCloud actions.
//
// One action reads in its own words ("See details of your data"); several
// read as short kinds on what they act on ("Read and delete your data").
// Shared by the fallback row and core-operation rows (statements.ts) and by
// titles composed from several operations (classify.ts), so a row and its
// title name the same consequences.

import { BOOTSTRAP_SPACE_NAMES } from "@tinycloud/bootstrap";
import { isSecretsSpace } from "./app-scope.js";
import { LITERAL_TRUNCATE_CHARS, renderLiteral } from "./copy.js";

/**
 * By short service name and verb: the sentence for that one action
 * (`{owner}` is "your ", "another user's " or nothing, `{data}` is "secrets"
 * in a secrets space, else "data"), the kinds it counts as when a row names
 * several actions, and what those kinds act on. The legacy named-secrets
 * service and `key.delete` (always refused) are absent on purpose; actions
 * outside this table show their raw ability.
 */
const PLAIN_ACTIONS: Record<
  string,
  Record<string, readonly [text: string, kinds: readonly string[], noun: string]>
> = {
  kv: {
    get: ["Read {owner}{data}", ["read"], "{data}"],
    list: ["List {owner}{data}", ["read"], "{data}"],
    metadata: ["See details of {owner}{data}", ["read"], "{data}"],
    put: ["Change {owner}{data}", ["change"], "{data}"],
    del: ["Delete {owner}{data}", ["delete"], "{data}"],
    delete: ["Delete {owner}{data}", ["delete"], "{data}"],
    sync: ["Follow changes to {owner}{data}", ["read"], "{data}"],
    retain: ["Keep offline copies of {owner}{data}", ["read"], "{data}"],
  },
  sql: {
    read: ["Read {owner}{data}", ["read"], "{data}"],
    select: ["Read {owner}{data}", ["read"], "{data}"],
    write: ["Change {owner}{data}", ["change"], "{data}"],
    schema: ["Edit and delete tables in {owner}{data}", ["change", "delete"], "{data}"],
    admin: ["Manage {owner}{data}", ["manage"], "{data}"],
    "*": ["Do anything with {owner}{data}", ["all"], "{data}"],
  },
  duckdb: {
    read: ["Read {owner}{data}", ["read"], "{data}"],
    select: ["Read {owner}{data}", ["read"], "{data}"],
    export: ["Download {owner}{data}", ["read"], "{data}"],
    write: ["Change {owner}{data}", ["change"], "{data}"],
    import: ["Replace {owner}{data}", ["change", "delete"], "{data}"],
    admin: ["Manage {owner}{data}", ["manage"], "{data}"],
    "*": ["Do anything with {owner}{data}", ["all"], "{data}"],
  },
  vfs: {
    get: ["Read {owner}files", ["read"], "files"],
    list: ["List {owner}files", ["read"], "files"],
    metadata: ["See details of {owner}files", ["read"], "files"],
    put: ["Change {owner}files", ["change"], "files"],
    delete: ["Delete {owner}files", ["delete"], "files"],
  },
  hooks: {
    subscribe: ["Watch changes to {owner}{data}", ["read"], "{data}"],
    list: ["See webhooks on {owner}{data}", ["read"], "{data}"],
    register: ["Send {owner}change alerts to a webhook", ["share"], "{data}"],
    unregister: ["Remove webhooks from {owner}{data}", ["change"], "{data}"],
  },
  space: {
    list: ["List {owner}spaces", ["read"], "spaces"],
    info: ["See usage of {owner}spaces", ["read"], "spaces"],
    host: ["Create {owner}spaces", ["create"], "spaces"],
    create: ["Create {owner}spaces", ["create"], "spaces"],
  },
  capabilities: { read: ["Check permissions on {owner}{data}", ["read"], "{data}"] },
  delegation: {
    list: ["See who can access {owner}{data}", ["read"], "{data}"],
    status: ["See who can access {owner}{data}", ["read"], "{data}"],
  },
  encryption: {
    decrypt: ["Decrypt {owner}data", ["decrypt"], "decryption"],
    "network.create": ["Set up {owner}decryption network", ["set up"], "decryption"],
    "network.revoke": ["Turn off {owner}decryption network", ["stop"], "decryption"],
    "key.create": ["Create {owner}keys", ["create"], "keys"],
    "key.block": ["Block {owner}keys", ["block"], "keys"],
    "key.unblock": ["Unblock {owner}keys", ["unblock"], "keys"],
  },
};

/** Reading order of the kinds. "manage" covers "change"; "all" covers every kind. */
const KIND_ORDER = [
  "decrypt",
  "read",
  "set up",
  "create",
  "change",
  "manage",
  "block",
  "unblock",
  "stop",
  "delete",
  "share",
];

/** `read`, `read and list`, `read, list and delete`. */
function joinAnd(words: readonly string[]): string {
  return words.length <= 1
    ? words.join("")
    : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/**
 * Space names OpenKey never names in copy: the ones it has words of its own
 * for, and every one of TinyCloud's own spaces (`BOOTSTRAP_SPACE_NAMES`,
 * which includes `secrets` and `agents`, where Courier keeps approvals and
 * peer delegations).
 */
const RESERVED_SPACE_NAMES: ReadonlySet<string> = new Set<string>([
  "account",
  "applications",
  "public",
  "default",
  ...BOOTSTRAP_SPACE_NAMES,
]);

/**
 * The name of a space that may be named in copy ("your messages data"): a
 * short plain name that is not one of TinyCloud's own spaces. Null for
 * anything else, which keeps its generic words.
 */
export function namedSpaceName(space: string): string | null {
  const name = space.slice(space.lastIndexOf(":") + 1);
  if (!space.startsWith("tinycloud:pkh:") || !/^[a-z][a-z0-9-]{0,11}$/.test(name)) return null;
  if (RESERVED_SPACE_NAMES.has(name) || isSecretsSpace(space)) return null;
  return name;
}

/**
 * The known actions in plain words: one sentence for one known action, else
 * one part per thing acted on ("read and delete your data"). Every part
 * keeps `owner`. `raw` holds every other action, each escaped and capped on
 * its own; with `rawOnly` every action is raw. `dataNoun` replaces "data"
 * for a space the caller has recognized by name ("messages data").
 */
export function plainWords(
  abilities: readonly string[],
  space: string,
  owner: string,
  rawOnly: boolean,
  dataNoun?: string,
): { parts: string[]; raw: string[] } {
  const data = isSecretsSpace(space) ? "secrets" : dataNoun ?? "data";
  const sentences = new Set<string>();
  const kindsByNoun = new Map<string, Set<string>>();
  const raw: string[] = [];
  for (const ability of abilities) {
    const slash = ability.indexOf("/");
    const head = slash >= 0 ? ability.slice(0, slash).replace(/^tinycloud\./, "") : "";
    const table = !rawOnly && Object.hasOwn(PLAIN_ACTIONS, head) ? PLAIN_ACTIONS[head] : undefined;
    const verb = slash >= 0 ? ability.slice(slash + 1) : ability;
    const entry = table !== undefined && Object.hasOwn(table, verb) ? table[verb]! : undefined;
    if (entry === undefined) {
      raw.push(renderLiteral(ability, LITERAL_TRUNCATE_CHARS));
      continue;
    }
    sentences.add(entry[0].replace("{owner}", owner).replace("{data}", data));
    const noun = entry[2].replace("{data}", data);
    const kinds = kindsByNoun.get(noun) ?? new Set<string>();
    for (const kind of entry[1]) kinds.add(kind);
    kindsByNoun.set(noun, kinds);
  }
  if (sentences.size <= 1) return { parts: [...sentences], raw };
  const parts = [...kindsByNoun].map(([noun, kinds]) => {
    const words = kinds.has("all")
      ? ["do anything with"]
      : KIND_ORDER.filter((kind) => kinds.has(kind) && !(kind === "change" && kinds.has("manage")));
    return `${joinAnd(words)} ${owner}${noun}`;
  });
  return { parts, raw };
}

/** Plain words for several known actions as one capitalized line ("Read and delete your data"). */
export function plainSentence(abilities: readonly string[], space: string, owner: string, dataNoun?: string): string {
  const text = plainWords(abilities, space, owner, false, dataNoun).parts.join("; ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
