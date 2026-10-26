// Copy projection.
//
// A shared string catalog so the CLI browser, popup, and iframe render the
// exact same words for the exact same review model. UI components MUST route
// their text through this file — never emit ad-hoc labels.

import type {
  CapabilityFamily,
  CapabilityGrant,
  PermissionSeverity,
  RequestProtocol,
} from "./model.js";

export const SEVERITY_HEADING: Record<PermissionSeverity, string> = {
  standard: "Standard permissions",
  attention: "Permissions that need attention",
  sensitive: "Sensitive permissions",
};

export const SEVERITY_HINT: Record<PermissionSeverity, string> = {
  standard: "Routine bootstrap access.",
  attention: "Grants access to app or user data.",
  sensitive: "Grants access to secrets or decrypted content.",
};

export const FAMILY_LABEL: Record<CapabilityFamily, string> = {
  "bootstrap-kv": "Key-value storage",
  "bootstrap-sql": "SQL database",
  "bootstrap-capabilities": "Capability metadata",
  "bootstrap-delegation": "Connected access and sharing",
  "own-app-data": "Application data",
  "cross-app-data": "Another user's data",
  "public-data": "Public data",
  "secret-read": "Named secret (read)",
  "secret-namespace-list": "Secret namespace access",
  "secret-mutation": "Named secret (mutate)",
  "encryption-key": "Encryption key material",
  "encryption-decrypt": "Decrypt encrypted content",
  "app-keys": "App keys",
  "space-create": "Create a space",
  "space-read": "Space details",
  hooks: "Change notifications",
  "duckdb-data": "DuckDB database",
  "database-admin": "Database administration",
  "file-data": "Files",
  unknown: "Unknown capability",
};

/**
 * Title of a read-only `tinycloud.delegation` grant (`list`, `status`) on the
 * signer's own `account` or `applications` space. The node answers with every
 * delegation of the account: who holds it, the names of what it reaches, the
 * actions and the expiry.
 */
export const DELEGATION_LIST_LABEL =
  "See which apps and links can reach your data, and the names of what each can reach";

/** The consent sentence for the same grant. */
export const DELEGATION_LIST_STATEMENT =
  "See who has access to your data, what it reaches (by name) and when it ends. Keys and contents aren't shown.";

/**
 * Consent copy for a raw `tinycloud.encryption/decrypt` on the account's
 * `:default` network. Single source of truth: statements.ts imports this
 * constant and tests compare against it.
 */
export const DECRYPT_DEFAULT_KEY_STATEMENT =
  "Decrypt anything encrypted with your account's default key — including your Secrets and every private share — whenever this app gets hold of the encrypted copy, until this access expires.";

/** Named-key verbs that carry consent copy. */
export type NamedKeyVerb = "create" | "decrypt" | "block" | "unblock" | "delete";

export const DELETE_REFUSED_TEMPLATE =
  "Delete the key {path}: only you can do this, with your wallet, as a separate step. This request is refused.";

/**
 * Named-key consent sentences, one per verb and resource shape. `{path}` is
 * the key path (a prefix keeps its trailing `/`) and `{network}` the network
 * name, both filled verbatim by renderNamedKeySentence. `null` means no
 * approved wording: the row renders the literal fallback instead.
 */
export const NAMED_KEY_STATEMENTS: Record<
  NamedKeyVerb,
  { key: string | null; prefix: string | null }
> = {
  create: {
    key: "Create the encryption key {path} in your account's {network} network.",
    prefix: "Create encryption keys under {path} in your account's {network} network.",
  },
  decrypt: {
    key: "Decrypt anything encrypted with your key {path} in your account's {network} network, whenever this app gets hold of the encrypted copy, until this access expires.",
    prefix: "Decrypt anything encrypted with any of your keys under {path} in your account's {network} network, including keys created later, whenever this app gets hold of the encrypted copy, until this access expires.",
  },
  block: {
    key: "Block the key {path} in your account's {network} network, so nobody, you included, can decrypt with it until it is unblocked. You can unblock it later.",
    prefix:
      "Block every key under {path} in your account's {network} network, so nobody, you included, can decrypt with any of them until they are unblocked. You can unblock them later.",
  },
  unblock: {
    key: "Unblock the key {path} in your account's {network} network, so it can decrypt again, even if you blocked it yourself.",
    prefix:
      "Unblock every key under {path} in your account's {network} network, so they can decrypt again, even if you blocked them yourself.",
  },
  delete: {
    key: DELETE_REFUSED_TEMPLATE,
    prefix: DELETE_REFUSED_TEMPLATE,
  },
};

export const OWN_KEY_PREFIX_STATEMENTS = {
  create: "Create encryption keys of your own in the folder `{path}`",
  decrypt: "Decrypt data locked with your own keys in the folder `{path}`, including keys created later",
} as const;

/**
 * Escape controls, markup and non-ASCII characters as `\uXXXX`, so
 * resource text cannot alter the displayed consent sentence. Cap raw text
 * at `maxChars` output characters, ending with `…`.
 */
export function renderLiteral(text: string, maxChars?: number): string {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    const piece =
      code === 0x5c
        ? "\\u005C"
        : code === 0x3c || code === 0x3e || code === 0x26 ||
          code === 0x22 || code === 0x27 || code < 0x20 || code > 0x7e
          ? `\\u${code.toString(16).padStart(4, "0")}`
          : text.charAt(i);
    if (maxChars !== undefined && out.length + piece.length > maxChars) {
      return `${out}…`;
    }
    out += piece;
  }
  return out;
}

/**
 * One line of an exact-message view: the control characters (C0, DEL, C1), every
 * non-ASCII character and the backslash read `\uXXXX`; every other printable
 * ASCII character, including `' " < > &`, reads as itself. A backslash in the
 * output therefore always starts an escape.
 */
function escapeExactLine(line: string): string {
  let out = "";
  for (let i = 0; i < line.length; i += 1) {
    const code = line.charCodeAt(i);
    out += code === 0x5c ? "\\u005C" : code < 0x20 || code > 0x7e ? `\\u${code.toString(16).padStart(4, "0")}` : line.charAt(i);
  }
  return out;
}

/**
 * The exact-message view of a SIWE message. A line feed (U+000A) between two
 * lines is a real line break; control characters, non-ASCII characters and the
 * backslash are escaped as `\uXXXX`, and printable ASCII reads as itself. Runs
 * of two or more spaces and spaces at the end of a line
 * read `\u0020` and a final line feed reads `\u000a`, so an empty line, a line
 * of spaces, a long run of spaces, trailing spaces and a trailing line feed
 * each look different from their absence. Each line break
 * shown is one line feed in the message, a carriage return reads `\u000d`, and
 * un-escaping the output gives the input back. Not truncated.
 */
export function renderSiweLiteral(text: string): string {
  const endsWithLineFeed = text.endsWith("\n");
  const lines = (endsWithLineFeed ? text.slice(0, -1) : text)
    .split("\n")
    .map((line) => escapeExactLine(line).replace(/ {2,}| +$/g, (spaces) => "\\u0020".repeat(spaces.length)));
  return lines.join("\n") + (endsWithLineFeed ? "\\u000a" : "");
}

/** Output-character cap for raw, unparsed resource text before `…`. */
export const LITERAL_TRUNCATE_CHARS = 120;

/**
 * Fill a named-key template in one pass, so a `{network}` inside a path is
 * never substituted again and `$` is never a replacement pattern. Every value
 * goes through renderLiteral. `truncateAt` is passed only for raw text that
 * did not parse; valid keys are never truncated.
 */
export function renderNamedKeySentence(
  template: string,
  keyPath: string,
  network: string,
  truncateAt?: number,
): string {
  const values = {
    path: renderLiteral(keyPath, truncateAt),
    network: renderLiteral(network),
  };
  return template.replace(
    /\{(path|network)\}/g,
    (_match, name: string) => (name === "path" ? values.path : values.network),
  );
}

/** The abilities an app key grant can name, in the order their rows are shown. */
export const APP_KEY_ABILITIES = [
  "key.create",
  "decrypt",
  "key.block",
  "key.unblock",
  "key.delete",
] as const;

export type AppKeyAbility = (typeof APP_KEY_ABILITIES)[number];

/**
 * Consent copy for one ability on an app key (an exact key) or an app key
 * prefix. The rows say "this app", never the app's name, and never show the
 * path: `path` is the key path, or the prefix with its trailing `/`, and an
 * exact key is named by its last segment. The text between backticks is shown
 * in monospace.
 */
export function appKeyStatementText(
  ability: AppKeyAbility,
  target: { path: string; isPrefix: boolean },
): string {
  const keyName = `\`${target.path.slice(target.path.lastIndexOf("/") + 1)}\``;
  switch (ability) {
    case "key.create":
      return target.isPrefix
        ? "Create new encryption keys tied to this app"
        : `Create the encryption key ${keyName} for this app`;
    case "decrypt":
      return target.isPrefix
        ? "Decrypt data locked with this app's keys"
        : `Decrypt data locked with this app's key ${keyName}`;
    case "key.block":
      return target.isPrefix
        ? "Block this app's encryption keys so they can't be used to decrypt"
        : `Block this app's key ${keyName} so it can't be used to decrypt`;
    case "key.unblock":
      return target.isPrefix
        ? "Unblock this app's encryption keys so they can be used again"
        : `Unblock this app's key ${keyName} so it can be used again`;
    case "key.delete":
      return target.isPrefix
        ? "Delete this app's encryption keys. Apps can't be given this permission."
        : `Delete this app's key ${keyName}. Apps can't be given this permission.`;
  }
}

/** Shown while a request with app keys is being edited: the app keys are one unit. */
export const APP_KEY_GROUP_NOTE = "App keys can only be approved together. Untick all of them, or keep them all.";

/** The line above the rows of a request with app keys. */
export function appRequestingLine(name: string | null): string {
  return `${name ?? "This app"} is requesting:`;
}

export const APP_KEY_ACCESS_WITHOUT_EXPIRY = "This access lasts until it expires.";

/**
 * Standing-access line for app-key decrypt. `expiry` is the signed SIWE
 * `Expiration Time`. `formatExpiry` turns it into the text shown; without one
 * the signed value is shown as written.
 */
export function appKeyAccessStatement(
  expiry: string | null,
  formatExpiry: (expiry: string) => string = (value) => value,
): string {
  if (expiry === null || Number.isNaN(Date.parse(expiry))) return APP_KEY_ACCESS_WITHOUT_EXPIRY;
  return `This access lasts until ${formatExpiry(expiry)}.`;
}

export const PROTOCOL_HEADLINE: Record<RequestProtocol, string> = {
  "legacy-message": "Sign message",
  "siwe-plain": "Sign in with Ethereum",
  "tinycloud-siwe-recap": "Authorize capabilities",
  "malformed-recap": "Refusing to sign: malformed capability payload",
};

export const PROTOCOL_HINT: Record<RequestProtocol, string> = {
  "legacy-message":
    "You will sign these bytes exactly. Editing is not available.",
  "siwe-plain":
    "You will sign this SIWE message exactly. Editing is not available.",
  "tinycloud-siwe-recap":
    "Review the requested capabilities. Uncheck anything you do not want to grant.",
  "malformed-recap":
    "This message carries a capability payload we could not decode. Approving is disabled so a broken ReCap cannot be silently signed as an exact-byte SIWE.",
};

/**
 * Build the ordered rendering plan a UI needs: severity buckets, each with
 * a heading and the grants in stable order.
 */
export function buildRenderPlan(grants: CapabilityGrant[]): Array<{
  severity: PermissionSeverity;
  heading: string;
  hint: string;
  grants: CapabilityGrant[];
}> {
  const buckets: Record<PermissionSeverity, CapabilityGrant[]> = {
    sensitive: [],
    attention: [],
    standard: [],
  };
  for (const grant of grants) {
    buckets[grant.severity].push(grant);
  }
  // Stable order inside each bucket: family, then id.
  const ordered: PermissionSeverity[] = ["sensitive", "attention", "standard"];
  return ordered
    .filter((sev) => buckets[sev].length > 0)
    .map((sev) => ({
      severity: sev,
      heading: SEVERITY_HEADING[sev],
      hint: SEVERITY_HINT[sev],
      grants: [...buckets[sev]].sort((a, b) => {
        if (a.family !== b.family) return a.family.localeCompare(b.family);
        return a.id.localeCompare(b.id);
      }),
    }));
}

/**
 * Compact human label for a single grant. Prefers verified metadata label,
 * falls back to structural display label.
 */
export function grantHeading(grant: CapabilityGrant): string {
  return grant.metadataLabel ?? grant.displayLabel;
}
