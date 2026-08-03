// SSRF-guarded fetch for the app's well-known OpenKey manifest.
//
// Used by /authorize-sign-prepare so it can OPTIONALLY upgrade the
// presentation-envelope trust label from `unsigned` to `origin-bound` when:
//   1. The widget reported an https origin as the browser-verified parent.
//   2. That origin serves `.well-known/openkey-manifest.json` over https.
//   3. The SHA-256 of the fetched manifest's canonical JSON representation
//      matches the envelope's `manifestDigest` field.
//
// Never used to grant authority — the manifest is display-only. The trust
// upgrade only lets the widget render a slightly more honest label; the
// ReCap payload remains the sole gate for what the user can approve.
//
// SSRF guardrails:
//   - https-only (http, file, data, gopher, ws, ftp all rejected)
//   - No redirects (redirect: "error")
//   - Public-IP-only: hostnames that resolve to loopback, link-local, or
//     RFC1918 private ranges are rejected. Because Node's `fetch` doesn't
//     expose the resolved IP, we do a DNS lookup ourselves and reject any
//     private/reserved address; we also reject an obviously-textual private
//     hostname to catch the trivially-wrong cases quickly.
//   - 5 second timeout
//   - 64KB max response size
//   - Silently returns `{ ok: false }` on any failure — the caller's
//     fail-closed rule is to fall back to `unsigned` trust.

import { createHash, timingSafeEqual } from "node:crypto";
import { promises as dns } from "node:dns";
import net from "node:net";
import { Agent, buildConnector, fetch as undiciFetch } from "undici";

const MANIFEST_PATH = "/.well-known/openkey-manifest.json";
const REQUEST_TIMEOUT_MS = 5_000;
const MAX_BYTES = 64 * 1024;

/**
 * Sol MAJOR-2: a single declared scoped-secret entry extracted from the
 * origin-bound manifest. The trust rule for surfacing a KV/secret grant
 * as "app-scoped normal" (rather than the default sensitive presentation)
 * requires that ALL of `{ secretName, scope, actions }` match a signed
 * ReCap resource in the same scope. This shape carries what the widget
 * needs to make that comparison — nothing more.
 */
export interface DeclaredScopedSecret {
  /** The manifest secret key (or explicit `name` override). */
  secretName: string;
  /** The app-declared scope namespace. Omit for global secrets. */
  scope?: string;
  /** The declared action strings (short verbs, not URNs). */
  actions: string[];
}

/**
 * Sol MAJOR-2: a single declared permission from the origin-bound
 * manifest. Used to validate that the signed ReCap resource actually
 * falls within what the manifest declared. Any grant whose (service,
 * space-suffix, path-prefix, action) does not match a declared entry
 * MUST remain sensitive — the widget will refuse to demote it.
 */
export interface DeclaredPermission {
  /** Fully-qualified service name, e.g. `tinycloud.kv`. */
  service: string;
  /** Space name or full URI, if declared. */
  space?: string;
  /** Manifest-relative path (before prefix expansion). */
  path: string;
  /** Short action verbs the manifest requested for this resource. */
  actions: string[];
}

export interface OriginBindResult {
  ok: boolean;
  /** Only present when ok=true. */
  manifest?: {
    name?: string;
    appId?: string;
    manifestId?: string;
    /**
     * Sol MAJOR-2: the manifest's declared `prefix` (or `app_id` when
     * `prefix` is unset). Used by the widget to build the expected
     * full ReCap path for each declared permission.
     */
    prefix?: string;
    /** Sol MAJOR-2: the manifest's declared `space` (or default). */
    defaultSpace?: string;
    /**
     * Sol MAJOR-2: declared scoped-secret entries. Only present when the
     * manifest carries a `secrets` block. The widget uses this to
     * classify a secret grant as "app-scoped normal" only when the
     * grant's (service, path, actions) match a declared entry AND the
     * ReCap resource carries the declared scope. Otherwise the grant
     * remains sensitive.
     */
    declaredSecrets?: DeclaredScopedSecret[];
    /**
     * Sol MAJOR-2: declared permissions block. The widget cross-checks
     * every ReCap resource against this list to decide whether the app
     * actually asked for it via its published manifest.
     */
    declaredPermissions?: DeclaredPermission[];
  };
  /** Only present when ok=true. SHA-256 of the fetched canonical manifest JSON. */
  fetchedDigest?: string;
  /** Debug/log reason for failure (never surfaced to the caller). */
  reason?: string;
}

/**
 * Attempt to origin-bind the caller-reported origin against a declared
 * manifest digest. Returns `{ ok: true }` only when every guard passes and
 * the fetched manifest's canonical-JSON SHA-256 matches `declaredDigest`
 * (case-insensitive hex compare, constant-time).
 */
export async function fetchAndBindWellKnownManifest(input: {
  reportedOrigin: string;
  declaredDigest: string;
}): Promise<OriginBindResult> {
  const { reportedOrigin, declaredDigest } = input;

  // 1. Structural URL validation.
  let url: URL;
  try {
    url = new URL(reportedOrigin);
  } catch {
    return { ok: false, reason: "reportedOrigin is not a URL" };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: "reportedOrigin is not https" };
  }
  if (url.pathname && url.pathname !== "" && url.pathname !== "/") {
    return { ok: false, reason: "reportedOrigin must not carry a path" };
  }

  // 2. Reject obviously-private hostnames before DNS.
  if (isLiterallyPrivateHostname(url.hostname)) {
    return { ok: false, reason: "reportedOrigin resolves to a private host" };
  }

  // 3. DNS resolve + reject private/reserved IPs. Uses `dns.lookup` so it
  //    matches what the network stack itself would use.
  //
  // SECURITY (Sol MAJOR-4 — DNS rebinding): a later fetch that re-resolves
  //  the hostname would be TOCTOU-vulnerable: an attacker's DNS could
  //  return a public IP here and a private IP on the fetch. To defeat this
  //  we pick ONE validated address here and pin the actual HTTPS
  //  connection to it via a custom undici dispatcher below. TLS SNI /
  //  hostname validation stays bound to `url.hostname`, so the fetch
  //  refuses if the presented cert is not for the reported origin.
  let pinnedAddress: string | null = null;
  try {
    const addresses = await dns.lookup(url.hostname, { all: true });
    if (!addresses.length) {
      return { ok: false, reason: "reportedOrigin failed DNS resolution" };
    }
    for (const a of addresses) {
      if (isPrivateOrReservedAddress(a.address)) {
        return {
          ok: false,
          reason: `reportedOrigin resolves to reserved address ${a.address}`,
        };
      }
    }
    // Pick the first validated address as the pin target. Every address
    // in `addresses` has already been verified public/reserved-safe above.
    pinnedAddress = addresses[0]!.address;
  } catch {
    return { ok: false, reason: "reportedOrigin DNS lookup threw" };
  }

  // 4. Declared digest sanity: 64 lowercase hex chars.
  const normalizedDeclared = declaredDigest.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalizedDeclared)) {
    return { ok: false, reason: "declaredDigest is not a 64-char hex sha256" };
  }

  // 5. Fetch with timeout, size cap, no redirects.
  //
  // Sol MAJOR-4: pin the connection to the DNS address that already
  // passed the private/reserved check (defeats DNS rebinding). We use
  // undici with a per-request Agent whose `connect` forces `hostname`
  // to the pinned IP. `servername` is left unset so TLS SNI + cert
  // validation continue to run against `url.hostname` — the fetch
  // refuses when the presented certificate does not name the reported
  // origin, and cannot silently talk to a different host.
  //
  // Sol MAJOR-4: the 5-second abort deadline stays active THROUGH the
  // complete body read. An attacker holding the TCP connection open by
  // trickling bytes cannot stall this call past REQUEST_TIMEOUT_MS —
  // the controller.abort() will surface as a body-read error.
  const manifestUrl = `${url.origin}${MANIFEST_PATH}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  // A per-call Agent avoids leaking sockets and keeps the pin scoped
  // to THIS request. We install a custom `connector` that hard-overrides
  // the `hostname` field on the socket-connect callback with the
  // already-validated `pinnedAddress` — but leaves `servername` (SNI)
  // and the HTTP Host header intact so TLS certificate validation
  // continues to check the reported origin. A DNS response that later
  // flips to a private IP cannot influence this fetch; the socket
  // connects to the pre-validated IP even if the OS resolver would
  // have chosen something different.
  const baseConnect = buildConnector();
  const pinnedConnector: buildConnector.connector = (options, callback) => {
    baseConnect(
      {
        ...options,
        // `hostname` is the field the socket layer resolves and dials.
        hostname: pinnedAddress!,
      },
      callback,
    );
  };
  const dispatcher = new Agent({ connect: pinnedConnector });
  let res: Awaited<ReturnType<typeof undiciFetch>>;
  try {
    res = await undiciFetch(manifestUrl, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      dispatcher,
      // Some Node fetches allow overriding — set Accept for hygiene only.
      headers: { Accept: "application/json" },
    });
  } catch {
    clearTimeout(timer);
    try {
      await dispatcher.close();
    } catch {
      // best-effort
    }
    return { ok: false, reason: "fetch threw" };
  }
  if (!res.ok) {
    clearTimeout(timer);
    try {
      await dispatcher.close();
    } catch {
      // best-effort
    }
    return { ok: false, reason: `fetch returned status ${res.status}` };
  }
  // Enforce max size — read as bytes and abort if larger than MAX_BYTES.
  // The abort timer remains armed throughout — a slow trickle attack
  // trips it inside `reader.read()` and short-circuits with a bounded
  // failure rather than hanging.
  const reader = res.body?.getReader();
  if (!reader) {
    clearTimeout(timer);
    try {
      await dispatcher.close();
    } catch {
      // best-effort
    }
    return { ok: false, reason: "response body has no reader" };
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  let bodyOk = false;
  try {
    while (true) {
      let done = false;
      let value: Uint8Array | undefined;
      try {
        const chunk = await reader.read();
        done = chunk.done;
        value = chunk.value;
      } catch {
        return { ok: false, reason: "response body read threw" };
      }
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // best-effort
        }
        return { ok: false, reason: "response exceeded 64KB" };
      }
      chunks.push(value);
    }
    bodyOk = true;
  } finally {
    // Only clear the abort timer AFTER body consumption completes (or
    // errors). Closing the dispatcher tears down the pinned socket.
    clearTimeout(timer);
    try {
      await dispatcher.close();
    } catch {
      // best-effort
    }
  }
  if (!bodyOk) {
    // Defence in depth — the loop above returns on every error path.
    return { ok: false, reason: "response body did not complete" };
  }
  const bytes = concatBytes(chunks, total);

  // Parse, canonicalize, digest, compare, and extract as one fail-closed
  // operation. The SDK computes the same canonical JSON digest from its
  // in-memory manifest, so harmless whitespace or object-key ordering in the
  // published file cannot break origin binding.
  return bindWellKnownManifestBytes(bytes, normalizedDeclared);
}

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * Deterministic sorted-key JSON shared by the manifest digest protocol.
 * `JSON.stringify`/parse first applies ordinary JSON semantics (including
 * dropping undefined object fields) before recursive key sorting.
 */
export function canonicalizeManifestJson(value: unknown): string {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new TypeError("manifest is not JSON-serializable");
  }
  return canonicalizeJsonValue(JSON.parse(json) as JsonValue);
}

function canonicalizeJsonValue(value: JsonValue): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJsonValue).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonicalizeJsonValue(value[key]!)}`,
    )
    .join(",")}}`;
}

export function canonicalManifestSha256Hex(value: unknown): string {
  return createHash("sha256")
    .update(canonicalizeManifestJson(value))
    .digest("hex");
}

/**
 * Testable, network-independent half of origin binding. Invalid UTF-8,
 * invalid/non-object JSON, a malformed digest, or any digest mismatch fails
 * closed. Extraction happens only after the canonical digest has matched.
 */
export function bindWellKnownManifestBytes(
  bytes: Uint8Array,
  declaredDigest: string,
): OriginBindResult {
  const normalizedDeclared = declaredDigest.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalizedDeclared)) {
    return { ok: false, reason: "declaredDigest is not a 64-char hex sha256" };
  }

  let parsed: Record<string, unknown>;
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(decoded) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, reason: "fetched manifest is not a JSON object" };
    }
    parsed = value as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "fetched manifest is not valid UTF-8 JSON" };
  }

  const fetchedDigest = canonicalManifestSha256Hex(parsed);
  const actual = Buffer.from(fetchedDigest, "hex");
  const expected = Buffer.from(normalizedDeclared, "hex");
  if (
    actual.length !== expected.length ||
    !timingSafeEqual(actual, expected)
  ) {
    return {
      ok: false,
      reason: "fetched manifest digest does not match declared digest",
    };
  }

  const manifest: NonNullable<OriginBindResult["manifest"]> = {
    name: typeof parsed.name === "string" ? parsed.name : undefined,
    appId:
      typeof parsed.app_id === "string"
        ? parsed.app_id
        : typeof parsed.appId === "string"
          ? parsed.appId
          : undefined,
    manifestId:
      typeof parsed.manifest_id === "string"
        ? parsed.manifest_id
        : typeof parsed.manifestId === "string"
          ? parsed.manifestId
          : undefined,
    prefix:
      typeof parsed.prefix === "string"
        ? parsed.prefix
        : typeof parsed.app_id === "string"
          ? parsed.app_id
          : undefined,
    defaultSpace:
      typeof parsed.space === "string" ? parsed.space : undefined,
    declaredSecrets: extractDeclaredSecrets(parsed.secrets),
    declaredPermissions: extractDeclaredPermissions(parsed.permissions),
  };

  return { ok: true, manifest, fetchedDigest };
}

/**
 * Sol MAJOR-2: extract `{ secretName, scope, actions }` triples from a
 * manifest `secrets` block. The shape mirrors js-sdk's
 * `ManifestSecretActions`:
 *
 * ```
 * secrets: {
 *   MY_KEY: true                                // implicit "read", global scope
 *   MY_KEY: "read"                              // single action, global scope
 *   MY_KEY: ["read", "put"]                     // multiple actions, global scope
 *   MY_KEY: { scope: "listen", actions: [...] } // scoped
 * }
 * ```
 *
 * Any entry we cannot confidently parse is DROPPED (fail-closed: the
 * widget will treat the corresponding grant as sensitive rather than
 * inventing app-scope-normal semantics from a shape we don't recognize).
 */
function extractDeclaredSecrets(input: unknown): DeclaredScopedSecret[] | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) return undefined;
  const out: DeclaredScopedSecret[] = [];
  for (const [key, raw] of Object.entries(input as Record<string, unknown>)) {
    if (typeof key !== "string" || key.length === 0) continue;
    if (raw === true) {
      out.push({ secretName: key, actions: ["read"] });
      continue;
    }
    if (typeof raw === "string" && raw.length > 0) {
      out.push({ secretName: key, actions: [raw] });
      continue;
    }
    if (Array.isArray(raw) && raw.every((a) => typeof a === "string")) {
      out.push({ secretName: key, actions: raw as string[] });
      continue;
    }
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      const obj = raw as Record<string, unknown>;
      const nameRaw = typeof obj.name === "string" && obj.name.length > 0 ? obj.name : key;
      const scopeRaw = typeof obj.scope === "string" && obj.scope.length > 0 ? obj.scope : undefined;
      let actions: string[] | null = null;
      // Match js-sdk ManifestSecretActions exactly: an object that omits
      // `actions` defaults to read.
      if (obj.actions === undefined) {
        actions = ["read"];
      } else if (typeof obj.actions === "string" && obj.actions.length > 0) {
        actions = [obj.actions];
      } else if (Array.isArray(obj.actions) && obj.actions.every((a) => typeof a === "string")) {
        actions = obj.actions as string[];
      }
      if (!actions || actions.length === 0) continue;
      out.push({ secretName: nameRaw, scope: scopeRaw, actions });
    }
  }
  return out.length > 0 ? out : undefined;
}

/**
 * Sol MAJOR-2: extract declared permission entries from a manifest
 * `permissions` array. Each entry must at minimum carry a `service`,
 * `path`, and non-empty `actions` array; anything else is dropped.
 */
function extractDeclaredPermissions(input: unknown): DeclaredPermission[] | undefined {
  if (!Array.isArray(input)) return undefined;
  const out: DeclaredPermission[] = [];
  for (const raw of input) {
    if (!raw || typeof raw !== "object") continue;
    const obj = raw as Record<string, unknown>;
    if (typeof obj.service !== "string" || obj.service.length === 0) continue;
    if (typeof obj.path !== "string") continue;
    if (!Array.isArray(obj.actions) || obj.actions.length === 0) continue;
    if (!obj.actions.every((a) => typeof a === "string" && a.length > 0)) continue;
    out.push({
      service: obj.service,
      space: typeof obj.space === "string" && obj.space.length > 0 ? obj.space : undefined,
      path: obj.path,
      actions: obj.actions as string[],
    });
  }
  return out.length > 0 ? out : undefined;
}

function concatBytes(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

function isLiterallyPrivateHostname(host: string): boolean {
  const lower = host.toLowerCase();
  if (lower === "localhost") return true;
  if (lower.endsWith(".localhost")) return true;
  // Bracketed IPv6.
  const bare = lower.startsWith("[") && lower.endsWith("]") ? lower.slice(1, -1) : lower;
  if (bare === "::1") return true;
  // The rest is handled by dns.lookup + isPrivateOrReservedAddress.
  return false;
}

function isPrivateOrReservedAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return isPrivateIPv4(address);
  if (family === 6) return isPrivateIPv6(address);
  // Non-IP → treat as unresolvable, err on the side of blocking.
  return true;
}

function isPrivateIPv4(address: string): boolean {
  const parts = address.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  // Length checked above — safe to non-null assert.
  const a = parts[0]!;
  const b = parts[1]!;
  const c = parts[2]!;
  // 0.0.0.0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 100.64/10,
  // 192.0.0/24, 192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4,
  // 240/4, 255.255.255.255.
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224 && a <= 239) return true;
  if (a >= 240) return true;
  return false;
}

function isPrivateIPv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  // fe80::/10 link-local, fc00::/7 unique-local, ::ffff:/96 IPv4-mapped,
  // 64:ff9b::/96 well-known translation prefix, ff00::/8 multicast.
  if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (lower.startsWith("::ffff:")) return true;
  if (lower.startsWith("64:ff9b:")) return true;
  if (lower.startsWith("ff")) return true;
  return false;
}
