// SSRF-guarded fetch for the app's well-known OpenKey manifest.
//
// Used by /authorize-sign-prepare so it can OPTIONALLY upgrade the
// presentation-envelope trust label from `unsigned` to `origin-bound` when:
//   1. The widget reported an https origin as the browser-verified parent.
//   2. That origin serves `.well-known/openkey-manifest.json` over https.
//   3. The canonical SHA-256 of the fetched bytes matches the envelope's
//      `manifestDigest` field.
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

const MANIFEST_PATH = "/.well-known/openkey-manifest.json";
const REQUEST_TIMEOUT_MS = 5_000;
const MAX_BYTES = 64 * 1024;

export interface OriginBindResult {
  ok: boolean;
  /** Only present when ok=true. */
  manifest?: {
    name?: string;
    appId?: string;
    manifestId?: string;
  };
  /** Only present when ok=true. The canonical hex SHA-256 of the fetched bytes. */
  fetchedDigest?: string;
  /** Debug/log reason for failure (never surfaced to the caller). */
  reason?: string;
}

/**
 * Attempt to origin-bind the caller-reported origin against a declared
 * manifest digest. Returns `{ ok: true }` only when every guard passes and
 * the fetched bytes' SHA-256 matches `declaredDigest` (case-insensitive
 * hex compare, constant-time).
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
  } catch {
    return { ok: false, reason: "reportedOrigin DNS lookup threw" };
  }

  // 4. Declared digest sanity: 64 lowercase hex chars.
  const normalizedDeclared = declaredDigest.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalizedDeclared)) {
    return { ok: false, reason: "declaredDigest is not a 64-char hex sha256" };
  }

  // 5. Fetch with timeout, size cap, no redirects.
  const manifestUrl = `${url.origin}${MANIFEST_PATH}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(manifestUrl, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      // Some Node fetches allow overriding — set Accept for hygiene only.
      headers: { Accept: "application/json" },
    });
  } catch {
    clearTimeout(timer);
    return { ok: false, reason: "fetch threw" };
  }
  clearTimeout(timer);
  if (!res.ok) {
    return { ok: false, reason: `fetch returned status ${res.status}` };
  }
  // Enforce max size — read as bytes and abort if larger than MAX_BYTES.
  const reader = res.body?.getReader();
  if (!reader) return { ok: false, reason: "response body has no reader" };
  const chunks: Uint8Array[] = [];
  let total = 0;
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
  const bytes = concatBytes(chunks, total);

  // 6. Compute canonical digest of the exact bytes.
  const fetchedDigest = createHash("sha256").update(bytes).digest("hex");

  // 7. Constant-time compare against the declared digest.
  const a = Buffer.from(fetchedDigest, "hex");
  const b = Buffer.from(normalizedDeclared, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return {
      ok: false,
      reason: "fetched manifest digest does not match declared digest",
    };
  }

  // 8. Best-effort parse of the manifest for display-only fields. Failure
  //    to parse is not fatal — we already have a matching digest, which is
  //    what the trust decision hinges on.
  let manifest: OriginBindResult["manifest"];
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8").decode(bytes)) as Record<
      string,
      unknown
    >;
    manifest = {
      name: typeof parsed.name === "string" ? parsed.name : undefined,
      appId: typeof parsed.app_id === "string"
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
    };
  } catch {
    manifest = {};
  }

  return { ok: true, manifest, fetchedDigest };
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
