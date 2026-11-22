// TC-3893: registry-change record builder, node URL canonicaliser, SSRF-safe identity
// probe (warn-only), and direct v2 registry reader/publisher.
//
// Direct PUT is used instead of `publishLocationRecordV2` so unreachable or mismatched
// nodes warn on the consent screen without blocking sovereign approval, while keeping
// every safety guard: strict URL canonicalisation, node/space caps, DNS-based SSRF
// filtering before probing, bounded probe concurrency, location-registry v2 validation,
// never dropping unrelated spaces, re-read drift check before signing, and verifying
// that the registry's accepted record matches the signed prepared bytes.

import { createHash } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import {
  DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL,
  LocationRecordValidationError,
  canonicalLocationPayloadV2,
  exactHttpOrigin,
  registryOwnerKeyV2,
  signLocationRecordV2,
  validateLocationRecordV2,
  validateLocationRecordV2Payload,
  verifyLocationRecordV2,
  type LocationRecordSigner,
  type LocationRecordV2,
  type LocationRecordV2Payload,
} from '@tinycloud/sdk-core';
import { boundedResponseBytes } from '@tinycloud/sdk-core/registry-publication';

const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;
const REGISTRY_TIMEOUT_MS = 5_000;
const NODE_IDENTITY_TIMEOUT_MS = 5_000;
const MAX_REGISTRY_BYTES = 64 * 1024;
const MAX_NODE_IDENTITY_BYTES = 16 * 1024;

/** F1 caps: enforced before any DNS lookup or network probe. */
export const MAX_REGISTRY_CHANGE_NODES = 16;
export const MAX_REGISTRY_CHANGE_SPACES = 64;
export const MAX_IDENTITY_PROBE_CONCURRENCY = 4;

export interface RegistryChangeNodeInput {
  url: string;
  did?: string;
}

export interface RegistryChangeSpaceNodeInput {
  url: string;
  mode?: 'read-write' | 'read-only';
}

export interface RegistryChangeSpaceInput {
  space: string;
  nodes: RegistryChangeSpaceNodeInput[];
}

export interface RegistryChangeRequestInput {
  nodes: RegistryChangeNodeInput[];
  spaces?: RegistryChangeSpaceInput[];
  encryptionNode?: string | null;
}

export type NodeIdentityStatus = 'ok' | 'mismatch' | 'unreachable';

export interface NodeIdentityResult {
  readonly url: string;
  readonly did: string | null;
  readonly status: NodeIdentityStatus;
}

export type HostResolver = (hostname: string) => Promise<string[]>;

export class RegistryChangeError extends Error {
  readonly status: 400 | 409 | 422 | 502;
  readonly host?: string;
  constructor(public readonly code: string, message: string, status: 400 | 409 | 422 | 502, host?: string) {
    super(message);
    this.name = 'RegistryChangeError';
    this.status = status;
    if (host !== undefined) this.host = host;
  }
}

/**
 * Canonicalise a node URL to `scheme://host[:port]` (exactHttpOrigin-style).
 * Accepts HTTPS origins and loopback HTTP (`127.0.0.1`, `[::1]`) only; strips default
 * ports and optional trailing slash; rejects credentials, paths, queries, fragments,
 * non-ASCII, and unparseable URLs. Raw IPv4, IPv6, and non-default ports are preserved.
 */
export function canonicalNodeUrl(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0 || !PRINTABLE_ASCII.test(trimmed)) return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  const isLoopback = url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    return null;
  }
  if (url.username !== '' || url.password !== '' || url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    return null;
  }
  if (!url.origin || url.origin === 'null') return null;
  return url.origin;
}

/** Canonical host for display (includes non-default port, raw IPv4, bracketed IPv6). */
export function displayNodeHost(canonicalUrl: string): string {
  try {
    return new URL(canonicalUrl).host;
  } catch {
    return canonicalUrl;
  }
}

/** Validate a candidate Ed25519 did:key using sdk-core's exact v2 validator. */
export function isValidV2NodeDid(did: unknown): did is string {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) return false;
  try {
    validateLocationRecordV2Payload({
      version: 2,
      subject: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
      nodes: [{ did, url: 'https://node.example' }],
      spaces: [],
      encryptionNode: null,
      updated_at: '2026-01-01T00:00:00.000Z',
      sequence: 0,
    });
    return true;
  } catch {
    return false;
  }
}

function parseIpv4Octets(ip: string): [number, number, number, number] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => (/^\d+$/.test(p) ? Number(p) : -1));
  if (nums.some((n) => n < 0 || n > 255)) return null;
  return nums as [number, number, number, number];
}

function expandIpv6Groups(raw: string): number[] | null {
  let ip = raw.toLowerCase();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) ip = ip.slice(0, zoneIdx);

  // Convert embedded IPv4 tail (e.g. ::ffff:169.254.169.254) into two 16-bit hex groups.
  const lastColon = ip.lastIndexOf(':');
  if (lastColon !== -1 && ip.slice(lastColon + 1).includes('.')) {
    const octets = parseIpv4Octets(ip.slice(lastColon + 1));
    if (!octets) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    ip = `${ip.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (side === '') return [];
    const tokens = side.split(':');
    const out: number[] = [];
    for (const token of tokens) {
      if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
      out.push(Number.parseInt(token, 16));
    }
    return out;
  };

  const left = parseSide(halves[0]!);
  const right = halves.length === 2 ? parseSide(halves[1]!) : [];
  if (!left || !right) return null;

  if (halves.length === 1) {
    return left.length === 8 ? left : null;
  }
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function isBlockedIpv4(octets: [number, number, number, number], allowLoopback: boolean): boolean {
  const [a, b, c] = octets;
  // Loopback 127.0.0.0/8
  if (a === 127) return !allowLoopback;
  // Unspecified 0.0.0.0/8
  if (a === 0) return true;
  // RFC1918 private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  // CGNAT 100.64.0.0/10
  if (a === 100 && b >= 64 && b <= 127) return true;
  // Link-local & cloud metadata 169.254.0.0/16 (incl. 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // IETF Protocol Assignments 192.0.0.0/24
  if (a === 192 && b === 0 && c === 0) return true;
  // Benchmarking 198.18.0.0/15
  if (a === 198 && (b === 18 || b === 19)) return true;
  // Multicast (224.0.0.0/4), reserved (240.0.0.0/4), and limited broadcast (255.255.255.255)
  if (a >= 224) return true;
  return false;
}

function ipv4OctetsFromHexGroups(hi: number, lo: number): [number, number, number, number] {
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
}

/**
 * F1 + N3 SSRF filter: returns true when `ip` is loopback (unless `allowLoopback`),
 * private (RFC1918/ULA), link-local, CGNAT, IETF 192.0.0.0/24, benchmarking 198.18.0.0/15,
 * metadata (`169.254.169.254`, `fd00:ec2::254`), unspecified, multicast, reserved (240/4),
 * limited broadcast (255.255.255.255), or an IPv6 address embedding a blocked IPv4 via
 * `::/96`, `::ffff:0:0/96`, `::ffff:0:0:0/96`, `64:ff9b::/96` (NAT64), or `2002::/16` (6to4).
 */
export function isBlockedProbeIp(rawIp: string, allowLoopback: boolean): boolean {
  const ip = rawIp.startsWith('[') && rawIp.endsWith(']') ? rawIp.slice(1, -1) : rawIp;
  const kind = isIP(ip);
  if (kind === 4) {
    const octets = parseIpv4Octets(ip);
    return !octets || isBlockedIpv4(octets, allowLoopback);
  }
  if (kind === 6) {
    const groups = expandIpv6Groups(ip);
    if (!groups) return true;
    const allZero = groups.every((g) => g === 0);
    if (allZero) return true; // :: unspecified
    const isLoopback6 = groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1;
    if (isLoopback6) return !allowLoopback; // ::1
    // IPv4-compatible ::/96 (after :: and ::1 handled above)
    if (groups.slice(0, 6).every((g) => g === 0)) {
      return isBlockedIpv4(ipv4OctetsFromHexGroups(groups[6]!, groups[7]!), allowLoopback);
    }
    // IPv4-mapped ::ffff:0:0/96
    if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
      return isBlockedIpv4(ipv4OctetsFromHexGroups(groups[6]!, groups[7]!), allowLoopback);
    }
    // IPv4-translated ::ffff:0:0:0/96 (RFC 2765)
    if (groups.slice(0, 4).every((g) => g === 0) && groups[4] === 0xffff && groups[5] === 0) {
      return isBlockedIpv4(ipv4OctetsFromHexGroups(groups[6]!, groups[7]!), allowLoopback);
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)
    if (groups[0] === 0x0064 && groups[1] === 0xff9b && groups.slice(2, 6).every((g) => g === 0)) {
      return isBlockedIpv4(ipv4OctetsFromHexGroups(groups[6]!, groups[7]!), allowLoopback);
    }
    // 6to4 2002::/16 (RFC 3056 — embedded IPv4 in bits 16-47 = groups[1..2])
    if (groups[0] === 0x2002) {
      return isBlockedIpv4(ipv4OctetsFromHexGroups(groups[1]!, groups[2]!), allowLoopback);
    }
    // Unique local fc00::/7 (includes fd00:ec2::254 AWS IMDSv2 IPv6 metadata)
    if ((groups[0]! & 0xfe00) === 0xfc00) return true;
    // Link-local fe80::/10
    if ((groups[0]! & 0xffc0) === 0xfe80) return true;
    // Deprecated site-local fec0::/10 (RFC 3879)
    if ((groups[0]! & 0xffc0) === 0xfec0) return true;
    // Multicast ff00::/8
    if ((groups[0]! & 0xff00) === 0xff00) return true;
    return false;
  }
  // Unrecognised address format -> fail closed (block probe).
  return true;
}

export async function defaultHostResolver(hostname: string): Promise<string[]> {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (isIP(bare) !== 0) return [bare];
  const entries = await dnsLookup(bare, { all: true, verbatim: true });
  return entries.map((e) => e.address);
}

async function isHostAllowedForProbe(
  canonicalUrl: string,
  allowLoopback: boolean,
  resolveHost: HostResolver,
): Promise<boolean> {
  let hostname: string;
  try {
    hostname = new URL(canonicalUrl).hostname;
  } catch {
    return false;
  }
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (isIP(bare) !== 0) {
    return !isBlockedProbeIp(bare, allowLoopback);
  }
  let addresses: string[];
  try {
    addresses = await resolveHost(bare);
  } catch {
    return false;
  }
  if (addresses.length === 0) return false;
  return addresses.every((addr) => !isBlockedProbeIp(addr, allowLoopback));
}

async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(Math.max(1, limit), items.length);
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (nextIndex < items.length) {
        const currentIndex = nextIndex++;
        results[currentIndex] = await fn(items[currentIndex]!, currentIndex);
      }
    }),
  );
  return results;
}

async function fetchJsonBounded(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  maxBytes: number,
): Promise<{ ok: true; status: number; body: unknown } | { ok: false; status: number | null }> {
  try {
    const response = await fetchImpl(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.redirected) return { ok: false, status: response.status };
    const bytes = await boundedResponseBytes(response, maxBytes);
    if (bytes === null) return { ok: false, status: response.status };
    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      return { ok: false, status: response.status };
    }
    return { ok: true, status: response.status, body };
  } catch {
    return { ok: false, status: null };
  }
}

export interface NodeIdentityProbeOptions {
  readonly fetch?: typeof fetch;
  readonly resolveHost?: HostResolver;
  readonly allowLoopback?: boolean;
}

/**
 * Resolve host and check SSRF filter, then probe `{url}/info` and
 * `{url}/.well-known/tinycloud/node-keys` in parallel (no redirects).
 * Returns `ok | mismatch | unreachable` — warning only, never blocks.
 */
export async function checkNodeIdentity(
  canonicalUrl: string,
  expectedDid?: string,
  opts: NodeIdentityProbeOptions = {},
): Promise<NodeIdentityResult> {
  const fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const resolveHost = opts.resolveHost ?? defaultHostResolver;
  const allowLoopback = opts.allowLoopback ?? false;

  const allowed = await isHostAllowedForProbe(canonicalUrl, allowLoopback, resolveHost);
  if (!allowed) {
    return { url: canonicalUrl, did: expectedDid ?? null, status: 'unreachable' };
  }

  const [infoRes, keysRes] = await Promise.all([
    fetchJsonBounded(`${canonicalUrl}/info`, fetchImpl, NODE_IDENTITY_TIMEOUT_MS, MAX_NODE_IDENTITY_BYTES),
    fetchJsonBounded(`${canonicalUrl}/.well-known/tinycloud/node-keys`, fetchImpl, NODE_IDENTITY_TIMEOUT_MS, MAX_NODE_IDENTITY_BYTES),
  ]);

  const infoOk = infoRes.ok && infoRes.status >= 200 && infoRes.status < 300
    && typeof infoRes.body === 'object' && infoRes.body !== null && !Array.isArray(infoRes.body);
  const keysOk = keysRes.ok && keysRes.status >= 200 && keysRes.status < 300
    && typeof keysRes.body === 'object' && keysRes.body !== null && !Array.isArray(keysRes.body);

  if (!infoOk && !keysOk) {
    return { url: canonicalUrl, did: expectedDid ?? null, status: 'unreachable' };
  }

  const infoDid = infoOk ? (infoRes.body as Record<string, unknown>).nodeId : undefined;
  const keysDid = keysOk ? (keysRes.body as Record<string, unknown>).nodeDid : undefined;
  const infoValid = isValidV2NodeDid(infoDid) ? infoDid : null;
  const keysValid = isValidV2NodeDid(keysDid) ? keysDid : null;

  // Both endpoints answered cleanly with matching valid Ed25519 DIDs.
  if (infoOk && keysOk && infoValid && keysValid && infoValid === keysValid) {
    if (expectedDid !== undefined) {
      return expectedDid === infoValid
        ? { url: canonicalUrl, did: expectedDid, status: 'ok' }
        : { url: canonicalUrl, did: expectedDid, status: 'mismatch' };
    }
    return { url: canonicalUrl, did: infoValid, status: 'ok' };
  }

  const observedDid = infoValid ?? keysValid;
  if (!infoOk || !keysOk) {
    if (expectedDid !== undefined && observedDid !== null && observedDid !== expectedDid) {
      return { url: canonicalUrl, did: expectedDid, status: 'mismatch' };
    }
    return { url: canonicalUrl, did: expectedDid ?? observedDid, status: 'unreachable' };
  }

  // Both endpoints answered 2xx JSON, but DIDs disagreed or were malformed.
  return { url: canonicalUrl, did: expectedDid ?? observedDid, status: 'mismatch' };
}

/**
 * Read and cryptographically verify the owner's current v2 location record from the registry.
 * Returns `null` only on the canonical 404 absence response.
 */
export async function readCurrentLocationRecordV2(options: {
  registryUrl?: string;
  subject: string;
  fetch?: typeof fetch;
}): Promise<LocationRecordV2 | null> {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const registryOrigin = exactHttpOrigin(options.registryUrl ?? DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL, 'registry URL');
  const ownerKey = registryOwnerKeyV2(options.subject);
  const endpoint = `${registryOrigin}/v2/locations/${encodeURIComponent(ownerKey)}`;

  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'GET',
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
    });
  } catch {
    throw new RegistryChangeError('registry_unavailable', 'Could not reach the location registry', 502);
  }
  if (response.redirected) {
    throw new RegistryChangeError('registry_unavailable', 'Registry lookup cannot follow a redirect', 502);
  }
  if (response.status !== 200 && response.status !== 404) {
    throw new RegistryChangeError('registry_unavailable', `Registry lookup returned HTTP ${response.status}`, 502);
  }
  const bytes = await boundedResponseBytes(response, MAX_REGISTRY_BYTES);
  if (bytes === null) {
    throw new RegistryChangeError('registry_unavailable', 'Registry response exceeds 64 KiB', 502);
  }
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new RegistryChangeError('registry_unavailable', 'Registry response is not valid JSON', 502);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new RegistryChangeError('registry_unavailable', 'Registry response must be an object', 502);
  }
  if (response.status === 404) {
    const obj = body as Record<string, unknown>;
    if (Object.keys(obj).length !== 1 || obj.error !== 'location record not found') {
      throw new RegistryChangeError('registry_unavailable', 'Registry 404 is not canonical owner absence', 502);
    }
    return null;
  }
  if (!('record' in body)) {
    throw new RegistryChangeError('registry_unavailable', 'Registry response is missing its record', 502);
  }
  let record: LocationRecordV2;
  try {
    record = validateLocationRecordV2((body as { record: unknown }).record);
  } catch {
    throw new RegistryChangeError('registry_unavailable', 'Registry record failed v2 validation', 502);
  }
  if (registryOwnerKeyV2(record.subject) !== ownerKey || !await verifyLocationRecordV2(record)) {
    throw new RegistryChangeError('registry_unavailable', 'Registry record does not verify for this owner', 502);
  }
  return record;
}

export interface PreparedRegistryChange {
  readonly before: LocationRecordV2Payload;
  readonly after: LocationRecordV2Payload;
  readonly beforeHash: string;
  readonly recordHash: string;
  readonly payloadCanonical: string;
  readonly identity: NodeIdentityResult[];
  readonly encryptionChanged: boolean;
}

export function payloadWithoutSignature(record: LocationRecordV2): LocationRecordV2Payload {
  return {
    version: record.version,
    subject: record.subject,
    nodes: record.nodes.map(({ did, url }) => ({ did, url })),
    spaces: record.spaces.map(({ space, nodes }) => ({
      space,
      nodes: nodes.map(({ did, mode }) => ({ did, mode })),
    })),
    encryptionNode: record.encryptionNode,
    updated_at: record.updated_at,
    sequence: record.sequence,
  };
}

/**
 * Validate caps + request shape before any registry or node network call (F1).
 */
export function validateRequestBounds(request: unknown): {
  nodes: Array<{ url: string; did?: string }>;
  rawSpaces: unknown[] | undefined;
  rawEncryptionNode: unknown;
} {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new RegistryChangeError('registry_change_invalid_node', 'Request must be an object', 400);
  }
  const rawReq = request as Record<string, unknown>;
  if (!Array.isArray(rawReq.nodes) || rawReq.nodes.length === 0) {
    throw new RegistryChangeError('registry_change_invalid_node', 'At least one node is required', 400);
  }
  if (rawReq.nodes.length > MAX_REGISTRY_CHANGE_NODES) {
    throw new RegistryChangeError(
      'registry_change_too_many_nodes',
      `At most ${MAX_REGISTRY_CHANGE_NODES} nodes may be requested at once`,
      400,
    );
  }
  if (rawReq.spaces !== undefined) {
    if (!Array.isArray(rawReq.spaces)) {
      throw new RegistryChangeError('registry_change_invalid_node', 'spaces must be an array', 400);
    }
    if (rawReq.spaces.length > MAX_REGISTRY_CHANGE_SPACES) {
      throw new RegistryChangeError(
        'registry_change_too_many_spaces',
        `At most ${MAX_REGISTRY_CHANGE_SPACES} spaces may be requested at once`,
        400,
      );
    }
  }

  const parsedNodes: Array<{ url: string; did?: string }> = [];
  const seenUrls = new Set<string>();
  for (const item of rawReq.nodes) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new RegistryChangeError('registry_change_invalid_node', 'Each node must be an object', 400);
    }
    const nodeObj = item as Record<string, unknown>;
    const canonicalUrl = canonicalNodeUrl(nodeObj.url);
    if (!canonicalUrl) {
      throw new RegistryChangeError('registry_change_invalid_node', 'Node URL could not be parsed as a canonical HTTP(S) origin', 400);
    }
    if (seenUrls.has(canonicalUrl)) {
      throw new RegistryChangeError('registry_change_invalid_node', 'Duplicate node URL in request', 400);
    }
    seenUrls.add(canonicalUrl);
    let did: string | undefined;
    if (nodeObj.did !== undefined) {
      if (!isValidV2NodeDid(nodeObj.did)) {
        throw new RegistryChangeError('registry_change_invalid_node', 'Node DID must be a canonical Ed25519 did:key', 400);
      }
      did = nodeObj.did;
    }
    parsedNodes.push(did !== undefined ? { url: canonicalUrl, did } : { url: canonicalUrl });
  }

  return {
    nodes: parsedNodes,
    rawSpaces: rawReq.spaces as unknown[] | undefined,
    rawEncryptionNode: rawReq.encryptionNode,
  };
}

/**
 * Validate + canonicalise the caller's request, probe node identities (SSRF-filtered,
 * bounded concurrency <= 4, warn-only), merge with `current` without dropping unrelated
 * spaces, set `sequence = current + 1` and `updated_at = now`, and validate against
 * location-registry v2 rules.
 */
export async function prepareRegistryChangeRecord(options: {
  current: LocationRecordV2;
  request: unknown;
  now: Date;
  fetch?: typeof fetch;
  resolveHost?: HostResolver;
  allowLoopback?: boolean;
}): Promise<PreparedRegistryChange> {
  const { current, now } = options;
  const { nodes: parsedNodes, rawSpaces, rawEncryptionNode } = validateRequestBounds(options.request);

  // Probe node identities with bounded concurrency <= 4 (SSRF-filtered, warn-only).
  const currentByUrl = new Map(current.nodes.map((node) => [node.url, node]));
  const identity = await mapWithConcurrency(
    parsedNodes,
    MAX_IDENTITY_PROBE_CONCURRENCY,
    (node) =>
      checkNodeIdentity(node.url, node.did, {
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.resolveHost ? { resolveHost: options.resolveHost } : {}),
        ...(options.allowLoopback !== undefined ? { allowLoopback: options.allowLoopback } : {}),
      }),
  );

  const resolvedNodesByUrl = new Map<string, { url: string; did: string }>();
  for (let i = 0; i < parsedNodes.length; i++) {
    const reqNode = parsedNodes[i]!;
    const idResult = identity[i]!;
    const resolvedDid = reqNode.did ?? idResult.did ?? currentByUrl.get(reqNode.url)?.did ?? null;
    if (!resolvedDid || !isValidV2NodeDid(resolvedDid)) {
      const host = displayNodeHost(reqNode.url);
      throw new RegistryChangeError(
        'registry_change_node_did_required',
        `Couldn't reach ${host} to discover its node identity; provide node did or try again when reachable`,
        422,
        host,
      );
    }
    if (idResult.did === null) {
      identity[i] = { ...idResult, did: resolvedDid };
    }
    resolvedNodesByUrl.set(reqNode.url, { url: reqNode.url, did: resolvedDid });
  }

  // Merge spaces: preserve every existing space not mentioned in `request.spaces`.
  const spacesMap = new Map<string, { space: string; nodes: Array<{ did: string; mode: 'read-write' | 'read-only' }> }>(
    current.spaces.map(({ space, nodes }) => [
      space,
      { space, nodes: nodes.map((membership) => ({ ...membership })) },
    ]),
  );

  if (rawSpaces !== undefined) {
    for (const item of rawSpaces) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new RegistryChangeError('registry_change_invalid_node', 'Each space entry must be an object', 400);
      }
      const spaceObj = item as Record<string, unknown>;
      if (typeof spaceObj.space !== 'string' || spaceObj.space.length === 0 || !Array.isArray(spaceObj.nodes)) {
        throw new RegistryChangeError('registry_change_invalid_node', 'Each space entry must name a space and node list', 400);
      }
      const memberships: Array<{ did: string; mode: 'read-write' | 'read-only' }> = [];
      for (const ref of spaceObj.nodes) {
        if (!ref || typeof ref !== 'object' || Array.isArray(ref)) {
          throw new RegistryChangeError('registry_change_invalid_node', 'Space node reference must be an object', 400);
        }
        const refObj = ref as Record<string, unknown>;
        const canonicalUrl = canonicalNodeUrl(refObj.url);
        if (!canonicalUrl) {
          throw new RegistryChangeError('registry_change_invalid_node', 'Space node URL could not be parsed', 400);
        }
        const targetNode = resolvedNodesByUrl.get(canonicalUrl);
        if (!targetNode) {
          throw new RegistryChangeError('registry_change_invalid_node', 'Space node URL must reference a node in request.nodes', 400);
        }
        const mode = refObj.mode ?? 'read-write';
        if (mode !== 'read-write' && mode !== 'read-only') {
          throw new RegistryChangeError('registry_change_invalid_node', 'Space node mode must be read-write or read-only', 400);
        }
        memberships.push({ did: targetNode.did, mode });
      }
      spacesMap.set(spaceObj.space, { space: spaceObj.space, nodes: memberships });
    }
  } else {
    // No explicit `spaces` field: move all existing spaces to the requested nodes.
    const defaultMemberships = [...resolvedNodesByUrl.values()].map((node) => ({
      did: node.did,
      mode: 'read-write' as const,
    }));
    for (const spaceKey of spacesMap.keys()) {
      spacesMap.set(spaceKey, { space: spaceKey, nodes: defaultMemberships.map((m) => ({ ...m })) });
    }
  }

  // Resolve `encryptionNode` per pinned contract: canonical node URL matching request.nodes[].url, or null, or omitted (preserve).
  let encryptionNode: string | null;
  if (rawEncryptionNode === undefined) {
    encryptionNode = current.encryptionNode;
  } else if (rawEncryptionNode === null) {
    encryptionNode = null;
  } else if (typeof rawEncryptionNode === 'string') {
    const canonicalUrl = canonicalNodeUrl(rawEncryptionNode);
    if (!canonicalUrl) {
      throw new RegistryChangeError('registry_change_invalid_node', 'encryptionNode URL could not be parsed', 400);
    }
    const targetNode = resolvedNodesByUrl.get(canonicalUrl);
    if (!targetNode) {
      throw new RegistryChangeError('registry_change_invalid_node', 'encryptionNode must reference a node in request.nodes', 400);
    }
    encryptionNode = targetNode.did;
  } else {
    throw new RegistryChangeError('registry_change_invalid_node', 'encryptionNode must be a URL string or null', 400);
  }

  // Assemble the node table: all requested nodes, plus any existing nodes still referenced
  // by untouched spaces or an unchanged encryptionNode.
  const referencedDids = new Set<string>();
  for (const space of spacesMap.values()) {
    for (const membership of space.nodes) referencedDids.add(membership.did);
  }
  if (encryptionNode) referencedDids.add(encryptionNode);

  const finalNodesByDid = new Map<string, { did: string; url: string }>();
  for (const node of resolvedNodesByUrl.values()) {
    if (finalNodesByDid.has(node.did) && finalNodesByDid.get(node.did)!.url !== node.url) {
      throw new RegistryChangeError('registry_change_invalid_node', 'Duplicate node DID with conflicting URLs', 400);
    }
    finalNodesByDid.set(node.did, { did: node.did, url: node.url });
  }
  for (const existing of current.nodes) {
    if (referencedDids.has(existing.did) && !finalNodesByDid.has(existing.did)) {
      finalNodesByDid.set(existing.did, { did: existing.did, url: existing.url });
    }
  }

  let after: LocationRecordV2Payload;
  try {
    after = validateLocationRecordV2Payload({
      version: 2,
      subject: current.subject,
      nodes: [...finalNodesByDid.values()],
      spaces: [...spacesMap.values()],
      encryptionNode,
      updated_at: now.toISOString(),
      sequence: current.sequence + 1,
    });
  } catch (error) {
    if (error instanceof LocationRecordValidationError) {
      throw new RegistryChangeError('registry_change_invalid_node', error.message, 400);
    }
    throw error;
  }

  const before = payloadWithoutSignature(current);
  const beforeCanonical = canonicalLocationPayloadV2(before);
  const beforeHash = createHash('sha256').update(beforeCanonical, 'utf8').digest('hex');
  const payloadCanonical = canonicalLocationPayloadV2(after);
  const recordHash = createHash('sha256').update(payloadCanonical, 'utf8').digest('hex');

  const beforeNodeUrls = new Map(before.nodes.map((n) => [n.did, n.url]));
  const afterNodeUrls = new Map(after.nodes.map((n) => [n.did, n.url]));
  const prevEncUrl = before.encryptionNode ? beforeNodeUrls.get(before.encryptionNode) ?? null : null;
  const nextEncUrl = after.encryptionNode ? afterNodeUrls.get(after.encryptionNode) ?? null : null;
  const encryptionChanged = before.encryptionNode !== after.encryptionNode || prevEncUrl !== nextEncUrl;

  return {
    before,
    after,
    beforeHash,
    recordHash,
    payloadCanonical,
    identity,
    encryptionChanged,
  };
}

/**
 * TC-3893 (Bobbie restore-any-version): build an exact REPLACE payload from a stored
 * `previousRecord` (removing any spaces/nodes added by later changes), with
 * `sequence = current.sequence + 1` and `updated_at = now`.
 */
export async function prepareRegistryUndoRecord(options: {
  current: LocationRecordV2;
  previousRecord: unknown;
  now: Date;
  fetch?: typeof fetch;
  resolveHost?: HostResolver;
  allowLoopback?: boolean;
}): Promise<PreparedRegistryChange> {
  const { current, now } = options;

  let stored: LocationRecordV2Payload;
  try {
    stored = payloadWithoutSignature(validateLocationRecordV2(options.previousRecord));
  } catch {
    try {
      stored = validateLocationRecordV2Payload(options.previousRecord);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Stored previous record is invalid';
      throw new RegistryChangeError('registry_change_invalid_node', msg, 400);
    }
  }

  let after: LocationRecordV2Payload;
  try {
    after = validateLocationRecordV2Payload({
      version: 2,
      subject: current.subject,
      nodes: stored.nodes.map(({ did, url }) => ({ did, url })),
      spaces: stored.spaces.map(({ space, nodes }) => ({
        space,
        nodes: nodes.map(({ did, mode }) => ({ did, mode })),
      })),
      encryptionNode: stored.encryptionNode,
      updated_at: now.toISOString(),
      sequence: current.sequence + 1,
    });
  } catch (error) {
    if (error instanceof LocationRecordValidationError) {
      throw new RegistryChangeError('registry_change_invalid_node', error.message, 400);
    }
    throw error;
  }

  const identity = await mapWithConcurrency(
    after.nodes,
    MAX_IDENTITY_PROBE_CONCURRENCY,
    (node) =>
      checkNodeIdentity(node.url, node.did, {
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.resolveHost ? { resolveHost: options.resolveHost } : {}),
        ...(options.allowLoopback !== undefined ? { allowLoopback: options.allowLoopback } : {}),
      }),
  );

  const before = payloadWithoutSignature(current);
  const beforeCanonical = canonicalLocationPayloadV2(before);
  const beforeHash = createHash('sha256').update(beforeCanonical, 'utf8').digest('hex');
  const payloadCanonical = canonicalLocationPayloadV2(after);
  const recordHash = createHash('sha256').update(payloadCanonical, 'utf8').digest('hex');

  const beforeNodeUrls = new Map(before.nodes.map((n) => [n.did, n.url]));
  const afterNodeUrls = new Map(after.nodes.map((n) => [n.did, n.url]));
  const prevEncUrl = before.encryptionNode ? beforeNodeUrls.get(before.encryptionNode) ?? null : null;
  const nextEncUrl = after.encryptionNode ? afterNodeUrls.get(after.encryptionNode) ?? null : null;
  const encryptionChanged = before.encryptionNode !== after.encryptionNode || prevEncUrl !== nextEncUrl;

  return {
    before,
    after,
    beforeHash,
    recordHash,
    payloadCanonical,
    identity,
    encryptionChanged,
  };
}

/**
 * Sign the exact prepared payload, PUT it to the location registry, and verify that
 * the accepted record returned by the registry matches the signed prepared bytes.
 */
export async function publishSignedLocationRecordV2(options: {
  registryUrl?: string;
  payload: LocationRecordV2Payload;
  payloadCanonical: string;
  signer: LocationRecordSigner;
  fetch?: typeof fetch;
}): Promise<LocationRecordV2> {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const registryOrigin = exactHttpOrigin(options.registryUrl ?? DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL, 'registry URL');

  if (canonicalLocationPayloadV2(options.payload) !== options.payloadCanonical) {
    throw new RegistryChangeError('registry_publish_failed', 'Prepared payload does not match canonical bytes', 502);
  }

  const record = await signLocationRecordV2(options.payload, options.signer);
  const body = JSON.stringify(record);
  if (new TextEncoder().encode(JSON.stringify({ record, status: 'created' })).byteLength > MAX_REGISTRY_BYTES) {
    throw new RegistryChangeError('registry_publish_failed', 'Published record exceeds 64 KiB limit', 502);
  }

  const ownerKey = registryOwnerKeyV2(options.payload.subject);
  const endpoint = `${registryOrigin}/v2/locations/${encodeURIComponent(ownerKey)}`;

  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'PUT',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body,
      redirect: 'error',
      signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
    });
  } catch {
    throw new RegistryChangeError('registry_publish_failed', 'Could not reach the location registry', 502);
  }
  if (response.redirected) {
    throw new RegistryChangeError('registry_publish_failed', 'Registry publication cannot follow a redirect', 502);
  }
  if (response.status === 409) {
    throw new RegistryChangeError('registry_change_stale', 'Registry sequence changed before publication', 409);
  }
  if (response.status !== 200 && response.status !== 201) {
    throw new RegistryChangeError('registry_publish_failed', `Registry publication returned HTTP ${response.status}`, 502);
  }

  const bytes = await boundedResponseBytes(response, MAX_REGISTRY_BYTES);
  if (bytes === null) {
    throw new RegistryChangeError('registry_publish_failed', 'Registry publication response exceeds 64 KiB', 502);
  }
  let reply: unknown;
  try {
    reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new RegistryChangeError('registry_publish_failed', 'Registry publication response is not valid JSON', 502);
  }
  if (!reply || typeof reply !== 'object' || Array.isArray(reply) || !('record' in reply)) {
    throw new RegistryChangeError('registry_publish_failed', 'Registry publication response is missing its record', 502);
  }
  let accepted: LocationRecordV2;
  try {
    accepted = validateLocationRecordV2((reply as { record: unknown }).record);
  } catch {
    throw new RegistryChangeError('registry_publish_failed', 'Registry publication response failed v2 validation', 502);
  }
  if (
    canonicalLocationPayloadV2(accepted) !== options.payloadCanonical ||
    accepted.signature !== record.signature ||
    !await verifyLocationRecordV2(accepted)
  ) {
    throw new RegistryChangeError('registry_publish_failed', 'Registry publication response does not match the signed record', 502);
  }
  return accepted;
}
