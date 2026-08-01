// Parser that turns a raw request into a CapabilityReviewModel.
//
// Handles four input shapes:
//   1. TinyCloud SIWE with ReCap capabilities (editable)
//   2. Ordinary SIWE (no ReCap; not editable)
//   3. Plain text / arbitrary bytes (legacy signMessage)
//   4. Malformed input (returned with parseWarnings + safest-possible model)
//
// The parser NEVER throws for a malformed request; it returns a model with
// parseWarnings so the widget can render a fail-closed review. Throwing would
// crash the widget and prevent the user from seeing what the request even
// looked like.

import { actionId, permissionId } from "./ids.js";
import { classifyRecapEntry, classifySeverityFromActions } from "./classify.js";
import type {
  CapabilityAction,
  CapabilityGrant,
  CapabilityReviewModel,
  ImmutableSiweFields,
  MetadataTrust,
  ParseWarning,
  ReasonProvenance,
  RequesterIdentity,
  RequestProtocol,
  SignerInfo,
} from "./model.js";

export interface ParseContext {
  /** The raw message to review. Signed byte-for-byte in the legacy path. */
  message: string;
  /**
   * The SIWE `domain` field the CLI/opener claims. If absent, we parse it
   * from the SIWE if present. `verifiedOrigin` is set from `postMessageOrigin`
   * for widget flows so we can flag mismatches.
   */
  postMessageOrigin?: string | null;
  /** Signer this request will be signed with. */
  signer: SignerInfo;
  /**
   * ReCap entries the CLI marked as REQUIRED (server-side capability read
   * that must remain in the SIWE). Extra safety on top of the parser's own
   * required-action heuristics.
   */
  requiredActionIds?: string[];
  /**
   * Explicit selection to render. If omitted, all parsed actions are
   * considered selected (default consent).
   */
  selectedActionIds?: string[];
  /**
   * When true, everything is selected but only required actions are
   * `editable: false`. When false, entire model is read-only (legacy
   * signMessage byte-exact flow).
   */
  editable: boolean;
  /** Verified metadata trust decision. */
  metadataTrust: MetadataTrust;
  /** Reason string, and where it came from. */
  reason: ReasonProvenance;
  /** Requester (app) identity, verified by the caller before parse. */
  requester: RequesterIdentity;
  /**
   * Sol MAJOR-8: the requesting app's verified Ethereum address, lowercased.
   * When BOTH `requesterAddress` and `requesterVerified === true` are set,
   * the classifier uses this identity to distinguish own-app vs cross-app
   * grants — replacing the deprecated signer-address fallback that caused
   * every cross-user grant sharing a signer with its owner to appear as
   * own-app-data. Callers MUST NOT supply an unverified address here.
   */
  requesterAddress?: string | null;
  /**
   * True only when `requesterAddress` was derived from a signed manifest
   * whose digest matched, whose signature verified, and whose freshness
   * is within the configured window. Any lower trust state MUST leave
   * this false (or omit it).
   */
  requesterVerified?: boolean;
}

const SIWE_DOMAIN_LINE = /^(.*?) wants you to sign in with your Ethereum account:$/m;
const SIWE_ADDRESS_LINE = /^0x[a-fA-F0-9]{40}$/m;
const SIWE_URI_LINE = /^URI: (.+)$/m;
const SIWE_VERSION_LINE = /^Version: (.+)$/m;
const SIWE_CHAIN_LINE = /^Chain ID: (\d+)$/m;
const SIWE_NONCE_LINE = /^Nonce: (.+)$/m;
const SIWE_ISSUED_LINE = /^Issued At: (.+)$/m;
const SIWE_EXPIRATION_LINE = /^Expiration Time: (.+)$/m;
// ReCap capabilities are appended by TinyCloud as a resources list.
const SIWE_RESOURCE_LINE = /^- (.+)$/gm;

interface ParsedRecapEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
  /**
   * Per-ability caveats keyed by the fully-qualified ability string. Empty
   * arrays mean "no caveats" and are indistinguishable from an absent key
   * — callers should not rely on absence to encode "no caveats". Preserved
   * end-to-end so subset validation can compare candidate vs baseline
   * caveats structurally.
   */
  caveatsByAbility: Record<string, unknown[]>;
}

/**
 * Best-effort SIWE parse. Returns null if the input does not look like SIWE
 * at all.
 */
function looksLikeSiwe(message: string): boolean {
  return (
    SIWE_DOMAIN_LINE.test(message) &&
    SIWE_ADDRESS_LINE.test(message) &&
    SIWE_URI_LINE.test(message)
  );
}

function firstMatch(re: RegExp, text: string): string | null {
  const m = text.match(re);
  return m && m[1] ? m[1] : null;
}

function parseImmutableSiweFields(
  message: string,
  signer: SignerInfo,
): ImmutableSiweFields | null {
  const domain = firstMatch(SIWE_DOMAIN_LINE, message);
  const addrMatch = message.match(SIWE_ADDRESS_LINE);
  const chainRaw = firstMatch(SIWE_CHAIN_LINE, message);
  const nonce = firstMatch(SIWE_NONCE_LINE, message);
  const issuedAt = firstMatch(SIWE_ISSUED_LINE, message);
  const expirationTime = firstMatch(SIWE_EXPIRATION_LINE, message);
  if (!domain || !addrMatch || !chainRaw || !nonce || !issuedAt || !expirationTime) {
    return null;
  }
  const address = addrMatch[0];
  const chainId = Number(chainRaw);
  // The prepared session carries the JWK as an out-of-band field, not in
  // the SIWE. Keep the placeholder null so the caller can back-fill it
  // after issuing the /prepare context.
  return {
    address,
    chainId,
    domain,
    issuedAt,
    expirationTime,
    spaceId: /* filled by caller */ signer.address, // placeholder; caller must overwrite
    jwk: null,
    nonce,
  };
}

// Base64 alphabet lookup. Values outside the alphabet map to -1.
const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_DECODE_TABLE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < BASE64_ALPHABET.length; i += 1) {
    t[BASE64_ALPHABET.charCodeAt(i)] = i;
  }
  return t;
})();

/**
 * Decode a base64url string into UTF-8 text. Returns null on failure.
 *
 * Implemented in pure JS so the package stays platform-agnostic — the
 * runtimes we ship into (Bun API, browsers via Svelte, Node fallback) all
 * bring their own atob/Buffer/TextDecoder, but this package's tsconfig
 * targets ES2022 without DOM or node lib, so we can't reference any of them.
 */
function decodeBase64Url(input: string): string | null {
  try {
    let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
    const padding = b64.length % 4;
    if (padding === 2) b64 += "==";
    else if (padding === 3) b64 += "=";
    else if (padding !== 0) return null;
    const bytes: number[] = [];
    for (let i = 0; i < b64.length; i += 4) {
      const c0 = b64.charCodeAt(i);
      const c1 = b64.charCodeAt(i + 1);
      const c2 = b64.charCodeAt(i + 2);
      const c3 = b64.charCodeAt(i + 3);
      const v0 = c0 < 128 ? BASE64_DECODE_TABLE[c0]! : -1;
      const v1 = c1 < 128 ? BASE64_DECODE_TABLE[c1]! : -1;
      if (v0 < 0 || v1 < 0) return null;
      bytes.push((v0 << 2) | (v1 >> 4));
      if (b64.charAt(i + 2) === "=") break;
      const v2 = c2 < 128 ? BASE64_DECODE_TABLE[c2]! : -1;
      if (v2 < 0) return null;
      bytes.push(((v1 & 0xf) << 4) | (v2 >> 2));
      if (b64.charAt(i + 3) === "=") break;
      const v3 = c3 < 128 ? BASE64_DECODE_TABLE[c3]! : -1;
      if (v3 < 0) return null;
      bytes.push(((v2 & 0x3) << 6) | v3);
    }
    return utf8BytesToString(bytes);
  } catch {
    return null;
  }
}

/**
 * Decode a UTF-8 byte sequence into a JS string. Returns null on invalid
 * sequences. Pure-JS implementation so the package stays platform-agnostic.
 */
function utf8BytesToString(bytes: number[]): string | null {
  let out = "";
  for (let i = 0; i < bytes.length; ) {
    const b0 = bytes[i]!;
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
      i += 1;
    } else if ((b0 & 0xe0) === 0xc0) {
      if (i + 1 >= bytes.length) return null;
      const b1 = bytes[i + 1]!;
      out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
      i += 2;
    } else if ((b0 & 0xf0) === 0xe0) {
      if (i + 2 >= bytes.length) return null;
      const b1 = bytes[i + 1]!;
      const b2 = bytes[i + 2]!;
      out += String.fromCharCode(
        ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f),
      );
      i += 3;
    } else if ((b0 & 0xf8) === 0xf0) {
      if (i + 3 >= bytes.length) return null;
      const b1 = bytes[i + 1]!;
      const b2 = bytes[i + 2]!;
      const b3 = bytes[i + 3]!;
      let cp =
        ((b0 & 0x07) << 18) |
        ((b1 & 0x3f) << 12) |
        ((b2 & 0x3f) << 6) |
        (b3 & 0x3f);
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10));
      out += String.fromCharCode(0xdc00 + (cp & 0x3ff));
      i += 4;
    } else {
      return null;
    }
  }
  return out;
}

/**
 * Split a ReCap "att" key (a resource URI) into `space` and `path`. Keys of
 * the form `tinycloud:pkh:eip155:<chain>:<addr>:<name>[/<path>]` split at the
 * first `/`. Non-tinycloud URIs (e.g. `eip155://ethereum/eip155Chain/1`) are
 * returned as-is so classification can flag them as unknown.
 */
function splitResourceUri(resourceUri: string): { space: string; path: string } {
  if (resourceUri.startsWith("tinycloud:")) {
    const slashIdx = resourceUri.indexOf("/");
    if (slashIdx >= 0) {
      return {
        space: resourceUri.slice(0, slashIdx),
        path: resourceUri.slice(slashIdx + 1),
      };
    }
    return { space: resourceUri, path: "" };
  }
  return { space: resourceUri, path: "" };
}

/**
 * Split an ability key (e.g. `tinycloud.kv/get`) into `service` and verb.
 * Returns null if the key has no `/` separator.
 */
function splitAbility(ability: string): { service: string; verb: string } | null {
  const idx = ability.indexOf("/");
  if (idx < 0) return null;
  return { service: ability.slice(0, idx), verb: ability.slice(idx + 1) };
}

/**
 * Decode a single `urn:recap:<b64>` resource into (service, space, path,
 * actions) tuples. Populates `grouped` in place and emits `warnings` for
 * anything that cannot be decoded.
 *
 * Real TinyCloud recap payloads look like:
 *   { "att": { "<resourceUri>": { "<service>/<verb>": [caveats...] } }, "prf": [] }
 * where `<resourceUri>` is `tinycloud:pkh:eip155:<chain>:<addr>:<name>[/path]`
 * and `<service>/<verb>` is the fully-qualified ability (e.g. `tinycloud.kv/get`).
 */
function decodeRecapUri(
  raw: string,
  grouped: Map<string, ParsedRecapEntry>,
  warnings: ParseWarning[],
): void {
  const payload = raw.slice("urn:recap:".length);
  const decoded = decodeBase64Url(payload);
  if (decoded === null) {
    warnings.push({
      code: "unrecognized-recap-namespace",
      message: "ReCap payload could not be base64url-decoded.",
    });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    warnings.push({
      code: "unrecognized-recap-namespace",
      message: "ReCap payload is not valid JSON.",
    });
    return;
  }
  if (!parsed || typeof parsed !== "object") {
    warnings.push({
      code: "unrecognized-recap-namespace",
      message: "ReCap payload is not an object.",
    });
    return;
  }
  const att = (parsed as { att?: unknown }).att;
  if (!att || typeof att !== "object") {
    warnings.push({
      code: "unrecognized-recap-namespace",
      message: "ReCap payload is missing an `att` map.",
    });
    return;
  }
  for (const [resourceUri, abilityMapRaw] of Object.entries(
    att as Record<string, unknown>,
  )) {
    if (!abilityMapRaw || typeof abilityMapRaw !== "object") {
      warnings.push({
        code: "malformed-space",
        message: `ReCap resource "${resourceUri}" has a non-object ability map.`,
      });
      continue;
    }
    const { space, path } = splitResourceUri(resourceUri);
    for (const [ability, rawCaveats] of Object.entries(
      abilityMapRaw as Record<string, unknown>,
    )) {
      const split = splitAbility(ability);
      if (!split) {
        warnings.push({
          code: "malformed-space",
          message: `ReCap ability "${ability}" is missing a service/verb separator.`,
        });
        continue;
      }
      const service = split.service;
      const key = `${service} ${space} ${path}`;
      let entry = grouped.get(key);
      if (!entry) {
        entry = { service, space, path, actions: [], caveatsByAbility: {} };
        grouped.set(key, entry);
      }
      if (entry.actions.includes(ability)) {
        warnings.push({
          code: "duplicate-action",
          message: `Action ${ability} appears multiple times for ${space}/${path}.`,
        });
      } else {
        entry.actions.push(ability);
      }
      // Preserve caveats verbatim. ReCap requires the value be an array —
      // treat non-arrays as empty and warn so the operator sees the input
      // was malformed rather than silently accepted.
      if (Array.isArray(rawCaveats)) {
        entry.caveatsByAbility[ability] = rawCaveats as unknown[];
      } else {
        entry.caveatsByAbility[ability] = [];
        if (rawCaveats !== undefined) {
          warnings.push({
            code: "malformed-space",
            message: `ReCap ability "${ability}" caveats value is not an array; treated as empty.`,
          });
        }
      }
    }
  }
}

/**
 * Extract ReCap resource lines and split them into (service, space, path,
 * actions) tuples. Empty on non-ReCap SIWE.
 *
 * ReCap resources take one of two forms:
 *   - `urn:recap:<b64>` (canonical wire form): base64url-encoded JSON with an
 *     `att` map keyed by resource URI. This is what a signed TinyCloud SIWE
 *     actually carries; see decodeRecapUri.
 *   - `<service>/<verb>:<space>[/<path>]` (legacy expanded form): kept for
 *     backward compatibility with older tinycloud-node revisions.
 *
 * Emits warnings for malformed input instead of throwing.
 */
function parseRecapResources(message: string): {
  entries: ParsedRecapEntry[];
  warnings: ParseWarning[];
} {
  const warnings: ParseWarning[] = [];
  const grouped = new Map<string, ParsedRecapEntry>();

  SIWE_RESOURCE_LINE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SIWE_RESOURCE_LINE.exec(message)) !== null) {
    const raw = match[1]!.trim();

    // Canonical wire form: base64url-encoded JSON payload.
    if (raw.startsWith("urn:recap:")) {
      decodeRecapUri(raw, grouped, warnings);
      continue;
    }

    // Legacy expanded form: <service>/<verb>:<space>[/<path>]
    const firstColon = raw.indexOf(":");
    if (firstColon < 0) {
      warnings.push({
        code: "malformed-space",
        message: `Resource "${raw}" is missing a service:space separator.`,
      });
      continue;
    }
    const head = raw.slice(0, firstColon);
    const rest = raw.slice(firstColon + 1);
    const slash = head.indexOf("/");
    if (slash < 0) {
      warnings.push({
        code: "malformed-space",
        message: `Resource "${raw}" is missing a service/action separator.`,
      });
      continue;
    }
    const service = head.slice(0, slash);
    const action = head.slice(slash + 1);
    // The space URI is `tinycloud:...:<name>`; the path is anything after
    // the space name. We split on the LAST `:` after `tinycloud:` to keep
    // colons inside path elements.
    let space = rest;
    let path = "";
    if (rest.startsWith("tinycloud:")) {
      // Walk forward `tinycloud:pkh:eip155:<chain>:<addr>:<name>[/<path>]`
      // Path is delimited by the FIRST `/` after the space name.
      const slashIdx = rest.indexOf("/");
      if (slashIdx >= 0) {
        space = rest.slice(0, slashIdx);
        path = rest.slice(slashIdx + 1);
      } else {
        space = rest;
        path = "";
      }
    }
    const key = `${service} ${space} ${path}`;
    let entry = grouped.get(key);
    if (!entry) {
      entry = { service, space, path, actions: [], caveatsByAbility: {} };
      grouped.set(key, entry);
    }
    // Dedupe actions but flag the duplicate so callers can note the redundancy.
    const qualified = `${service}/${action}`;
    if (entry.actions.includes(qualified)) {
      warnings.push({
        code: "duplicate-action",
        message: `Action ${qualified} appears multiple times for ${space}/${path}.`,
      });
    } else {
      entry.actions.push(qualified);
    }
    // Legacy expanded form cannot encode caveats — record empty list so
    // downstream comparisons treat every ability uniformly.
    if (entry.caveatsByAbility[qualified] === undefined) {
      entry.caveatsByAbility[qualified] = [];
    }
  }

  // Deterministic order: sort grants by (service, space, path) and actions
  // within each grant alphabetically. Callers compare model JSON for equality
  // and the wire form must not depend on ReCap resource ordering.
  const entries = Array.from(grouped.values());
  for (const entry of entries) {
    entry.actions.sort();
  }
  entries.sort((a, b) => {
    if (a.service !== b.service) return a.service < b.service ? -1 : 1;
    if (a.space !== b.space) return a.space < b.space ? -1 : 1;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    return 0;
  });
  return { entries, warnings };
}

function buildActions(
  entry: ParsedRecapEntry,
  ctx: ParseContext,
): CapabilityAction[] {
  const required = new Set(ctx.requiredActionIds ?? []);
  const selected = ctx.selectedActionIds
    ? new Set(ctx.selectedActionIds)
    : null;
  return entry.actions.map((ability): CapabilityAction => {
    const verb = ability.includes("/")
      ? ability.slice(ability.indexOf("/") + 1)
      : ability;
    const id = actionId(entry.service, entry.space, entry.path, ability);
    // Structural requirement: the TinyCloud capabilities/read grant is
    // architecturally required for delegation activation.
    const structurallyRequired =
      entry.service === "tinycloud.capabilities" &&
      (ability === "tinycloud.capabilities/read" || ability === "capabilities/read");
    const isRequired = required.has(id) || structurallyRequired;
    const isSelected = selected ? selected.has(id) || isRequired : true;
    const caveats = entry.caveatsByAbility[ability] ?? [];
    // A ReCap ability whose caveat list is MEANINGFULLY non-empty
    // narrows authority in ways the SIWE regenerator cannot preserve.
    // "Meaningfully non-empty" excludes ReCap's canonical `[{}]`
    // vacuous-caveat placeholder — that is the standard shape for
    // "no caveats" and appears in every real TinyCloud-emitted recap.
    // A caveat array that carries any non-empty object is a real
    // narrowing constraint and we mark the action non-editable.
    const hasMeaningfulCaveats =
      Array.isArray(caveats) &&
      caveats.some(
        (c) =>
          c !== null &&
          typeof c === "object" &&
          Object.keys(c as Record<string, unknown>).length > 0,
      );
    return {
      id,
      ability,
      verb,
      required: isRequired,
      selected: isSelected,
      editable: ctx.editable && !isRequired && !hasMeaningfulCaveats,
      caveats,
    };
  });
}

function ownerFromSpace(space: string): {
  owner: string | null;
  ownedBySelf: boolean | null;
} {
  const match = space.match(
    /^tinycloud:pkh:eip155:\d+:(0x[a-fA-F0-9]{40})(?::|$)/,
  );
  if (!match) return { owner: null, ownedBySelf: null };
  return { owner: match[1]!.toLowerCase(), ownedBySelf: null };
}

function buildGrants(
  entries: ParsedRecapEntry[],
  ctx: ParseContext,
  signer: SignerInfo,
): CapabilityGrant[] {
  const signerAddress = signer.address.toLowerCase();
  // Sol MAJOR-8 (requester classification): derive the ownership axis from
  // the verified requester identity when the parser was given one. `signer`
  // is the OpenKey user account — using it as the ownership axis mis-labels
  // every cross-app request that shares the SAME signer with the space
  // owner (which is common: a user often signs into OpenKey with the same
  // wallet that owns their TinyCloud space). Only a VERIFIED requester
  // address (from a signed manifest that matched its expected digest) is
  // trustworthy for cross-app classification.
  const requesterAddress = ctx.requesterAddress ?? null;
  const requesterVerified = ctx.requesterVerified === true;
  return entries.map((entry): CapabilityGrant => {
    // Forward both the (deprecated) signer address and the verified
    // requester identity so classifyRecapEntry can distinguish own-app
    // vs cross-app grants correctly.
    const { family, displayLabel } = classifyRecapEntry({
      ...entry,
      signerAddress,
      requesterAddress,
      requesterVerified,
    });
    const severity = classifySeverityFromActions(family, entry.actions);
    const actions = buildActions(entry, ctx);
    const ownership = ownerFromSpace(entry.space);
    // ownedBySelf is a UI hint. Prefer the VERIFIED requester when
    // available; fall back to the signer address only when there is no
    // requester identity to compare against. When neither is available
    // (and the space has an owner), we fail closed by reporting null so
    // the UI does not falsely claim self-ownership.
    const trustedOwnershipAxis = requesterVerified && requesterAddress
      ? requesterAddress.toLowerCase()
      : requesterAddress
        ? null
        : signerAddress;
    const ownedBySelf =
      ownership.owner === null
        ? null
        : trustedOwnershipAxis === null
          ? null
          : ownership.owner === trustedOwnershipAxis;
    return {
      id: permissionId(entry.service, entry.space, entry.path),
      family,
      severity,
      service: entry.service,
      space: entry.space,
      path: entry.path,
      owner: ownership.owner,
      ownedBySelf,
      displayLabel,
      metadataLabel: null,
      actions,
    };
  });
}

export function parseCapabilityReview(
  ctx: ParseContext,
): CapabilityReviewModel {
  const warnings: ParseWarning[] = [];

  // 1. Legacy or non-SIWE: byte-exact review, no permission model.
  if (!looksLikeSiwe(ctx.message)) {
    return {
      version: 1,
      protocol: "legacy-message",
      rawMessage: ctx.message,
      requester: ctx.requester,
      reason: ctx.reason,
      signer: ctx.signer,
      expiry: null,
      immutable: null,
      metadataTrust: ctx.metadataTrust,
      permissions: [],
      parseWarnings: warnings,
    };
  }

  // 2. Parse SIWE-level fields.
  const immutable = parseImmutableSiweFields(ctx.message, ctx.signer);
  const expiration = firstMatch(SIWE_EXPIRATION_LINE, ctx.message);

  const { entries, warnings: recapWarnings } = parseRecapResources(ctx.message);
  warnings.push(...recapWarnings);

  // 3. Plain SIWE (no editable capabilities).
  if (entries.length === 0) {
    warnings.push({
      code: "no-recap",
      message: "Ordinary SIWE — no capability payload; review is read-only.",
    });
    return {
      version: 1,
      protocol: "siwe-plain",
      rawMessage: ctx.message,
      requester: ctx.requester,
      reason: ctx.reason,
      signer: ctx.signer,
      expiry: expiration,
      immutable,
      metadataTrust: ctx.metadataTrust,
      permissions: [],
      parseWarnings: warnings,
    };
  }

  // 4. TinyCloud SIWE-ReCap: editable capabilities.
  const permissions = buildGrants(entries, ctx, ctx.signer);
  const protocol: RequestProtocol = "tinycloud-siwe-recap";
  return {
    version: 1,
    protocol,
    rawMessage: ctx.message,
    requester: ctx.requester,
    reason: ctx.reason,
    signer: ctx.signer,
    expiry: expiration,
    immutable,
    metadataTrust: ctx.metadataTrust,
    permissions,
    parseWarnings: warnings,
  };
}
