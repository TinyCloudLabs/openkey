// SIWE narrowing that PRESERVES every immutable header field byte-for-byte.
//
// Sol continuation contract (CRITICAL): every real production SIWE produced by
// `NodeUserAuthorization.prepareSessionForSigning()` (via the WASM
// `prepareSession`) carries a NON-EMPTY `statement` line beginning with
// "I further authorize the stated URI to perform the following actions on my
// behalf: ...". The statement is a text encoding of the ReCap contents.
//
// The prior implementation rejected any narrowing when `immutable.statement`
// was present, which meant the entire production editable-signing flow was
// dead code: every real request bounced with `immutable_fields_not_preservable`
// before ever regenerating.
//
// This module instead ACCEPTS narrowing by splicing the narrowed ReCap block
// and its derived statement back into the ORIGINAL SIWE bytes, preserving
// every other line byte-for-byte:
//   - Header line ("<domain> wants you to sign in with your Ethereum account:")
//   - Address line
//   - URI, Version, Chain ID, Nonce, Issued At, Expiration Time
//   - Not Before, Request ID (when present)
//   - Every `- <resource>` line that is NOT a `- urn:recap:...` line
//   - Blank-line placement between blocks
//
// The narrowed replacement bytes come from the WASM `prepareSession` — the SAME
// canonical emitter that produced the original. That guarantees:
//   - The narrowed statement uses the exact ReCap-derived phrasing the WASM
//     produces for the narrowed abilities (formatting, quoting, punctuation).
//   - The narrowed `urn:recap:` payload uses the canonical base64url ordering.
//
// After splicing, we RE-PARSE the resulting SIWE and verify:
//   1. The full immutable-field digest matches the ORIGINAL SIWE's digest
//      (defence in depth against splice bugs).
//   2. The regenerated ReCap decodes to exactly the narrowed abilities.
//
// This is deliberately NOT a general SIWE rewriter — it is a targeted
// preserve-everything-except-ReCap splice. Any input that does not conform
// to the strict SIWE grammar (blank line before URI, exactly one Resources:
// block, ReCap resources appearing under Resources:) is rejected.

import { prepareSession, parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { entriesToSessionAbilities, type RecapEntry } from '../routes/delegate-session';
import { DELEGATION_MODE_KEY, decodeRecapUri, type DelegationMode } from './signed-subset';

export interface NarrowResult {
  siwe: string;
}

export interface NarrowError {
  ok: false;
  code:
    | 'siwe_not_parseable'
    | 'siwe_missing_uri_line'
    | 'siwe_missing_resources_line'
    | 'siwe_no_recap_resource'
    | 'narrowed_regenerate_failed'
    | 'narrowed_immutable_drift'
    | 'narrowed_recap_mismatch'
    | 'narrowed_statement_missing'
    | 'narrowed_recap_extract_failed';
  message: string;
}

export interface NarrowSuccess {
  ok: true;
  siwe: string;
}

export type NarrowOutcome = NarrowSuccess | NarrowError;

export interface NarrowInput {
  originalSiwe: string;
  narrowedEntries: RecapEntry[];
  address: string;
  chainId: number;
  spaceId: string;
  domain: string;
  issuedAt: string;
  expirationTime: string;
  jwk: unknown;
  notBefore?: string;
  /**
   * Sol continuation contract (caveats): the baseline attenuation
   * (resource → ability → caveats[]) parsed from the ORIGINAL SIWE.
   * When supplied, the narrower splices the ORIGINAL caveat multiset
   * back onto every surviving (resource, ability) pair after WASM
   * regenerates the ReCap payload (WASM emits a single empty-object
   * caveat per ability regardless of the input caveats — so blindly
   * accepting its payload would drop meaningful caveats from
   * survivors, which broadens authority).
   *
   * When omitted, the WASM-emitted caveats survive unchanged; this is
   * the correct behaviour when the original SIWE carried no
   * meaningful caveats (WASM's `[{}]` is equal to WASM's `[{}]`).
   */
  baselineCaveats?: Record<string, Record<string, unknown[]>>;
}

/**
 * Extract the exact line indices for the anchor points in a SIWE. Returns null
 * on a message that does not fit the expected grammar.
 *
 * Expected structure (blank lines shown explicitly):
 *   0: "<domain> wants you to sign in with your Ethereum account:"
 *   1: "0x<addr>"
 *   2: ""                            // blank
 *   3..K-1: statement lines          // may span multiple lines
 *   K: ""                            // blank
 *   K+1: "URI: ..."
 *   ...
 *   R: "Resources:"                  // when the SIWE grants any
 *   R+1..: "- <resource>"
 */
function anchor(siwe: string): {
  lines: string[];
  headerIdx: number;
  addressIdx: number;
  uriIdx: number;
  resourcesIdx: number | null;
  statementStart: number;
  statementEnd: number; // exclusive
} | null {
  const lines = siwe.split('\n');
  const headerIdx = lines.findIndex((l) =>
    /^.+ wants you to sign in with your Ethereum account:$/.test(l),
  );
  if (headerIdx < 0) return null;
  const addressIdx = headerIdx + 1;
  if (!/^0x[a-fA-F0-9]{40}$/.test(lines[addressIdx] ?? '')) return null;
  const uriIdx = lines.findIndex((l, i) => i > addressIdx && /^URI:\s/.test(l));
  if (uriIdx < 0) return null;
  // Statement: everything between (addressIdx + 1) and uriIdx, minus surrounding
  // blank lines. Real prepareSession output places exactly one blank line before
  // and after the statement, but we accept zero blanks (no statement) too.
  let statementStart = addressIdx + 1;
  while (statementStart < uriIdx && lines[statementStart] === '') statementStart += 1;
  let statementEnd = uriIdx; // exclusive
  while (statementEnd > statementStart && lines[statementEnd - 1] === '') statementEnd -= 1;
  const resourcesIdx = lines.findIndex((l, i) => i >= uriIdx && /^Resources:\s*$/.test(l));
  return {
    lines,
    headerIdx,
    addressIdx,
    uriIdx,
    resourcesIdx: resourcesIdx < 0 ? null : resourcesIdx,
    statementStart,
    statementEnd,
  };
}

/**
 * Return every non-ReCap `- <resource>` line under the Resources: block,
 * preserving order. Empty when no Resources: block exists or when every
 * resource is a `- urn:recap:` line.
 */
function nonRecapResourceLines(lines: string[], resourcesIdx: number | null): string[] {
  if (resourcesIdx === null) return [];
  const out: string[] = [];
  for (let i = resourcesIdx + 1; i < lines.length; i += 1) {
    const l = lines[i]!;
    if (!/^- /.test(l)) break;
    if (/^- urn:recap:/.test(l)) continue;
    out.push(l);
  }
  return out;
}

function recapResourceLines(lines: string[], resourcesIdx: number | null): string[] {
  if (resourcesIdx === null) return [];
  const out: string[] = [];
  for (let i = resourcesIdx + 1; i < lines.length; i += 1) {
    const l = lines[i]!;
    if (!/^- /.test(l)) break;
    if (/^- urn:recap:/.test(l)) out.push(l);
  }
  return out;
}

/**
 * Regenerate a narrowed SIWE that preserves every immutable header field
 * (URI, Version, Chain ID, Nonce, Issued At, Expiration Time, Not Before,
 * Request ID, non-ReCap resources) byte-for-byte from the original, while
 * substituting the ReCap-derived statement and `urn:recap:` payload with the
 * narrowed forms.
 */
export function narrowSiwePreservingImmutable(input: NarrowInput): NarrowOutcome {
  const orig = anchor(input.originalSiwe);
  if (!orig) {
    return {
      ok: false,
      code: 'siwe_not_parseable',
      message: 'Original SIWE does not conform to the expected grammar (header/address/URI).',
    };
  }
  const origRecapLines = recapResourceLines(orig.lines, orig.resourcesIdx);
  if (origRecapLines.length === 0) {
    return {
      ok: false,
      code: 'siwe_no_recap_resource',
      message: 'Original SIWE has no urn:recap: resource line.',
    };
  }
  if (origRecapLines.length > 1) {
    return {
      ok: false,
      code: 'siwe_not_parseable',
      message: 'Original SIWE carries more than one urn:recap: resource.',
    };
  }
  let originalDelegationMode: DelegationMode | undefined;
  try {
    originalDelegationMode = decodeRecapUri(origRecapLines[0]!.slice(2)).delegationMode;
  } catch (e) {
    return {
      ok: false,
      code: 'siwe_not_parseable',
      message: e instanceof Error ? e.message : 'Original SIWE ReCap is not well formed.',
    };
  }
  const { spaceAbilities, rawAbilities } = entriesToSessionAbilities(input.narrowedEntries);

  let narrowedPrepared: { siwe: string } & Record<string, unknown>;
  try {
    narrowedPrepared = prepareSession({
      address: input.address,
      chainId: input.chainId,
      domain: input.domain,
      issuedAt: input.issuedAt,
      expirationTime: input.expirationTime,
      spaceId: input.spaceId,
      jwk: input.jwk,
      abilities: spaceAbilities[input.spaceId] ?? {},
      spaceAbilities,
      rawAbilities,
      ...(input.notBefore ? { notBefore: input.notBefore } : {}),
    }) as { siwe: string } & Record<string, unknown>;
  } catch (e) {
    return {
      ok: false,
      code: 'narrowed_regenerate_failed',
      message: e instanceof Error ? e.message : 'prepareSession failed for the narrowed abilities.',
    };
  }
  const narrowedAnchor = anchor(narrowedPrepared.siwe);
  if (!narrowedAnchor) {
    return {
      ok: false,
      code: 'narrowed_regenerate_failed',
      message: 'Narrowed SIWE (WASM output) does not conform to the expected grammar.',
    };
  }
  // Extract the narrowed statement (ReCap-derived) and the narrowed `- urn:recap:`
  // lines from the WASM output.
  const narrowedStatement = narrowedAnchor.lines
    .slice(narrowedAnchor.statementStart, narrowedAnchor.statementEnd)
    .join('\n');
  if (!narrowedStatement) {
    return {
      ok: false,
      code: 'narrowed_statement_missing',
      message: 'Narrowed SIWE has no statement (WASM did not emit ReCap-derived text).',
    };
  }
  if (narrowedAnchor.resourcesIdx === null) {
    return {
      ok: false,
      code: 'siwe_missing_resources_line',
      message: 'Narrowed SIWE has no Resources: block (WASM did not emit ReCap).',
    };
  }
  const narrowedRecapLinesRaw: string[] = [];
  for (let i = narrowedAnchor.resourcesIdx + 1; i < narrowedAnchor.lines.length; i += 1) {
    const l = narrowedAnchor.lines[i]!;
    if (!/^- /.test(l)) break;
    if (/^- urn:recap:/.test(l)) narrowedRecapLinesRaw.push(l);
  }
  if (narrowedRecapLinesRaw.length === 0) {
    return {
      ok: false,
      code: 'siwe_no_recap_resource',
      message: 'Narrowed SIWE has no urn:recap: resource line (WASM produced an empty ReCap).',
    };
  }

  // Sol continuation contract (caveats) + TC-3810 (delegation mode):
  // If the caller supplied a baseline caveat map, rewrite each `- urn:recap:`
  // line so every surviving (resource, ability) pair carries the ORIGINAL
  // caveats. And if the original SIWE carried `xyz.tinycloud.policy/delegationMode`,
  // preserve that exact mode on the rewritten payload (WASM does not emit it).
  // Never add, drop, or flip the delegation mode.
  let narrowedRecapLines: string[];
  if (input.baselineCaveats || originalDelegationMode !== undefined) {
    const rewritten: string[] = [];
    for (const line of narrowedRecapLinesRaw) {
      const rewrittenLine = rewriteRecapLine(line, input.baselineCaveats, originalDelegationMode);
      if (!rewrittenLine.ok) {
        return {
          ok: false,
          code: 'narrowed_recap_extract_failed',
          message: rewrittenLine.message,
        };
      }
      rewritten.push(rewrittenLine.line);
    }
    narrowedRecapLines = rewritten;
  } else {
    narrowedRecapLines = narrowedRecapLinesRaw;
  }

  // Splice: build the new SIWE by taking the ORIGINAL lines and swapping ONLY
  // the statement block and the urn:recap: lines. Non-ReCap resources under
  // Resources: are preserved byte-for-byte and re-emitted in their original
  // order after the narrowed recap lines.
  //
  // Layout after splice (blank lines shown):
  //   header
  //   address
  //   ""                                        <-- blank
  //   <narrowedStatement lines>
  //   ""                                        <-- blank
  //   URI: ...                                  <-- first line after statement
  //   Version: ...
  //   ...
  //   Resources:
  //   - urn:recap:...                           <-- narrowed
  //   - <preserved non-recap resources...>
  const preservedResources = nonRecapResourceLines(orig.lines, orig.resourcesIdx);
  // `before` MUST end at the blank line that precedes the statement — NOT
  // include another synthetic blank. Slice up to (but not including) the
  // first statement line, so `before[last]` is the blank line.
  const before = orig.lines.slice(0, orig.statementStart);
  const afterStatementIdx = orig.statementEnd;
  // Copy from statementEnd up to (but not including) any Resources: line.
  // The slice STARTS with the trailing blank line the original had after
  // the statement block, so we do NOT emit another synthetic blank.
  const preResourcesEnd =
    orig.resourcesIdx !== null ? orig.resourcesIdx : orig.lines.length;
  const preResources = orig.lines.slice(afterStatementIdx, preResourcesEnd);
  // Rebuild.
  const rebuilt: string[] = [];
  rebuilt.push(...before);
  // Statement text only — surrounding blanks come from `before` and
  // `preResources`. Adding synthetic blanks here duplicated them.
  rebuilt.push(...narrowedStatement.split('\n'));
  rebuilt.push(...preResources);
  // Emit Resources: block if we have any resource lines.
  const hasResources = narrowedRecapLines.length > 0 || preservedResources.length > 0;
  if (hasResources) {
    rebuilt.push('Resources:');
    // Narrowed recap first, then preserved non-recap resources.
    for (const l of narrowedRecapLines) rebuilt.push(l);
    for (const l of preservedResources) rebuilt.push(l);
  }
  const rebuiltSiwe = rebuilt.join('\n');

  // Defence in depth: parse the resulting ReCap and confirm it exactly matches
  // the narrowed entries the caller asked for.
  let regeneratedEntries: RecapEntry[];
  try {
    regeneratedEntries = parseRecapFromSiwe(rebuiltSiwe) as RecapEntry[];
  } catch (e) {
    return {
      ok: false,
      code: 'narrowed_recap_extract_failed',
      message: e instanceof Error ? e.message : 'Rebuilt SIWE could not be re-parsed.',
    };
  }
  if (!recapEntriesEqual(regeneratedEntries, input.narrowedEntries)) {
    return {
      ok: false,
      code: 'narrowed_recap_mismatch',
      message:
        'Rebuilt SIWE ReCap does not exactly match the narrowed abilities — refusing to sign a divergent regeneration.',
    };
  }
  const rebuiltAnchor = anchor(rebuiltSiwe);
  const rebuiltRecapLines = rebuiltAnchor
    ? recapResourceLines(rebuiltAnchor.lines, rebuiltAnchor.resourcesIdx)
    : [];
  if (rebuiltRecapLines.length !== 1) {
    return {
      ok: false,
      code: 'narrowed_recap_extract_failed',
      message: 'Rebuilt SIWE must carry exactly one urn:recap: resource.',
    };
  }
  let rebuiltDelegationMode: DelegationMode | undefined;
  try {
    rebuiltDelegationMode = decodeRecapUri(rebuiltRecapLines[0]!.slice(2)).delegationMode;
  } catch (e) {
    return {
      ok: false,
      code: 'narrowed_recap_extract_failed',
      message: e instanceof Error ? e.message : 'Rebuilt SIWE ReCap is not well formed.',
    };
  }
  if (rebuiltDelegationMode !== originalDelegationMode) {
    return {
      ok: false,
      code: 'narrowed_recap_mismatch',
      message:
        'Rebuilt SIWE ReCap delegation mode does not match the original — refusing to sign a divergent regeneration.',
    };
  }

  return { ok: true, siwe: rebuiltSiwe };
}

/**
 * Rewrite a `- urn:recap:...` line to preserve original baseline caveats (when
 * supplied) and the original top-level `xyz.tinycloud.policy/delegationMode`
 * (when present).
 *
 * Canonical key order emitted: `att`, `prf`, and (only when present)
 * `xyz.tinycloud.policy/delegationMode`, encoded as unpadded `base64url`.
 */
function rewriteRecapLine(
  line: string,
  baselineCaveats: Record<string, Record<string, unknown[]>> | undefined,
  delegationMode: DelegationMode | undefined,
):
  | { ok: true; line: string }
  | { ok: false; message: string } {
  const match = line.match(/^(- urn:recap:)([A-Za-z0-9_-]+=*)$/);
  if (!match || !match[2]) {
    return { ok: false, message: `Invalid urn:recap: line: ${line}` };
  }
  const encoded = match[2];
  const normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  let parsed: { att?: Record<string, Record<string, unknown[]>>; prf?: unknown[] };
  try {
    const json = Buffer.from(padded, 'base64').toString('utf8');
    parsed = JSON.parse(json);
  } catch (e) {
    return {
      ok: false,
      message: e instanceof Error ? e.message : 'urn:recap: payload not decodable',
    };
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.att || typeof parsed.att !== 'object') {
    return { ok: false, message: 'urn:recap: payload missing att block' };
  }
  if (baselineCaveats) {
    // Rewrite in place: for each (resource, ability) present in the WASM output,
    // if the baseline had the same pair, use the baseline caveats. Otherwise
    // leave the WASM caveats untouched (this preserves the [{}] default for
    // abilities the baseline never carried — the RecapEntry contract does not
    // require caveats to exist).
    for (const [resource, abilityMap] of Object.entries(parsed.att)) {
      const baselineAbilityMap = baselineCaveats[resource];
      if (!baselineAbilityMap) continue;
      for (const ability of Object.keys(abilityMap)) {
        const baselineList = baselineAbilityMap[ability];
        if (Array.isArray(baselineList)) {
          abilityMap[ability] = baselineList;
        }
      }
    }
  }
  // Re-encode in canonical top-level key order: att, prf, then optional delegationMode.
  const rebuiltPayload: Record<string, unknown> = {
    att: parsed.att,
    prf: Array.isArray(parsed.prf) ? parsed.prf : [],
  };
  if (delegationMode !== undefined) {
    rebuiltPayload[DELEGATION_MODE_KEY] = delegationMode;
  }
  const rebuiltJson = JSON.stringify(rebuiltPayload);
  const rebuiltEncoded = Buffer.from(rebuiltJson, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  return { ok: true, line: `${match[1]}${rebuiltEncoded}` };
}

/**
 * Structural equality of two `RecapEntry[]` sequences. Ignores order across
 * entries and across actions within an entry.
 */
function recapEntriesEqual(a: RecapEntry[], b: RecapEntry[]): boolean {
  if (a.length !== b.length) return false;
  const norm = (entries: RecapEntry[]) =>
    entries
      .map((e) => ({
        service: e.service,
        space: e.space,
        path: e.path,
        actions: [...e.actions].sort(),
      }))
      .sort((x, y) => {
        if (x.service !== y.service) return x.service < y.service ? -1 : 1;
        if (x.space !== y.space) return x.space < y.space ? -1 : 1;
        if (x.path !== y.path) return x.path < y.path ? -1 : 1;
        return 0;
      });
  const na = norm(a);
  const nb = norm(b);
  for (let i = 0; i < na.length; i += 1) {
    const xa = na[i]!;
    const xb = nb[i]!;
    if (xa.service !== xb.service) return false;
    if (xa.space !== xb.space) return false;
    if (xa.path !== xb.path) return false;
    if (xa.actions.length !== xb.actions.length) return false;
    for (let j = 0; j < xa.actions.length; j += 1) {
      if (xa.actions[j] !== xb.actions[j]) return false;
    }
  }
  return true;
}
