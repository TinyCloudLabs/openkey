// The pre-sign rule: the set of things signed is a subset of the set of things
// requested, including the requester and the requestee.
//
// `checkSignedSubset` runs on the exact bytes OpenKey is about to sign with a
// managed key, and on the exact bytes it is about to hand to an external
// wallet. It compares them with the request the app made (the SIWE stored at
// /authorize-sign-prepare) and with the owner's selection:
//   - requester (scheme and domain), account, requestee (URI), version, chain,
//     nonce, issued-at, not-before and request id are equal;
//   - expiration equals the requested one unless the owner picked another on
//     the approval screen; a picked time later than the requested one needs
//     the app's opt-in and is never available to a CLI handoff;
//   - the statement is the requested one with only the ReCap-derived sentence
//     replaced by the sentence the signed capabilities produce;
//   - the resource list is the requested one; only the ReCap may change;
//   - every signed (resource, ability) is requested with the same caveats,
//     every signed proof is requested, and every signed capability is one the
//     owner left selected.
// Both messages go through a strict EIP-4361 / EIP-5573 parser first. Anything
// it cannot read losslessly is refused.

import { parseSiweFields, serializeSiwe, SIWE_URI_PATTERN, type SiweFields } from '@openkey/capability-review';
import { actionKey, isRawRecapEntry, parsePreparedRecap, type RecapEntry } from '../routes/delegate-session';
import { LATEST_SIWE_TIME_MS } from './approval-expiry';

export { serializeSiwe };

// ---------------------------------------------------------------------------
// Strict JSON (duplicate keys refused)
// ---------------------------------------------------------------------------

type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
interface JsonObject {
  [key: string]: JsonValue;
}

const JSON_STRING = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
const JSON_LITERAL = /true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const JSON_WHITESPACE = /[ \t\n\r]*/y;
const MAX_JSON_DEPTH = 32;

/** JSON.parse that refuses duplicate object keys and builds prototype-free objects. */
function parseStrictJson(text: string): JsonValue {
  let i = 0;
  const skipWhitespace = () => {
    JSON_WHITESPACE.lastIndex = i;
    JSON_WHITESPACE.exec(text);
    i = JSON_WHITESPACE.lastIndex;
  };
  const token = (pattern: RegExp): string => {
    pattern.lastIndex = i;
    const match = pattern.exec(text);
    if (!match) throw new Error(`unexpected input at offset ${i}`);
    i = pattern.lastIndex;
    return match[0];
  };
  const value = (depth: number): JsonValue => {
    if (depth > MAX_JSON_DEPTH) throw new Error('nesting too deep');
    skipWhitespace();
    const ch = text[i];
    if (ch === '{') {
      i += 1;
      const object: JsonObject = Object.create(null);
      skipWhitespace();
      if (text[i] === '}') {
        i += 1;
        return object;
      }
      for (;;) {
        skipWhitespace();
        const key = JSON.parse(token(JSON_STRING)) as string;
        if (Object.hasOwn(object, key)) throw new Error(`duplicate key ${JSON.stringify(key)}`);
        skipWhitespace();
        if (text[i] !== ':') throw new Error(`expected ':' at offset ${i}`);
        i += 1;
        object[key] = value(depth + 1);
        skipWhitespace();
        if (text[i] === ',') {
          i += 1;
          continue;
        }
        if (text[i] === '}') {
          i += 1;
          return object;
        }
        throw new Error(`expected ',' or '}' at offset ${i}`);
      }
    }
    if (ch === '[') {
      i += 1;
      const array: JsonValue[] = [];
      skipWhitespace();
      if (text[i] === ']') {
        i += 1;
        return array;
      }
      for (;;) {
        array.push(value(depth + 1));
        skipWhitespace();
        if (text[i] === ',') {
          i += 1;
          continue;
        }
        if (text[i] === ']') {
          i += 1;
          return array;
        }
        throw new Error(`expected ',' or ']' at offset ${i}`);
      }
    }
    if (ch === '"') return JSON.parse(token(JSON_STRING)) as string;
    return JSON.parse(token(JSON_LITERAL)) as JsonValue;
  };
  const result = value(0);
  skipWhitespace();
  if (i !== text.length) throw new Error(`trailing data at offset ${i}`);
  return result;
}

function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Key-order independent serialization of a caveat, for multiset comparison. */
function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isJsonObject(value)) {
    const keys = Object.keys(value).sort(compareBytes);
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k]!)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// ---------------------------------------------------------------------------
// ReCap (EIP-5573)
// ---------------------------------------------------------------------------

const RECAP_PREFIX = 'urn:recap:';
export const DELEGATION_MODE_KEY = 'xyz.tinycloud.policy/delegationMode';
export type DelegationMode = 'terminal' | 'attenuable';

/**
 * Normalize a request-level `delegationMode` declaration:
 * - `undefined` stays `undefined` (undeclared; step 4 keeps legacy attenuable).
 * - exact `"attenuable"` -> `"attenuable"`.
 * - `"terminal"` or any unknown non-undefined value -> `"terminal"` (unknown
 *   request declarations never select attenuable).
 */
export function normalizeDeclaredDelegationMode(value: unknown): DelegationMode | undefined {
  if (value === undefined) return undefined;
  return value === 'attenuable' ? 'attenuable' : 'terminal';
}

/**
 * Stamp `xyz.tinycloud.policy/delegationMode` onto a strict ReCap SIWE in
 * canonical top-level key order (`att`, `prf`, `xyz.tinycloud.policy/delegationMode`),
 * unpadded base64url. Returns `siwe` unchanged when it already carries `mode`.
 */
export function withRecapDelegationMode(siwe: string, mode: DelegationMode): string {
  const parsed = parseStrictSiwe(siwe);
  if (!parsed.ok || !parsed.siwe.recap || !parsed.siwe.resources) {
    throw new Error(parsed.ok ? 'SIWE carries no ReCap resource' : parsed.message);
  }
  if (parsed.siwe.recap.delegationMode === mode) return siwe;
  const recapIdx = parsed.siwe.resources.findIndex((r) => r.startsWith(RECAP_PREFIX));
  if (recapIdx < 0) throw new Error('SIWE carries no ReCap resource');
  const encoded = parsed.siwe.resources[recapIdx]!.slice(RECAP_PREFIX.length);
  const raw = parseStrictJson(
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.from(encoded, 'base64url')),
  ) as JsonObject;
  const rebuiltJson = JSON.stringify({
    att: raw.att,
    prf: raw.prf,
    [DELEGATION_MODE_KEY]: mode,
  });
  const nextResources = [...parsed.siwe.resources];
  nextResources[recapIdx] = `${RECAP_PREFIX}${Buffer.from(rebuiltJson, 'utf8').toString('base64url')}`;
  const rebuilt = serializeSiwe({ ...parsed.siwe, resources: nextResources });
  const verified = parseStrictSiwe(rebuilt);
  if (!verified.ok || verified.siwe.recap?.delegationMode !== mode) {
    throw new Error('Failed to verify stamped ReCap delegation mode');
  }
  return rebuilt;
}
const ABILITY_PATTERN = /^[^/\s]+\/\S+$/;
const PROOF_PATTERN = /^\S+$/;
const RECAP_STATEMENT_PREFIX =
  'I further authorize the stated URI to perform the following actions on my behalf:';

/** resource → ability → caveats, as decoded from the ReCap `att` block. */
export type Attenuation = Map<string, Map<string, JsonObject[]>>;

export interface Recap {
  att: Attenuation;
  prf: string[];
  delegationMode?: DelegationMode;
}

function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/** Decode a `urn:recap:` URI; throws on anything that is not a canonical, well-formed ReCap. */
export function decodeRecapUri(uri: string): Recap {
  if (!uri.startsWith(RECAP_PREFIX)) throw new Error('not a urn:recap: URI');
  const encoded = uri.slice(RECAP_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('ReCap payload is not unpadded base64url');
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.toString('base64url') !== encoded) throw new Error('ReCap payload is not canonical base64url');
  const json = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const payload = parseStrictJson(json);
  if (!isJsonObject(payload)) throw new Error('ReCap payload is not an object');
  const keys = Object.keys(payload).sort();
  const hasDelegationMode = Object.hasOwn(payload, DELEGATION_MODE_KEY);
  const allowedKeys = hasDelegationMode
    ? keys.length === 3 && keys[0] === 'att' && keys[1] === 'prf' && keys[2] === DELEGATION_MODE_KEY
    : keys.length === 2 && keys[0] === 'att' && keys[1] === 'prf';
  if (!allowedKeys) {
    throw new Error(
      `ReCap payload must have "att", "prf", and optional "${DELEGATION_MODE_KEY}", got ${JSON.stringify(keys)}`,
    );
  }
  let delegationMode: DelegationMode | undefined;
  if (hasDelegationMode) {
    const rawMode = payload[DELEGATION_MODE_KEY];
    if (rawMode !== 'terminal' && rawMode !== 'attenuable') {
      throw new Error(`ReCap "${DELEGATION_MODE_KEY}" must be "terminal" or "attenuable"`);
    }
    delegationMode = rawMode;
  }
  const rawAtt = payload.att;
  if (!isJsonObject(rawAtt) || Object.keys(rawAtt).length === 0) throw new Error('ReCap att must be a non-empty object');
  const att: Attenuation = new Map();
  for (const [resource, rawAbilities] of Object.entries(rawAtt)) {
    if (!SIWE_URI_PATTERN.test(resource)) throw new Error(`ReCap resource ${JSON.stringify(resource)} is not a URI`);
    if (!isJsonObject(rawAbilities) || Object.keys(rawAbilities).length === 0) {
      throw new Error(`ReCap resource ${resource} must name at least one ability`);
    }
    const abilities = new Map<string, JsonObject[]>();
    for (const [ability, caveats] of Object.entries(rawAbilities)) {
      if (!ABILITY_PATTERN.test(ability)) throw new Error(`ReCap ability ${JSON.stringify(ability)} is not <namespace>/<name>`);
      if (!Array.isArray(caveats) || caveats.length === 0 || !caveats.every(isJsonObject)) {
        throw new Error(`ReCap caveats for ${ability} on ${resource} must be a non-empty array of objects`);
      }
      abilities.set(ability, caveats);
    }
    att.set(resource, abilities);
  }
  const rawPrf = payload.prf;
  if (!Array.isArray(rawPrf) || !rawPrf.every((p): p is string => typeof p === 'string' && PROOF_PATTERN.test(p))) {
    throw new Error('ReCap prf must be an array of proof identifiers');
  }
  if (new Set(rawPrf).size !== rawPrf.length) throw new Error('ReCap prf repeats a proof');
  return delegationMode !== undefined ? { att, prf: rawPrf, delegationMode } : { att, prf: rawPrf };
}

/**
 * The EIP-5573 statement sentence for an attenuation: one numbered item per
 * (resource, namespace), resources, namespaces and ability names in byte order.
 */
export function recapStatement(att: Attenuation): string {
  const items: string[] = [];
  for (const resource of [...att.keys()].sort(compareBytes)) {
    const byNamespace = new Map<string, string[]>();
    for (const ability of att.get(resource)!.keys()) {
      const slash = ability.indexOf('/');
      const namespace = ability.slice(0, slash);
      const names = byNamespace.get(namespace) ?? [];
      names.push(ability.slice(slash + 1));
      byNamespace.set(namespace, names);
    }
    for (const namespace of [...byNamespace.keys()].sort(compareBytes)) {
      const names = byNamespace.get(namespace)!.sort(compareBytes).map((name) => `'${name}'`);
      items.push(`(${items.length + 1}) '${namespace}': ${names.join(', ')} for '${resource}'.`);
    }
  }
  return `${RECAP_STATEMENT_PREFIX} ${items.join(' ')}`;
}

// ---------------------------------------------------------------------------
// SIWE (EIP-4361)
// ---------------------------------------------------------------------------

/** A SIWE read by `parseSiweFields`, with its decoded ReCap. */
export interface StrictSiwe extends SiweFields {
  /** The decoded `urn:recap:` resource, when the message has one. */
  recap?: Recap;
}

export type StrictSiweOutcome = { ok: true; siwe: StrictSiwe } | { ok: false; message: string };

/**
 * Parse an EIP-4361 message with an optional EIP-5573 ReCap: the shared
 * grammar (`parseSiweFields`, the node's), and a canonical, well-formed ReCap
 * when the message has one.
 */
export function parseStrictSiwe(message: string): StrictSiweOutcome {
  const parsed = parseSiweFields(message);
  if (!parsed.ok) return parsed;
  const siwe: StrictSiwe = parsed.fields;
  const recaps = (siwe.resources ?? []).filter((r) => r.startsWith(RECAP_PREFIX));
  if (recaps.length > 1) return { ok: false, message: 'more than one urn:recap: resource' };
  try {
    if (recaps[0] !== undefined) siwe.recap = decodeRecapUri(recaps[0]);
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : 'unparsable ReCap' };
  }
  return { ok: true, siwe };
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

export type SignedSubsetReason =
  | 'request_unparsable'
  | 'signed_unparsable'
  | 'capability_mapping'
  | 'requester'
  | 'address'
  | 'requestee'
  | 'version'
  | 'chain_id'
  | 'nonce'
  | 'issued_at'
  | 'not_before'
  | 'request_id'
  | 'expiration'
  | 'statement'
  | 'resources'
  | 'capability'
  | 'proof'
  | 'delegation_mode'
  | 'selection';

export const SIGNED_SUBSET_REFUSAL_CODE = 'signed_exceeds_request';

export type SignedSubsetOutcome =
  | { ok: true }
  | { ok: false; code: typeof SIGNED_SUBSET_REFUSAL_CODE; reason: SignedSubsetReason; message: string };

export interface SignedSubsetInput {
  /** The SIWE the app requested, as stored at prepare. */
  requested: string;
  /** The exact bytes about to be signed or released to a wallet. */
  signed: string;
  /** The action ids the owner left selected. */
  selectedActionIds: ReadonlySet<string>;
  /** The expiration the owner picked on the approval screen; absent when they kept the app's. */
  ownerPickedExpiration?: string;
  /** The app opted in to a changed expiry and the request is not a CLI handoff. */
  longerExpiryAllowed: boolean;
}

function refuse(reason: SignedSubsetReason, message: string): SignedSubsetOutcome {
  return { ok: false, code: SIGNED_SUBSET_REFUSAL_CODE, reason, message };
}

/** The ReCap resource a parsed entry stands for (the inverse of how `prepareSession` writes it). */
function entryResource(entry: RecapEntry): string {
  if (isRawRecapEntry(entry)) return entry.path;
  return `${entry.space}/${entry.service}${entry.path ? `/${entry.path}` : ''}`;
}

const pairKey = (resource: string, ability: string) => `${resource}\0${ability}`;

function caveatMultiset(caveats: JsonObject[]): string {
  return caveats.map(canonicalJson).sort(compareBytes).join('\n');
}

function checkExpiration(requested: StrictSiwe, signed: StrictSiwe, input: SignedSubsetInput): SignedSubsetOutcome | null {
  const picked = input.ownerPickedExpiration;
  if (picked === undefined || picked === requested.expirationTime) {
    if (signed.expirationTime !== requested.expirationTime) {
      return refuse('expiration', 'The signed expiration differs from the requested one and the owner did not pick it');
    }
    return null;
  }
  if (signed.expirationTime !== picked) {
    return refuse('expiration', 'The signed expiration is not the one the owner picked');
  }
  if (requested.expirationTime === undefined) {
    return refuse('expiration', 'The request has no expiration to change');
  }
  const time = Date.parse(picked);
  if (!(time <= LATEST_SIWE_TIME_MS)) return refuse('expiration', 'The picked expiration is beyond the latest SIWE time');
  for (const bound of [signed.issuedAt, signed.notBefore]) {
    if (bound !== undefined && !(time > Date.parse(bound))) {
      return refuse('expiration', 'The picked expiration is not after the issue or not-before time');
    }
  }
  if (time > Date.parse(requested.expirationTime) && !input.longerExpiryAllowed) {
    return refuse('expiration', 'A later expiration than requested needs the app to allow the owner to change it');
  }
  return null;
}

export function checkSignedSubset(input: SignedSubsetInput): SignedSubsetOutcome {
  const requestedParse = parseStrictSiwe(input.requested);
  if (!requestedParse.ok) return refuse('request_unparsable', `The requested SIWE is not well formed: ${requestedParse.message}`);
  const signedParse = parseStrictSiwe(input.signed);
  if (!signedParse.ok) return refuse('signed_unparsable', `The SIWE to sign is not well formed: ${signedParse.message}`);
  const requested = requestedParse.siwe;
  const signed = signedParse.siwe;
  if (!requested.recap || !signed.recap) return refuse('capability', 'Both messages must carry a ReCap');

  const equalFields: Array<[SignedSubsetReason, string, string | undefined, string | undefined]> = [
    ['requester', 'scheme', requested.scheme, signed.scheme],
    ['requester', 'domain', requested.domain, signed.domain],
    ['address', 'address', requested.address, signed.address],
    ['requestee', 'URI', requested.uri, signed.uri],
    ['version', 'version', requested.version, signed.version],
    ['chain_id', 'chain id', requested.chainId, signed.chainId],
    ['nonce', 'nonce', requested.nonce, signed.nonce],
    ['issued_at', 'issued-at time', requested.issuedAt, signed.issuedAt],
    ['not_before', 'not-before time', requested.notBefore, signed.notBefore],
    ['request_id', 'request id', requested.requestId, signed.requestId],
  ];
  for (const [reason, label, want, got] of equalFields) {
    if (want !== got) return refuse(reason, `The signed ${label} differs from the requested one`);
  }

  const expiration = checkExpiration(requested, signed, input);
  if (expiration) return expiration;

  // Only the ReCap may differ in the resource list; every other resource stays where it was.
  const shape = (resources: string[] | undefined) =>
    (resources ?? []).map((r) => (r.startsWith(RECAP_PREFIX) ? RECAP_PREFIX : r)).join('\n');
  if (shape(requested.resources) !== shape(signed.resources)) {
    return refuse('resources', 'The signed resources differ from the requested ones');
  }

  // The ReCap-derived sentence is the only part of the statement that follows the capabilities.
  const requestedSentence = recapStatement(requested.recap.att);
  const requestedStatement = requested.statement ?? '';
  const expectedStatement = requestedStatement.endsWith(requestedSentence)
    ? requestedStatement.slice(0, requestedStatement.length - requestedSentence.length) + recapStatement(signed.recap.att)
    : requestedStatement;
  if ((signed.statement ?? '') !== expectedStatement) {
    return refuse('statement', 'The signed statement is not the requested one for the signed capabilities');
  }

  for (const [resource, abilities] of signed.recap.att) {
    const requestedAbilities = requested.recap.att.get(resource);
    for (const [ability, caveats] of abilities) {
      const requestedCaveats = requestedAbilities?.get(ability);
      if (!requestedCaveats) return refuse('capability', `${ability} on ${resource} was not requested`);
      if (caveatMultiset(caveats) !== caveatMultiset(requestedCaveats)) {
        return refuse('capability', `The caveats on ${ability} for ${resource} differ from the requested ones`);
      }
    }
  }
  for (const proof of signed.recap.prf) {
    if (!requested.recap.prf.includes(proof)) return refuse('proof', `Proof ${proof} was not requested`);
  }
  if (requested.recap.delegationMode !== signed.recap.delegationMode) {
    return refuse('delegation_mode', 'The signed delegation mode differs from the requested one');
  }

  // The selection is expressed in action ids over the parsed request. Both
  // parsers must agree on the request's capabilities before ids map to pairs.
  let requestedEntries: RecapEntry[];
  try {
    requestedEntries = parsePreparedRecap(input.requested);
  } catch (e) {
    return refuse('capability_mapping', e instanceof Error ? e.message : 'The requested ReCap could not be parsed');
  }
  const requestedPairs = new Set<string>();
  for (const [resource, abilities] of requested.recap.att) {
    for (const ability of abilities.keys()) requestedPairs.add(pairKey(resource, ability));
  }
  const selectedPairs = new Set<string>();
  const mappedPairs = new Set<string>();
  for (const entry of requestedEntries) {
    for (const action of entry.actions) {
      const pair = pairKey(entryResource(entry), action);
      mappedPairs.add(pair);
      if (input.selectedActionIds.has(actionKey(entry, action))) selectedPairs.add(pair);
    }
  }
  if (mappedPairs.size !== requestedPairs.size || [...mappedPairs].some((pair) => !requestedPairs.has(pair))) {
    return refuse('capability_mapping', 'The requested capabilities do not map one-to-one onto selectable actions');
  }
  for (const [resource, abilities] of signed.recap.att) {
    for (const ability of abilities.keys()) {
      if (!selectedPairs.has(pairKey(resource, ability))) {
        return refuse('selection', `${ability} on ${resource} is not in the owner's selection`);
      }
    }
  }
  return { ok: true };
}
