import { canonicalJson, namesIssuerStatement } from './org-issuer-statement';

// Kind 2: the org key signs an EIP-4361 SIWE message whose ReCap resources delegate,
// or revoke, access in the org space `tinycloud:pkh:eip155:1:<org key>:org` (T3 D1, §4).
//
// The server never trusts the caller's text. It parses the message into fields,
// rebuilds the canonical text from those fields, and signs only when the rebuilt text
// equals the input byte for byte. Extra fields, reordering and encoding drift all fail
// as org_space_not_canonical.

export type OrgRole = 'OWNER' | 'ADMIN';

export const ORG_SPACE_SIGNING_FLAG = 'ORG_SPACE_SIGNING_ENABLED';
export const ORG_SPACE_CHAIN_ID = 1;
export const ORG_SPACE_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const ORG_SPACE_MAX_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
export const ORG_SPACE_MAX_BYTES = 16 * 1024;
export const ORG_SPACE_FACT = 'org-space';
export const SHARED_INDEX_DB = 'shared-index';

const SIWE_HEADER = ' wants you to sign in with your Ethereum account:';
const HOST_ABILITY = 'tinycloud.space/host';
const SCHEMA_ABILITY = 'tinycloud.sql/admin';
const REVOKE_ABILITY = 'tinycloud.delegation/revoke';
const KV_OPS = ['get', 'list', 'metadata', 'put', 'del'] as const;
const CID = /^b[a-z2-7]{50,}$/;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function isOrgSpaceSigningEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env[ORG_SPACE_SIGNING_FLAG] === 'true';
}

// Each class is named. enabled: false is refused with org_space_class_not_enabled.
// renewal-key: held back by ruling (owner_holds_capabilities would make the org key
//   delegate read and decrypt; Sam must decide).
// sql-statement / writer-prefix / hook: T13a/T13b/T13, not in the node yet.
// encryption: the network name in urn:tinycloud:encryption:<did>:<network> is not fixed.
export const ORG_SPACE_CLASSES = [
  'space-host',
  'kv-delegation',
  'delegation-revoke',
  'renewal-key',
  'sql-statement',
  'writer-prefix',
  'hook',
  'encryption',
] as const;
export type OrgSpaceClass = (typeof ORG_SPACE_CLASSES)[number];

const CLASS_RULES: Record<OrgSpaceClass, { enabled: boolean; role: OrgRole }> = {
  'space-host': { enabled: true, role: 'OWNER' },
  'kv-delegation': { enabled: true, role: 'ADMIN' },
  'delegation-revoke': { enabled: true, role: 'OWNER' },
  'renewal-key': { enabled: false, role: 'ADMIN' },
  'sql-statement': { enabled: false, role: 'ADMIN' },
  'writer-prefix': { enabled: false, role: 'ADMIN' },
  'hook': { enabled: false, role: 'ADMIN' },
  'encryption': { enabled: false, role: 'ADMIN' },
};

export function roleSatisfies(granted: OrgRole, required: OrgRole): boolean {
  return required === 'ADMIN' || granted === 'OWNER';
}

export class OrgSpaceRefusal extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export function spaceIdFor(address: string): string {
  return `tinycloud:pkh:eip155:${ORG_SPACE_CHAIN_ID}:${address}:org`;
}

export function adminAccountFor(address: string): string {
  return `did:pkh:eip155:${ORG_SPACE_CHAIN_ID}:${address}`;
}

// T3 §4 admin kv ceiling. The writer segment is the admin's 0x address, byte-for-byte.
// get/list/metadata: shared/, config/. put: shared/<writer>/, config/. del: shared/.
export function kvCeiling(writer: string): Array<{ ability: string; path: string }> {
  return [
    { ability: 'tinycloud.kv/get', path: 'shared/' },
    { ability: 'tinycloud.kv/get', path: 'config/' },
    { ability: 'tinycloud.kv/list', path: 'shared/' },
    { ability: 'tinycloud.kv/list', path: 'config/' },
    { ability: 'tinycloud.kv/metadata', path: 'shared/' },
    { ability: 'tinycloud.kv/metadata', path: 'config/' },
    { ability: 'tinycloud.kv/put', path: `shared/${writer}/` },
    { ability: 'tinycloud.kv/put', path: 'config/' },
    { ability: 'tinycloud.kv/del', path: 'shared/' },
  ];
}

export type OrgSpaceAtt = { resource: string; ability: string };

export type OrgSpaceParsed = {
  domain: string;
  address: string;
  uri: string;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
  att: OrgSpaceAtt[];
  fact: { adminAccount: string; class: string; grantId: string };
};

function malformed(): OrgSpaceRefusal {
  return new OrgSpaceRefusal('org_space_malformed');
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeRecapPayload(b64: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  } catch {
    throw malformed();
  }
  if (!isPlainObject(parsed)) throw malformed();
  return parsed;
}

// Structural parse only. classifyOrgSpaceMessage applies the semantic checks, and the
// canonical re-render catches anything this loose parse lets through.
export function parseOrgSpaceMessage(message: string): OrgSpaceParsed {
  if (Buffer.byteLength(message, 'utf8') > ORG_SPACE_MAX_BYTES) throw new OrgSpaceRefusal('org_space_too_large');
  const lines = message.split('\n');
  if (lines.length !== 13) throw malformed();

  const header = /^([a-z0-9.-]+) wants you to sign in with your Ethereum account:$/.exec(lines[0] ?? '');
  if (!header) throw malformed();
  const domain = header[1] ?? '';

  const address = /^(0x[0-9a-fA-F]{40})$/.exec(lines[1] ?? '')?.[1];
  if (!address) throw malformed();
  const uri = /^URI: (.+)$/.exec(lines[5] ?? '')?.[1];
  if (!uri) throw malformed();
  if (lines[6] !== 'Version: 1') throw malformed();
  const chain = /^Chain ID: (\d+)$/.exec(lines[7] ?? '')?.[1];
  if (chain === undefined) throw malformed();
  if (chain !== String(ORG_SPACE_CHAIN_ID)) throw new OrgSpaceRefusal('org_space_chain_refused');
  const nonce = /^Nonce: ([A-Za-z0-9]{8,})$/.exec(lines[8] ?? '')?.[1];
  if (!nonce) throw malformed();
  const issuedAt = /^Issued At: (.+)$/.exec(lines[9] ?? '')?.[1];
  const expirationTime = /^Expiration Time: (.+)$/.exec(lines[10] ?? '')?.[1];
  if (!issuedAt || !expirationTime) throw malformed();
  if (lines[11] !== 'Resources:') throw malformed();
  const b64 = /^- urn:recap:([A-Za-z0-9_=-]+)$/.exec(lines[12] ?? '')?.[1];
  if (!b64) throw malformed();

  const payload = decodeRecapPayload(b64);
  if (Object.keys(payload).sort().join(',') !== 'att,fct,prf') throw malformed();
  if (!Array.isArray(payload.prf) || payload.prf.length !== 0) throw malformed();

  const fct = payload.fct;
  if (!Array.isArray(fct) || fct.length !== 1 || !isPlainObject(fct[0])) throw malformed();
  const factEntry = fct[0];
  if (Object.keys(factEntry).join(',') !== ORG_SPACE_FACT) throw malformed();
  const factValue = factEntry[ORG_SPACE_FACT];
  if (!isPlainObject(factValue)) throw malformed();
  if (Object.keys(factValue).sort().join(',') !== 'adminAccount,class,grantId') throw malformed();
  const { adminAccount, class: declared, grantId } = factValue;
  if (typeof adminAccount !== 'string' || typeof declared !== 'string' || typeof grantId !== 'string') {
    throw malformed();
  }

  const attObject = payload.att;
  if (!isPlainObject(attObject)) throw malformed();
  const att: OrgSpaceAtt[] = [];
  for (const [resource, abilities] of Object.entries(attObject)) {
    if (!isPlainObject(abilities)) throw malformed();
    for (const [ability, caveats] of Object.entries(abilities)) {
      if (!Array.isArray(caveats) || caveats.length !== 1 || !isPlainObject(caveats[0])) throw malformed();
      // Caveats are refused: no selector or statement caveats are signable in v1.
      if (Object.keys(caveats[0]).length !== 0) throw new OrgSpaceRefusal('org_space_ability_refused');
      att.push({ resource, ability });
    }
  }
  if (att.length === 0) throw malformed();

  return {
    domain,
    address,
    uri,
    nonce,
    issuedAt,
    expirationTime,
    att,
    fact: { adminAccount, class: declared, grantId },
  };
}

// Each segment starts with an alphanumeric, `_` or `-`, so `.` and `..` cannot be segments.
// The node accepts arbitrary strings here (probed: `shared/../x/`, `a*b`, `a%20b`); this
// grammar is a deliberate narrowing so the prefix ceiling cannot be escaped by traversal.
const KV_PATH = /^[A-Za-z0-9_-][A-Za-z0-9._-]*(\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*\/?$/;

function kvPathOf(space: string, resource: string): string | null {
  const prefix = `${space}/kv/`;
  if (!resource.startsWith(prefix)) return null;
  const path = resource.slice(prefix.length);
  return KV_PATH.test(path) ? path : null;
}

// The human line names the org and the admin. The node's ReCap statement follows it.
function humanLine(p: OrgSpaceParsed): string {
  const admin = p.fact.adminAccount;
  switch (p.fact.class) {
    case 'space-host':
      return `Host org ${p.address} space for admin ${admin}.`;
    case 'kv-delegation':
      return `Grant ${p.uri} kv access in org ${p.address} space for admin ${admin}.`;
    case 'delegation-revoke': {
      const cid = p.att[0]?.resource.slice('urn:cid:'.length) ?? '';
      return `Revoke delegation ${cid} in org ${p.address} space for admin ${admin}.`;
    }
    default:
      throw new OrgSpaceRefusal('org_space_class_not_enabled');
  }
}

// Mirrors the node's ReCap statement suffix: one clause per grant, in resource then ability order.
function recapClauses(att: OrgSpaceAtt[]): string {
  const sorted = [...att].sort((a, b) => {
    if (a.resource !== b.resource) return a.resource < b.resource ? -1 : 1;
    if (a.ability === b.ability) return 0;
    return a.ability < b.ability ? -1 : 1;
  });
  return sorted
    .map(({ resource, ability }, i) => {
      const cut = ability.lastIndexOf('/');
      return `(${i + 1}) '${ability.slice(0, cut)}': '${ability.slice(cut + 1)}' for '${resource}'.`;
    })
    .join(' ');
}

function statementOf(p: OrgSpaceParsed): string {
  return `${humanLine(p)} I further authorize the stated URI to perform the following actions on my behalf: ${recapClauses(p.att)}`;
}

// The one canonical text for a set of fields. This is the consent text, and it is the
// exact message the org key signs with EIP-191.
export function renderOrgSpaceMessage(p: OrgSpaceParsed): string {
  const resources: Record<string, Record<string, unknown[]>> = {};
  for (const { resource, ability } of p.att) {
    (resources[resource] ??= {})[ability] = [{}];
  }
  const payload = {
    att: resources,
    fct: [{ [ORG_SPACE_FACT]: { adminAccount: p.fact.adminAccount, class: p.fact.class, grantId: p.fact.grantId } }],
    prf: [],
  };
  const b64 = Buffer.from(canonicalJson(payload), 'utf8').toString('base64url');
  return [
    `${p.domain} wants you to sign in with your Ethereum account:`,
    p.address,
    '',
    statementOf(p),
    '',
    `URI: ${p.uri}`,
    'Version: 1',
    `Chain ID: ${ORG_SPACE_CHAIN_ID}`,
    `Nonce: ${p.nonce}`,
    `Issued At: ${p.issuedAt}`,
    `Expiration Time: ${p.expirationTime}`,
    'Resources:',
    `- urn:recap:${b64}`,
  ].join('\n');
}

// RFC 3339 date-time with a Z or +hh:mm / -hh:mm offset. Returns epoch milliseconds, or null.
// Date.parse is not used: it accepts formats outside RFC 3339.
export function parseRfc3339Ms(value: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  const millis = m[7] ? Number(m[7].slice(1).padEnd(3, '0')) : 0;
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return null;
  const epoch = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  const date = new Date(epoch);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  const zone = m[8] ?? 'Z';
  if (zone === 'Z') return epoch;
  const offsetHours = Number(zone.slice(1, 3));
  const offsetMinutes = Number(zone.slice(4, 6));
  if (offsetHours > 23 || offsetMinutes > 59) return null;
  const offset = (offsetHours * 60 + offsetMinutes) * 60_000;
  return zone[0] === '+' ? epoch - offset : epoch + offset;
}

// Ed25519 did:key: multibase base58btc 'z', multicodec varint 0xed 0x01, 32-byte key.
export function isEd25519DidKey(did: string): boolean {
  if (!did.startsWith('did:key:z')) return false;
  const bytes = base58Decode(did.slice('did:key:z'.length));
  return bytes !== null && bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01;
}

function base58Decode(s: string): Buffer | null {
  if (s.length === 0) return null;
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  let hex = n === 0n ? '' : n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let leading = 0;
  for (const ch of s) {
    if (ch !== '1') break;
    leading++;
  }
  return Buffer.concat([Buffer.alloc(leading), hex ? Buffer.from(hex, 'hex') : Buffer.alloc(0)]);
}

export type OrgSpaceContext = {
  allowedOrigins: readonly string[];
  requestingOrigin: string;
  address: string;
  adminAddress: string;
  grantId: string;
  role: OrgRole;
  now?: Date;
};

export type OrgSpaceClassification =
  | { ok: true; kind: string; action: string; text: string; role: OrgRole }
  | { ok: false; refusal: string };

// Ability to class. Returns null for any ability outside the recognised set.
function abilityClass(ability: string, resource: string, space: string): OrgSpaceClass | null {
  if (ability === HOST_ABILITY) return 'space-host';
  // The shared-index schema is created once, as part of host. Any other sql admin is refused.
  if (ability === SCHEMA_ABILITY && resource === `${space}/sql/${SHARED_INDEX_DB}`) return 'space-host';
  if (ability === REVOKE_ABILITY) return 'delegation-revoke';
  if (KV_OPS.some((op) => ability === `tinycloud.kv/${op}`)) return 'kv-delegation';
  if (ability.startsWith('tinycloud.sql/')) return 'sql-statement';
  if (ability.startsWith('tinycloud.hooks/')) return 'hook';
  if (ability.startsWith('tinycloud.encryption/')) return 'encryption';
  return null;
}

// Classification runs in fixed order. The first failing check decides the refusal.
export function classifyOrgSpaceMessage(message: string, ctx: OrgSpaceContext): OrgSpaceClassification {
  try {
    return classifyOrThrow(message, ctx);
  } catch (error) {
    if (error instanceof OrgSpaceRefusal) return { ok: false, refusal: error.code };
    throw error;
  }
}

function classifyOrThrow(message: string, ctx: OrgSpaceContext): OrgSpaceClassification {
  const p = parseOrgSpaceMessage(message);
  const declared = p.fact.class;
  if (!(ORG_SPACE_CLASSES as readonly string[]).includes(declared)) throw malformed();
  const declaredClass = declared as OrgSpaceClass;
  if (!CLASS_RULES[declaredClass].enabled) throw new OrgSpaceRefusal('org_space_class_not_enabled');

  // K1 D7: the org key never signs tinycloud.credentials/*. Checked before anything else.
  if (p.att.some((a) => a.ability.startsWith('tinycloud.credentials/'))) {
    throw new OrgSpaceRefusal('credentials_capability_refused');
  }

  if (!ctx.allowedOrigins.includes(ctx.requestingOrigin)) throw new OrgSpaceRefusal('org_space_origin_mismatch');
  if (p.domain !== new URL(ctx.requestingOrigin).host) throw new OrgSpaceRefusal('org_space_origin_mismatch');
  if (p.address !== ctx.address) throw new OrgSpaceRefusal('org_space_address_mismatch');
  if (p.fact.adminAccount !== adminAccountFor(ctx.adminAddress)) throw new OrgSpaceRefusal('org_space_grant_mismatch');
  if (p.fact.grantId !== ctx.grantId) throw new OrgSpaceRefusal('org_space_grant_mismatch');

  const space = spaceIdFor(ctx.address);
  // Each ability maps to exactly one class, and a message mixes no classes.
  const derived = new Set<OrgSpaceClass>();
  for (const { resource, ability } of p.att) {
    const cls = abilityClass(ability, resource, space);
    if (cls === null) throw new OrgSpaceRefusal('org_space_ability_refused');
    derived.add(cls);
  }
  if (derived.size !== 1) throw new OrgSpaceRefusal('org_space_mixed_classes');
  const [derivedClass] = [...derived] as [OrgSpaceClass];
  if (!CLASS_RULES[derivedClass].enabled) throw new OrgSpaceRefusal('org_space_class_not_enabled');
  if (derivedClass !== declaredClass) throw new OrgSpaceRefusal('org_space_class_mismatch');

  switch (declaredClass) {
    case 'space-host': {
      // The host flow signs exactly the space grant and the shared-index schema grant.
      // Host-only and schema-only messages are refused.
      const wanted = [`${HOST_ABILITY}|${space}/space`, `${SCHEMA_ABILITY}|${space}/sql/${SHARED_INDEX_DB}`].sort();
      const actual = p.att.map(({ resource, ability }) => `${ability}|${resource}`).sort();
      if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) {
        throw new OrgSpaceRefusal('org_space_resource_refused');
      }
      // The URI is the node-staged host did:key for this space.
      if (!isEd25519DidKey(p.uri)) throw new OrgSpaceRefusal('org_space_recipient_refused');
      break;
    }
    case 'kv-delegation': {
      const ceiling = kvCeiling(ctx.adminAddress);
      for (const { resource, ability } of p.att) {
        const path = kvPathOf(space, resource);
        // Ceiling entries are prefixes; a path must sit at or beneath one of them.
        const permitted =
          path !== null && ceiling.some((c) => c.ability === ability && path.startsWith(c.path));
        if (!permitted) throw new OrgSpaceRefusal('org_space_resource_refused');
      }
      if (!isEd25519DidKey(p.uri)) throw new OrgSpaceRefusal('org_space_recipient_refused');
      break;
    }
    case 'delegation-revoke': {
      if (p.att.length !== 1) throw new OrgSpaceRefusal('org_space_resource_refused');
      const only = p.att[0];
      if (!only || !only.resource.startsWith('urn:cid:') || !CID.test(only.resource.slice('urn:cid:'.length))) {
        throw new OrgSpaceRefusal('org_space_resource_refused');
      }
      if (p.uri !== space) throw new OrgSpaceRefusal('org_space_resource_refused');
      break;
    }
    default:
      throw new OrgSpaceRefusal('org_space_class_not_enabled');
  }

  const rule = CLASS_RULES[declaredClass];
  if (!roleSatisfies(ctx.role, rule.role)) throw new OrgSpaceRefusal('org_space_role_insufficient');

  // Lifetime and time window. issuedAt must be within the clock skew of now.
  const now = (ctx.now ?? new Date()).getTime();
  const issued = parseRfc3339Ms(p.issuedAt);
  const expires = parseRfc3339Ms(p.expirationTime);
  if (issued === null || expires === null) throw new OrgSpaceRefusal('org_space_time_invalid');
  if (Math.abs(issued - now) > ORG_SPACE_CLOCK_SKEW_MS) throw new OrgSpaceRefusal('org_space_time_invalid');
  if (expires <= now) throw new OrgSpaceRefusal('org_space_time_invalid');
  if (expires <= issued) throw new OrgSpaceRefusal('org_space_time_invalid');
  if (expires - issued > ORG_SPACE_MAX_LIFETIME_MS) throw new OrgSpaceRefusal('org_space_lifetime_exceeded');

  // Rebuild from the fields. Any difference from the input is refused as not canonical.
  const text = renderOrgSpaceMessage(p);
  if (text !== message) throw new OrgSpaceRefusal('org_space_not_canonical');
  return { ok: true, kind: `org-space/${declaredClass}`, action: declaredClass, text, role: rule.role };
}

// Detects kind 2 on the personal path, anywhere in the text: a SIWE message or typed-data
// JSON that carries a ReCap token. A token that will not decode counts as org-space.
// Fails closed.
export function namesOrgSpaceMessage(message: string): boolean {
  for (const match of message.matchAll(/urn:recap:([A-Za-z0-9_=-]*)/g)) {
    let payload: Record<string, unknown>;
    try {
      payload = decodeRecapPayload(match[1] ?? '');
    } catch {
      return true;
    }
    const facts: unknown[] = Array.isArray(payload.fct) ? payload.fct : isPlainObject(payload.fct) ? [payload.fct] : [];
    if (facts.some((f) => isPlainObject(f) && ORG_SPACE_FACT in f)) return true;
    if (isPlainObject(payload.att) && Object.keys(payload.att).some((k) => (k.split('/')[0] ?? '').endsWith(':org'))) return true;
  }
  return false;
}

// Personal routes refuse the issuer statement and every org-space message.
export function namesOrgSigningMessage(message: string): boolean {
  return namesIssuerStatement(message) || namesOrgSpaceMessage(message);
}
