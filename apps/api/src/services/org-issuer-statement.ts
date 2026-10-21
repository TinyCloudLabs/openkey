import { createHash } from 'node:crypto';
import { getAddress } from 'viem';

// TC-1520 K4: the issuer statement (kind 1) that an org key may sign. The client
// sends the statement JSON. The server parses it strictly, renders the fixed text,
// and signs that text (EIP-191). The rendering is part of the signed bytes, so the
// consent screen shows exactly what is signed.
//
// The grammar mirrors the OpenCredentials witness (`orgs/statement.rs`, `orgs/ids.rs`)
// so both sides accept and refuse the same statements.

export const ISSUER_STATEMENT_TYPE = 'tinycloud.org-issuer-authorization/v1';
export const ISSUER_STATEMENT_KIND = 'issuer-statement';
export const MAX_STATEMENT_BYTES = 16 * 1024;

const DIGEST_DOMAIN = `${ISSUER_STATEMENT_TYPE}\u0000`;
const ISSUER_DID_PREFIX = 'did:web:';
const ISSUER_HOST_SUFFIX = '.orgs.credentials.org';
const CONTROLLER_PREFIX = 'did:pkh:eip155:1:';

export type IssuerStatementAction = 'authorize' | 'retire' | 'revoke';
const ACTIONS: readonly IssuerStatementAction[] = ['authorize', 'retire', 'revoke'];

const FIELDS: Record<IssuerStatementAction, readonly string[]> = {
  authorize: [
    'action', 'alg', 'audience', 'controller', 'issuerDid', 'kid', 'nonce', 'notBefore',
    'orgId', 'profiles', 'publicKey', 'seq', 'slug', 'type', 'vcts',
  ],
  retire: ['action', 'audience', 'controller', 'issuerDid', 'kid', 'nonce', 'orgId', 'retiredAt', 'seq', 'slug', 'type'],
  revoke: ['action', 'audience', 'controller', 'issuerDid', 'kid', 'nonce', 'notAfter', 'orgId', 'seq', 'slug', 'type'],
};

// Handles that must never name an org (platform hosts and roles). Mirrors ids.rs.
const RESERVED_HANDLES: Record<string, true> = {
  issuer: true, orgs: true, witness: true, www: true, api: true, app: true, admin: true,
  mail: true, email: true, smtp: true, mx: true, auth: true, login: true, id: true,
  oauth: true, openkey: true, 'tinycloud-internal': true, status: true, docs: true, cdn: true,
  static: true, assets: true, pages: true, billing: true, pay: true, support: true, help: true,
  security: true, abuse: true, postmaster: true, hostmaster: true, webmaster: true, root: true,
  ns: true, ns1: true, ns2: true, dns: true, test: true, staging: true, dev: true, preview: true,
};

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
const RENDERED_TEXT = /^[\x20-\x7e\n]*$/;
const ORG_ID = /^o[a-z2-7]{26}$/;
const HANDLE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const CONTROLLER_HEX = /^0x[0-9a-fA-F]{40}$/;
const NONCE = /^[0-9a-f]{32}$/;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/;
const ITEM = /^[a-z0-9][a-z0-9.-]*\/v[1-9][0-9]*$/;
const KID_DIGITS = /^[1-9][0-9]*$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export class IssuerStatementRefusal extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

type Common = {
  action: IssuerStatementAction;
  audience: string;
  controller: string;
  issuerDid: string;
  kid: string;
  nonce: string;
  orgId: string;
  seq: number;
  slug: string;
  type: typeof ISSUER_STATEMENT_TYPE;
};

export type AuthorizeStatement = Common & {
  action: 'authorize';
  alg: 'EdDSA';
  notBefore: string;
  profiles: string[];
  publicKey: string;
  vcts: string[];
};
export type RetireStatement = Common & { action: 'retire'; retiredAt: string };
export type RevokeStatement = Common & { action: 'revoke'; notAfter: string };
export type IssuerStatement = AuthorizeStatement | RetireStatement | RevokeStatement;

// The OrgKey fields a statement must match (K1 D4 step 3). Null means the key
// record has not been given that field yet, which refuses every statement.
export type IssuerStatementRecord = {
  orgId: string;
  slug: string | null;
  issuerDid: string | null;
  controllerDid: string;
};

// JSON Canonicalization (RFC 8785) for the value shapes a statement uses.
// Integers render as JSON.stringify renders them, so 1.0 and 1e0 differ from 1.
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  const members = Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${members.join(',')}}`;
}

function refuse(code: string, message: string): never {
  throw new IssuerStatementRefusal(code, message);
}

function has(obj: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function issuerDidOf(orgId: string): string {
  return `${ISSUER_DID_PREFIX}${orgId}${ISSUER_HOST_SUFFIX}`;
}

// Org identity for org-key creation (T1 D1, D2). The issuer DID is never accepted from
// a caller: it is derived from the OrgId, which must be a canonical OrgId.
export function issuerDidForOrgId(orgId: string): string {
  if (!ORG_ID.test(orgId)) refuse('invalid_field', 'orgId is not a valid OrgId');
  return issuerDidOf(orgId);
}

// RFC 3339 UTC with whole seconds, a real calendar date, and a year of 1970 or later.
function isRfc3339Utc(value: string): boolean {
  if (!RFC3339_UTC.test(value)) return false;
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return false;
  return Number(value.slice(0, 4)) >= 1970 && new Date(ms).toISOString().replace('.000Z', 'Z') === value;
}

function stringField(obj: Record<string, unknown>, key: string, pattern?: RegExp): string {
  const value = obj[key];
  if (typeof value !== 'string' || value.length === 0 || (pattern && !pattern.test(value))) {
    refuse('invalid_field', `${key} is not valid`);
  }
  return value;
}

// Handle rules for slugs (T1 D2): 3-63 chars, [a-z0-9-], alphanumeric ends, no xn-- prefix,
// no dashes at positions 2-3, not a reserved handle, not shaped like an OrgId.
export function checkHandle(value: string, key: string): string {
  if (value.length < 3 || value.length > 63 || !HANDLE.test(value)) refuse('invalid_field', `${key} is not a valid handle`);
  if (value.startsWith('xn--') || value.slice(2, 4) === '--') refuse('invalid_field', `${key} has a reserved dash pattern`);
  if (has(RESERVED_HANDLES, value) || ORG_ID.test(value)) refuse('invalid_field', `${key} is reserved`);
  return value;
}

function handleField(obj: Record<string, unknown>, key: string): string {
  return checkHandle(stringField(obj, key), key);
}

function controllerField(obj: Record<string, unknown>): string {
  const value = stringField(obj, 'controller');
  if (!value.startsWith(CONTROLLER_PREFIX)) refuse('invalid_field', 'controller is not an EIP-155 address');
  const address = value.slice(CONTROLLER_PREFIX.length);
  if (!CONTROLLER_HEX.test(address) || getAddress(address) !== address) {
    refuse('invalid_field', 'controller is not a checksummed address');
  }
  return value;
}

// `<issuerDid>#issuing-<n>`, with `n` a canonical non-zero u32.
function kidField(obj: Record<string, unknown>, issuerDid: string): string {
  const kid = stringField(obj, 'kid');
  const prefix = `${issuerDid}#issuing-`;
  const digits = kid.startsWith(prefix) ? kid.slice(prefix.length) : '';
  if (!KID_DIGITS.test(digits) || Number(digits) > 0xffffffff) refuse('invalid_field', 'kid is not valid');
  return kid;
}

function publicKeyField(obj: Record<string, unknown>): string {
  const value = stringField(obj, 'publicKey', PUBLIC_KEY);
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) {
    refuse('invalid_field', 'publicKey is not a canonical 32-byte key');
  }
  return value;
}

function timeField(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string' || !isRfc3339Utc(value)) refuse('invalid_field', `${key} is not valid`);
  return value;
}

// Credential types and profiles: non-empty, each printable, each `<prefix>/v<N>`,
// no duplicates. The grammar rejects separators, so the ", " rendering is unambiguous.
function stringList(obj: Record<string, unknown>, key: string): string[] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length === 0) refuse('invalid_field', `${key} must be a non-empty list`);
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0) refuse('invalid_field', `${key} entries must be strings`);
    if (!PRINTABLE_ASCII.test(item)) refuse('non_printable', `${key} entries must be printable`);
    if (!ITEM.test(item) || out.includes(item)) refuse('invalid_field', `${key} entries must be unique <prefix>/v<N>`);
    out.push(item);
  }
  return out;
}

// Strict parse. Input must be the canonical JSON of exactly one statement of a known
// action, with no unknown or missing fields and every field in its allowed form.
// `allowedAudiences` is the set of origins a statement may name as its audience.
// The check order follows the witness so both sides refuse with the same code.
export function parseIssuerStatement(input: string, allowedAudiences: readonly string[]): IssuerStatement {
  if (Buffer.byteLength(input, 'utf8') > MAX_STATEMENT_BYTES) refuse('oversize', 'statement exceeds 16 KiB');
  let value: unknown;
  try {
    value = JSON.parse(input);
  } catch {
    refuse('not_json', 'statement is not JSON');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    refuse('not_object', 'statement is not a JSON object');
  }
  // Duplicate keys, reordered keys, and non-canonical numbers all change the
  // canonical form, so they are caught by this single comparison.
  if (canonicalJson(value) !== input) refuse('non_canonical', 'statement is not canonical JSON');

  const obj = value as Record<string, unknown>;
  if (!has(obj, 'type')) refuse('missing_field', 'missing field type');
  if (obj.type !== ISSUER_STATEMENT_TYPE) refuse('unknown_type', 'unknown statement type');
  if (!has(obj, 'action')) refuse('missing_field', 'missing field action');
  if (typeof obj.action !== 'string' || !ACTIONS.includes(obj.action as IssuerStatementAction)) {
    refuse('unknown_action', 'unknown statement action');
  }
  const action = obj.action as IssuerStatementAction;

  const allowed = FIELDS[action];
  const missing = allowed.find((key) => !has(obj, key));
  if (missing !== undefined) refuse('missing_field', `missing field ${missing}`);
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) refuse('unknown_field', `unknown field ${key}`);
  }

  const orgId = stringField(obj, 'orgId', ORG_ID);
  const slug = handleField(obj, 'slug');
  const controller = controllerField(obj);
  const issuerDid = issuerDidOf(orgId);
  if (stringField(obj, 'issuerDid') !== issuerDid) refuse('binding_mismatch', 'issuerDid does not belong to orgId');
  const kid = kidField(obj, issuerDid);
  if (typeof obj.seq !== 'number' || !Number.isSafeInteger(obj.seq) || obj.seq < 1) {
    refuse('invalid_field', 'seq must be a positive integer');
  }
  const audience = stringField(obj, 'audience');
  if (!allowedAudiences.includes(audience)) refuse('invalid_field', 'audience is not an allowed origin');
  const nonce = stringField(obj, 'nonce', NONCE);

  const common: Common = {
    action,
    audience,
    controller,
    issuerDid,
    kid,
    nonce,
    orgId,
    seq: obj.seq,
    slug,
    type: ISSUER_STATEMENT_TYPE,
  };

  if (action === 'authorize') {
    if (obj.alg !== 'EdDSA') refuse('invalid_field', 'alg must be EdDSA');
    const publicKey = publicKeyField(obj);
    const vcts = stringList(obj, 'vcts');
    const profiles = stringList(obj, 'profiles');
    return {
      ...common,
      action,
      alg: 'EdDSA',
      notBefore: timeField(obj, 'notBefore'),
      profiles,
      publicKey,
      vcts,
    };
  }
  if (action === 'retire') return { ...common, action, retiredAt: timeField(obj, 'retiredAt') };
  return { ...common, action, notAfter: timeField(obj, 'notAfter') };
}

// Every statement field that names the org must equal the stored OrgKey record, and
// the audience must equal the verified requesting origin (K1 D4 step 3).
export function bindIssuerStatement(
  statement: IssuerStatement,
  context: { record: IssuerStatementRecord; requestingOrigin: string },
): void {
  const { record } = context;
  if (statement.audience !== context.requestingOrigin) refuse('binding_mismatch', 'audience is not the requesting origin');
  if (record.slug === null || record.issuerDid === null) {
    refuse('org_record_incomplete', 'org key record has no slug or issuerDid');
  }
  if (
    statement.orgId !== record.orgId ||
    statement.slug !== record.slug ||
    statement.issuerDid !== record.issuerDid ||
    statement.controller !== record.controllerDid
  ) {
    refuse('binding_mismatch', 'statement does not match the org key record');
  }
}

// base64url(SHA-256(domain || statement JSON)). The statement is canonical here, so
// the digest is over the bytes the client sent.
export function issuerStatementDigest(statementJson: string): string {
  return createHash('sha256').update(DIGEST_DOMAIN).update(statementJson, 'utf8').digest('base64url');
}

const HEADLINE: Record<IssuerStatementAction, string> = {
  authorize: 'credentials.org asks your org key to AUTHORISE an issuing key.',
  retire:
    'credentials.org asks your org key to RETIRE an issuing key (it stops issuing; existing credentials keep working).',
  revoke:
    'credentials.org asks your org key to REVOKE an issuing key (STOP issuing now; ask TinyCloud to invalidate its credentials).',
};

// The fixed text that is signed. Every field is read from the parsed statement, so
// the text cannot say anything the statement does not.
export function renderIssuerStatement(statement: IssuerStatement, statementJson: string): string {
  const lines = [
    HEADLINE[statement.action],
    '',
    `Action: ${statement.action}`,
    `Org: ${statement.slug} (${statement.orgId})`,
    `Controller: ${statement.controller}`,
    `Issuer: ${statement.issuerDid}`,
    `Key id: ${statement.kid}`,
  ];
  if (statement.action === 'authorize') {
    lines.push(
      `Public key: ${statement.publicKey}`,
      `Credential types: ${statement.vcts.join(', ')}`,
      `Profiles: ${statement.profiles.join(', ')}`,
      `From: ${statement.notBefore}`,
    );
  } else if (statement.action === 'retire') {
    lines.push(`Retire at: ${statement.retiredAt}`);
  } else {
    lines.push(`Invalidate at: ${statement.notAfter}`);
  }
  lines.push(
    `Audience: ${statement.audience}`,
    `Sequence: ${statement.seq}`,
    `Nonce: ${statement.nonce}`,
    `Statement: ${ISSUER_STATEMENT_TYPE} ${issuerStatementDigest(statementJson)}`,
  );
  const text = lines.join('\n');
  if (!RENDERED_TEXT.test(text)) refuse('non_printable', 'rendered statement is not printable');
  return text;
}

export type IssuerStatementClassification =
  | { ok: true; action: IssuerStatementAction; text: string }
  | { ok: false; refusal: string };

// Parse, bind, and render. Every refusal is a code, never a thrown error, so the
// caller maps it straight to a 403 body.
export function classifyIssuerStatement(
  message: string,
  context: { record: IssuerStatementRecord; requestingOrigin: string; allowedAudiences: readonly string[] },
): IssuerStatementClassification {
  try {
    const statement = parseIssuerStatement(message, context.allowedAudiences);
    bindIssuerStatement(statement, context);
    return { ok: true, action: statement.action, text: renderIssuerStatement(statement, message) };
  } catch (error) {
    if (error instanceof IssuerStatementRefusal) return { ok: false, refusal: error.code };
    throw error;
  }
}

// Personal signing routes refuse any message that names this statement type (K1 D3).
export function namesIssuerStatement(message: string): boolean {
  return message.includes('tinycloud.org-issuer-authorization/');
}
