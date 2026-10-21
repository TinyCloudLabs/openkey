import { createHash } from 'node:crypto';

// TC-1520 K4: the issuer statement (kind 1) that an org key may sign. The client
// sends the statement JSON. The server parses it strictly, renders the fixed text,
// and signs that text (EIP-191). The rendering is part of the signed bytes, so the
// consent screen shows exactly what is signed.

export const ISSUER_STATEMENT_TYPE = 'tinycloud.org-issuer-authorization/v1';
export const ISSUER_STATEMENT_KIND = 'issuer-statement';

const DIGEST_DOMAIN = `${ISSUER_STATEMENT_TYPE}\u0000`;

export type IssuerStatementAction = 'authorize' | 'retire' | 'revoke';

const FIELDS: Record<IssuerStatementAction, readonly string[]> = {
  authorize: [
    'action', 'alg', 'audience', 'controller', 'issuerDid', 'kid', 'nonce', 'notBefore',
    'orgId', 'profiles', 'publicKey', 'seq', 'slug', 'type', 'vcts',
  ],
  retire: ['action', 'audience', 'controller', 'issuerDid', 'kid', 'nonce', 'orgId', 'retiredAt', 'seq', 'slug', 'type'],
  revoke: ['action', 'audience', 'controller', 'issuerDid', 'kid', 'nonce', 'notAfter', 'orgId', 'seq', 'slug', 'type'],
};

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
const CONTROLLER = /^did:pkh:eip155:1:0x[0-9a-fA-F]{40}$/;
const ISSUER_DID = /^did:web:[A-Za-z0-9.:%_-]+$/;
const KID = /^(did:web:[A-Za-z0-9.:%_-]+)#issuing-([1-9][0-9]*)$/;
const NONCE = /^[0-9a-f]{32}$/;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/;
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

function assertPrintable(value: unknown): void {
  if (typeof value === 'string') {
    if (!PRINTABLE_ASCII.test(value)) refuse('non_printable', 'statement contains non-printable text');
  } else if (Array.isArray(value)) {
    value.forEach(assertPrintable);
  } else if (value !== null && typeof value === 'object') {
    Object.values(value).forEach(assertPrintable);
  }
}

// RFC 3339 UTC with whole seconds, and a real calendar date (no 02-30).
function isRfc3339Utc(value: string): boolean {
  if (!RFC3339_UTC.test(value)) return false;
  try {
    return new Date(value).toISOString().replace('.000Z', 'Z') === value;
  } catch {
    return false;
  }
}

function stringField(obj: Record<string, unknown>, key: string, pattern?: RegExp): string {
  const value = obj[key];
  if (typeof value !== 'string' || value.length === 0 || (pattern && !pattern.test(value))) {
    refuse('invalid_field', `${key} is not valid`);
  }
  return value;
}

function timeField(obj: Record<string, unknown>, key: string): string {
  const value = obj[key];
  if (typeof value !== 'string' || !isRfc3339Utc(value)) refuse('invalid_field', `${key} is not valid`);
  return value;
}

function stringList(obj: Record<string, unknown>, key: string): string[] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length === 0) refuse('invalid_field', `${key} must be a non-empty list`);
  return value.map((item) => {
    if (typeof item !== 'string' || item.length === 0) refuse('invalid_field', `${key} entries must be strings`);
    return item;
  });
}

// Strict parse. Input must be the canonical JSON of exactly one statement of a known
// action, with no unknown or missing fields and every field in its allowed form.
// `allowedAudiences` is the set of origins a statement may name as its audience.
export function parseIssuerStatement(input: string, allowedAudiences: readonly string[]): IssuerStatement {
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
  if (typeof obj.action !== 'string' || !(obj.action in FIELDS)) refuse('unknown_action', 'unknown statement action');
  const action = obj.action as IssuerStatementAction;
  if (obj.type !== ISSUER_STATEMENT_TYPE) refuse('unknown_type', 'unknown statement type');

  const allowed = FIELDS[action];
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) refuse('unknown_field', `unknown field ${key}`);
  }
  for (const key of allowed) {
    if (!(key in obj)) refuse('missing_field', `missing field ${key}`);
  }

  assertPrintable(obj);

  const audience = stringField(obj, 'audience');
  if (!allowedAudiences.includes(audience)) refuse('invalid_field', 'audience is not an allowed origin');
  const kidMatch = KID.exec(stringField(obj, 'kid'));
  if (!kidMatch) refuse('invalid_field', 'kid is not valid');
  const issuerDid = stringField(obj, 'issuerDid', ISSUER_DID);
  if (typeof obj.seq !== 'number' || !Number.isSafeInteger(obj.seq) || obj.seq < 1) {
    refuse('invalid_field', 'seq must be a positive integer');
  }

  const common: Common = {
    action,
    audience,
    controller: stringField(obj, 'controller', CONTROLLER),
    issuerDid,
    kid: kidMatch[0],
    nonce: stringField(obj, 'nonce', NONCE),
    orgId: stringField(obj, 'orgId'),
    seq: obj.seq,
    slug: stringField(obj, 'slug'),
    type: ISSUER_STATEMENT_TYPE,
  };

  if (action === 'authorize') {
    if (obj.alg !== 'EdDSA') refuse('invalid_field', 'alg must be EdDSA');
    return {
      ...common,
      action,
      alg: 'EdDSA',
      notBefore: timeField(obj, 'notBefore'),
      profiles: stringList(obj, 'profiles'),
      publicKey: stringField(obj, 'publicKey', PUBLIC_KEY),
      vcts: stringList(obj, 'vcts'),
    };
  }
  if (action === 'retire') return { ...common, action, retiredAt: timeField(obj, 'retiredAt') };
  return { ...common, action, notAfter: timeField(obj, 'notAfter') };
}

// K1 D4 step 3: every statement field that names the org must equal the stored
// OrgKey record, and the audience must equal the verified requesting origin.
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
    statement.controller !== record.controllerDid ||
    !statement.kid.startsWith(`${statement.issuerDid}#`)
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
  return lines.join('\n');
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
