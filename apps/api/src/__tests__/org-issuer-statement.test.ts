import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress, type Hex } from 'viem';
import authorizeVectors from '../services/fixtures/org-issuer-authorization-v1/vectors.json';
import signedVectors from '../services/fixtures/org-issuer-authorization-v1/signed-vectors.json';
import refusalCases from '../services/fixtures/org-issuer-authorization-v1/refusals.json';
import {
  canonicalJson,
  checkHandle,
  classifyIssuerStatement,
  issuerDidForOrgId,
  issuerStatementDigest,
  IssuerStatementRefusal,
  MAX_STATEMENT_BYTES,
  namesIssuerStatement,
  parseIssuerStatement,
  renderIssuerStatement,
  type IssuerStatementRecord,
} from '../services/org-issuer-statement';

const ORIGIN = 'https://credentials.org';
const ALLOWED = [ORIGIN];

// Looks up a named vector and fails loudly if the fixture changes shape.
function vectorNamed(name: string) {
  const vector = authorizeVectors.find((v) => v.name === name);
  if (!vector) throw new Error(`missing fixture vector: ${name}`);
  return vector;
}
const authorizeVector = vectorNamed('authorize');

// The record every fixture statement was generated against (vectors.json).
const FIXTURE_RECORD: IssuerStatementRecord = {
  orgId: 'oceirceirceirceirceirceirce',
  slug: 'acme-labs',
  issuerDid: 'did:web:oceirceirceirceirceirceirce.orgs.credentials.org',
  controllerDid: 'did:pkh:eip155:1:0x1234567890123456789012345678901234567890',
};

// Anvil account 0. Public test key, used only to sign fixtures in tests.
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as Hex;
const ANVIL_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

function classify(message: string, record: IssuerStatementRecord = FIXTURE_RECORD) {
  return classifyIssuerStatement(message, { record, requestingOrigin: ORIGIN, allowedAudiences: ALLOWED });
}

describe('issuer statement rendering matches the OpenCredentials fixtures', () => {
  for (const vector of authorizeVectors) {
    it(`${vector.name}: rendered text and digest are byte-identical`, () => {
      const statement = parseIssuerStatement(vector.statement, ALLOWED);
      expect(renderIssuerStatement(statement, vector.statement)).toBe(vector.text);
      expect(issuerStatementDigest(vector.statement)).toBe(vector.digest);
    });
  }

  for (const vector of signedVectors.vectors) {
    it(`${vector.name}: signature recovers to the fixture signer over the rendered text`, async () => {
      const statement = parseIssuerStatement(vector.statement, ALLOWED);
      const text = renderIssuerStatement(statement, vector.statement);
      expect(issuerStatementDigest(vector.statement)).toBe(vector.digest);
      const signer = await recoverMessageAddress({ message: text, signature: vector.signature as Hex });
      expect(signer).toBe(signedVectors.signer.address as Hex);
    });
  }

  it('is the canonical JSON of each fixture statement', () => {
    for (const vector of authorizeVectors) {
      expect(canonicalJson(JSON.parse(vector.statement))).toBe(vector.statement);
    }
  });
});

describe('issuer statement refusal fixtures', () => {
  for (const refusal of refusalCases) {
    it(`${refusal.name} refuses with ${refusal.code}`, () => {
      const result = classify(refusal.input);
      expect(result).toEqual({ ok: false, refusal: refusal.code });
    });
  }
});

describe('issuer statement binding to the stored org key', () => {
  const authorize = authorizeVector.statement;

  it('signs a statement whose fields all match the record', () => {
    const result = classify(authorize);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.action).toBe('authorize');
      expect(result.text).toBe(authorizeVector.text);
    }
  });

  it('refuses when the org key has no slug or issuerDid yet', () => {
    expect(classify(authorize, { ...FIXTURE_RECORD, slug: null })).toEqual({
      ok: false,
      refusal: 'org_record_incomplete',
    });
    expect(classify(authorize, { ...FIXTURE_RECORD, issuerDid: null })).toEqual({
      ok: false,
      refusal: 'org_record_incomplete',
    });
  });

  it('refuses when the statement names another org, slug, or controller', () => {
    expect(classify(authorize, { ...FIXTURE_RECORD, orgId: 'otherorgotherorgotheroorg0' })).toEqual({
      ok: false,
      refusal: 'binding_mismatch',
    });
    expect(classify(authorize, { ...FIXTURE_RECORD, slug: 'other-labs' })).toEqual({
      ok: false,
      refusal: 'binding_mismatch',
    });
    expect(
      classify(authorize, {
        ...FIXTURE_RECORD,
        controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001',
      }),
    ).toEqual({ ok: false, refusal: 'binding_mismatch' });
  });

  it('refuses when the requesting origin is not the statement audience', () => {
    const result = classifyIssuerStatement(authorize, {
      record: FIXTURE_RECORD,
      requestingOrigin: 'https://other.example',
      allowedAudiences: [ORIGIN, 'https://other.example'],
    });
    expect(result).toEqual({ ok: false, refusal: 'binding_mismatch' });
  });

  it('renders different text for a one-character change to the statement', () => {
    const changed = authorize.replace('"seq":1', '"seq":2');
    const result = classify(changed);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.text).not.toBe(authorizeVector.text);
  });
});

describe('retire and revoke statements round-trip through the signer', () => {
  const account = privateKeyToAccount(ANVIL_KEY);
  expect(account.address).toBe(ANVIL_ADDRESS);

  for (const name of ['retire', 'revoke']) {
    it(`${name} renders the fixture statement and recovers to the signer`, async () => {
      const vector = authorizeVectors.find((v) => v.name === name);
      expect(vector).toBeDefined();
      if (!vector) return;
      const result = classify(vector.statement);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.text).toBe(vector.text);
      const signature = await account.signMessage({ message: result.text });
      expect(await recoverMessageAddress({ message: result.text, signature })).toBe(ANVIL_ADDRESS);
    });
  }
});

describe('personal routes refuse the statement prefix', () => {
  it('flags any message that names the statement type', () => {
    expect(namesIssuerStatement(authorizeVector.text)).toBe(true);
    expect(namesIssuerStatement(authorizeVector.statement)).toBe(true);
    expect(namesIssuerStatement('Sign in to example.com with Ethereum')).toBe(false);
  });
});

describe('statement digest domain', () => {
  it('uses the documented domain separator before the statement bytes', () => {
    const statement = authorizeVector.statement;
    const expected = createHash('sha256')
      .update('tinycloud.org-issuer-authorization/v1\u0000')
      .update(statement, 'utf8')
      .digest('base64url');
    expect(issuerStatementDigest(statement)).toBe(expected);
  });
});

const BASE_AUTHORIZE = JSON.parse(authorizeVector.statement) as Record<string, unknown>;

// Canonical JSON of the authorize fixture with some fields replaced.
function authorizeWith(patch: Record<string, unknown>): string {
  return canonicalJson({ ...BASE_AUTHORIZE, ...patch });
}

// Returns the refusal code, or null when the call succeeds.
function refusalCode(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (error) {
    if (error instanceof IssuerStatementRefusal) return error.code;
    throw error;
  }
}

describe('issuer statement parser grammar and boundaries (F1/F2)', () => {
  const MEMBERSHIP = 'opencredentials.org-membership/v1';
  const BADGE = 'tinycloud.org-badge/v1';

  it('refuses input over the 16 KiB limit and leaves the limit itself to the JSON checks', () => {
    expect(classify('x'.repeat(MAX_STATEMENT_BYTES + 1))).toEqual({ ok: false, refusal: 'oversize' });
    expect(classify('x'.repeat(MAX_STATEMENT_BYTES))).toEqual({ ok: false, refusal: 'not_json' });
  });

  it('refuses a duplicated vcts or profiles entry', () => {
    expect(classify(authorizeWith({ vcts: [MEMBERSHIP, MEMBERSHIP] }))).toEqual({ ok: false, refusal: 'invalid_field' });
    expect(classify(authorizeWith({ profiles: [MEMBERSHIP, MEMBERSHIP] }))).toEqual({ ok: false, refusal: 'invalid_field' });
  });

  it('refuses list entries outside the <prefix>/v<N> grammar', () => {
    expect(classify(authorizeWith({ vcts: ['opencredentials.org-membership'] }))).toEqual({ ok: false, refusal: 'invalid_field' });
    expect(classify(authorizeWith({ vcts: ['Membership/v1'] }))).toEqual({ ok: false, refusal: 'invalid_field' });
  });

  it('accepts distinct well-formed list entries in the order given', () => {
    const statement = parseIssuerStatement(authorizeWith({ vcts: [MEMBERSHIP, BADGE] }), ALLOWED);
    expect(statement).toMatchObject({ vcts: [MEMBERSHIP, BADGE] });
  });

  it('refuses a publicKey that is not a canonical 32-byte key', () => {
    const short = Buffer.alloc(31, 0xbb).toString('base64url');
    const padded = `${BASE_AUTHORIZE.publicKey as string}=`;
    expect(classify(authorizeWith({ publicKey: short }))).toEqual({ ok: false, refusal: 'invalid_field' });
    expect(classify(authorizeWith({ publicKey: padded }))).toEqual({ ok: false, refusal: 'invalid_field' });
  });

  it('refuses a controller that is not EIP-55 checksummed and accepts the checksummed form', () => {
    const checksummed = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
    const lower = checksummed.toLowerCase();
    expect(classify(authorizeWith({ controller: `did:pkh:eip155:1:${lower}` }))).toEqual({ ok: false, refusal: 'invalid_field' });
    expect(parseIssuerStatement(authorizeWith({ controller: `did:pkh:eip155:1:${checksummed}` }), ALLOWED))
      .toMatchObject({ controller: `did:pkh:eip155:1:${checksummed}` });
  });

  it('refuses action names that exist only on Object.prototype as unknown_action', () => {
    for (const action of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      expect(classify(authorizeWith({ action }))).toEqual({ ok: false, refusal: 'unknown_action' });
    }
  });

  it('refuses a kid under another issuer DID even when issuerDid names this org', () => {
    const otherKid = 'did:web:oeirceirceirceirceirceircei.orgs.credentials.org#issuing-1';
    expect(classify(authorizeWith({ kid: otherKid }))).toEqual({ ok: false, refusal: 'invalid_field' });
  });

  it('refuses an issuerDid of another org even when the kid is under that same DID', () => {
    const otherDid = 'did:web:oeirceirceirceirceirceircei.orgs.credentials.org';
    expect(classify(authorizeWith({ issuerDid: otherDid, kid: `${otherDid}#issuing-1` }))).toEqual({
      ok: false,
      refusal: 'binding_mismatch',
    });
  });

  it('refuses any alg other than EdDSA', () => {
    for (const alg of ['ES256', 'eddsa', 'none']) {
      expect(classify(authorizeWith({ alg }))).toEqual({ ok: false, refusal: 'invalid_field' });
    }
  });

  it('checks slug handles for length, reserved dash patterns, reserved names, and OrgId shape', () => {
    expect(checkHandle('acme-labs', 'slug')).toBe('acme-labs');
    expect(refusalCode(() => checkHandle('ab', 'slug'))).toBe('invalid_field');
    expect(refusalCode(() => checkHandle('a'.repeat(64), 'slug'))).toBe('invalid_field');
    expect(refusalCode(() => checkHandle('xn--acme', 'slug'))).toBe('invalid_field');
    expect(refusalCode(() => checkHandle('ac--me', 'slug'))).toBe('invalid_field');
    expect(refusalCode(() => checkHandle('admin', 'slug'))).toBe('invalid_field');
    expect(refusalCode(() => checkHandle('oceirceirceirceirceirceirce', 'slug'))).toBe('invalid_field');
  });

  it('derives the issuer DID only from a valid OrgId', () => {
    expect(issuerDidForOrgId('oceirceirceirceirceirceirce')).toBe(
      'did:web:oceirceirceirceirceirceirce.orgs.credentials.org',
    );
    expect(refusalCode(() => issuerDidForOrgId('org_2'))).toBe('invalid_field');
  });

  it('refuses a 43-character publicKey whose final character carries non-zero padding bits', () => {
    const canonical = BASE_AUTHORIZE.publicKey as string;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const index = alphabet.indexOf(canonical.at(-1) as string);
    // A canonical 32-byte key ends in a character whose two low bits are zero.
    expect(index & 3).toBe(0);
    const tampered = `${canonical.slice(0, -1)}${alphabet[index + 1]}`;
    // Node's base64url decoder ignores the padding bits, so only the re-encode check refuses this.
    expect(Buffer.from(tampered, 'base64url').equals(Buffer.from(canonical, 'base64url'))).toBe(true);
    expect(classify(authorizeWith({ publicKey: tampered }))).toEqual({ ok: false, refusal: 'invalid_field' });
  });

  it('refuses an orgId outside the lowercase base32 OrgId grammar', () => {
    for (const orgId of [
      'OCEIRCEIRCEIRCEIRCEIRCEIRCE',
      'oceirceirceirceirceirceirc',
      'oceirceirceirceirceirceircea',
      'oceirceirceirceirceirceirc1',
    ]) {
      expect(classify(authorizeWith({ orgId }))).toEqual({ ok: false, refusal: 'invalid_field' });
    }
  });

  it('refuses a nonce that is not exactly 32 lowercase hex characters', () => {
    for (const nonce of [
      '0123456789ABCDEF0123456789ABCDEF',
      '0123456789abcdef0123456789abcde',
      '0123456789abcdef0123456789abcdef0',
      '0123456789abcdef0123456789abcdeg',
    ]) {
      expect(classify(authorizeWith({ nonce }))).toEqual({ ok: false, refusal: 'invalid_field' });
    }
  });
});
