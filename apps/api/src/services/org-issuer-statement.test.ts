import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress, type Hex } from 'viem';
import authorizeVectors from './fixtures/org-issuer-authorization-v1/vectors.json';
import signedVectors from './fixtures/org-issuer-authorization-v1/signed-vectors.json';
import refusalCases from './fixtures/org-issuer-authorization-v1/refusals.json';
import {
  canonicalJson,
  classifyIssuerStatement,
  issuerStatementDigest,
  namesIssuerStatement,
  parseIssuerStatement,
  renderIssuerStatement,
  type IssuerStatementRecord,
} from './org-issuer-statement';

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
