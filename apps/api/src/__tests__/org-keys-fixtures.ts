import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';
import type { TeeClient } from '@openkey/tee';
import { createOrgKey, ORG_KEY_ORIGIN } from '../services/org-keys';

// Shared fixtures for the org-key service and route tests. Not a test file.
// The fake Prisma client models only the operators org-keys.ts uses, and its
// $transaction rolls state back on throw, as Postgres does.

export const RP_ID = 'openkey.test';
export const ORIGIN = ORG_KEY_ORIGIN;
// Statement binding for org keys created by setupOrgKey (K4 D2: slug and issuerDid are required).
// ORG_ID is a canonical OrgId (T1 D1) and ISSUER_DID is derived from it (T1 D2), as in
// services/fixtures/org-issuer-authorization-v1/vectors.json.
export const SLUG = 'acme';
export const ORG_ID = 'oceirceirceirceirceirceirce';
export const ISSUER_DID = `did:web:${ORG_ID}.orgs.credentials.org`;

type Row = { [field: string]: unknown };
type Where = { [field: string]: unknown };

export function fakeTee(): TeeClient {
  return {
    deriveKey: async (...args: unknown[]) => new Uint8Array(createHash('sha256').update(JSON.stringify(args)).digest()),
    getQuote: async () => 'quote',
    isInTee: () => false,
  } as unknown as TeeClient;
}

// The fake implements only the operators the code under test uses. The cast is
// the test boundary: PrismaClient's full surface is not modelled here.
export function asPrisma(db: Row): PrismaClient {
  return db as unknown as PrismaClient;
}

export function fakeDb() {
  const state = {
    keys: [] as Row[],
    orgKeys: [] as Row[],
    grants: [] as Row[],
    passkeys: [] as Row[],
    audits: [] as Row[],
    challenges: [] as Row[],
    sessions: [] as Row[],
  };
  const fail = { auditInsert: false };
  let sequence = 0;
  const next = (prefix: string) => `${prefix}_${++sequence}`;

  const relation = (row: Row, field: string): Row | null => {
    if (field === 'key') return state.keys.find((key) => key.id === row.keyId) ?? null;
    if (field === 'orgKey') return state.orgKeys.find((orgKey) => orgKey.keyId === row.id) ?? null;
    throw new Error(`fake db: unmodelled relation ${field}`);
  };

  const isNotCondition = (condition: unknown): condition is { isNot: unknown } =>
    typeof condition === 'object' && condition !== null && 'isNot' in condition;

  const isGtCondition = (condition: unknown): condition is { gt: Date } =>
    typeof condition === 'object' && condition !== null && 'gt' in condition;

  const isLtCondition = (condition: unknown): condition is { lt: Date } =>
    typeof condition === 'object' && condition !== null && 'lt' in condition;

  const matches = (row: Row, where: Where): boolean =>
    Object.entries(where).every(([field, condition]) => {
      if (field === 'key' || field === 'orgKey') {
        const target = relation(row, field);
        if (isNotCondition(condition)) {
          return condition.isNot === null ? target !== null : target === null;
        }
        return target !== null && matches(target, condition as Where);
      }
      if (isGtCondition(condition)) return (row[field] as Date).getTime() > condition.gt.getTime();
      if (isLtCondition(condition)) return (row[field] as Date).getTime() < condition.lt.getTime();
      if (isNotCondition(condition)) {
        return condition.isNot === null ? row[field] != null : row[field] !== condition.isNot;
      }
      return condition === null ? row[field] == null : row[field] === condition;
    });

  const withRelations = (grant: Row): Row => {
    const key = relation(grant, 'key');
    return { ...grant, key: key ? { ...key, orgKey: relation(key, 'orgKey') } : null };
  };

  const api: Row = {
    ethereumKey: {
      create: async ({ data }: { data: Row }) => {
        const row = { id: next('key'), userId: null, archivedAt: null, label: null, sealedBlob: null, ...data };
        state.keys.push(row);
        return row;
      },
      findFirst: async ({ where }: { where: Where }) => state.keys.find((row) => matches(row, where)) ?? null,
    },
    orgKey: {
      create: async ({ data }: { data: Row }) => {
        const row = { id: next('orgkey'), ...data };
        state.orgKeys.push(row);
        return row;
      },
      findUnique: async ({ where }: { where: Where }) => state.orgKeys.find((row) => row.keyId === where.keyId) ?? null,
    },
    keyGrant: {
      create: async ({ data }: { data: Row }) => {
        const row = { id: next('grant'), revokedAt: null, revokedByUserId: null, acceptedAt: null, ...data };
        state.grants.push(row);
        return row;
      },
      findFirst: async ({ where }: { where: Where }) => {
        const grant = state.grants.find((row) => matches(row, where));
        return grant ? withRelations(grant) : null;
      },
      findMany: async ({ where }: { where: Where }) =>
        state.grants.filter((row) => matches(row, where)).map(withRelations),
    },
    // Models the FOR SHARE read in signOrgKeyMessage: values are grantId, keyId, userId
    // in statement order. The lock itself is covered by the real-Postgres test.
    $queryRaw: async (_strings: TemplateStringsArray, ...values: unknown[]) => {
      const [grantId, keyId, userId] = values;
      return state.grants
        .filter((row) => row.id === grantId && row.keyId === keyId && row.granteeUserId === userId && row.revokedAt == null)
        .map((row) => ({ id: row.id, role: row.role }));
    },
    orgKeySignChallenge: {
      create: async ({ data }: { data: Row }) => {
        const row = { id: next('challenge'), consumedAt: null, ...data };
        state.challenges.push(row);
        return row;
      },
      findFirst: async ({ where }: { where: Where }) => state.challenges.find((row) => matches(row, where)) ?? null,
      updateMany: async ({ where, data }: { where: Where; data: Row }) => {
        const rows = state.challenges.filter((row) => matches(row, where));
        for (const row of rows) Object.assign(row, data);
        return { count: rows.length };
      },
      deleteMany: async ({ where }: { where: Where }) => {
        const before = state.challenges.length;
        state.challenges = state.challenges.filter((row) => !matches(row, where));
        return { count: before - state.challenges.length };
      },
    },
    passkey: {
      findFirst: async ({ where }: { where: Where }) => state.passkeys.find((row) => matches(row, where)) ?? null,
      findMany: async ({ where }: { where: Where }) => state.passkeys.filter((row) => matches(row, where)),
      update: async ({ where, data }: { where: Where; data: Row }) => {
        const row = state.passkeys.find((passkey) => passkey.id === where.id);
        if (!row) throw new Error('fake db: passkey not found');
        Object.assign(row, data);
        return row;
      },
    },
    session: {
      findFirst: async ({ where }: { where: Where }) => state.sessions.find((row) => matches(row, where)) ?? null,
    },
    orgKeySignatureAudit: {
      create: async ({ data }: { data: Row }) => {
        if (fail.auditInsert) throw new Error('injected audit insert failure');
        if (state.audits.some((row) => row.passkeyAssertionHash === data.passkeyAssertionHash)) {
          throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
        }
        const row = { id: next('audit'), createdAt: new Date(), ...data };
        state.audits.push(row);
        return row;
      },
    },
    $transaction: async (callback: (tx: Row) => Promise<unknown>) => {
      const snapshot = structuredClone(state);
      try {
        return await callback(api);
      } catch (error) {
        Object.assign(state, snapshot);
        throw error;
      }
    },
  };

  return { db: api, state, fail };
}

export type PasskeyFixture = { credentialID: string; privateKey: KeyObject };

// Creates a P-256 passkey, stored the way Better Auth stores it: a COSE_Key
// (ES256) in standard base64.
export function addPasskey(state: { passkeys: Row[] }, userId: string, counter = 0): PasskeyFixture {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  // CBOR map {1: 2, 3: -7, -1: 1, -2: x, -3: y}
  const cose = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y,
  ]);
  const credentialID = randomBytes(16).toString('base64url');
  state.passkeys.push({
    id: `passkey_${state.passkeys.length + 1}`,
    userId,
    credentialID,
    publicKey: cose.toString('base64'),
    counter,
  });
  return { credentialID, privateKey };
}

// CBOR head for a major type and unsigned argument (RFC 8949 section 3).
function cborHead(major: number, value: number): number[] {
  if (value < 24) return [(major << 5) | value];
  if (value < 256) return [(major << 5) | 24, value];
  return [(major << 5) | 25, value >> 8, value & 0xff];
}

// Creates an RSA-2048 passkey with RS256 (alg -257), the algorithm Better Auth
// also registers (`[-8, -7, -257]`). Stored as a COSE_Key in standard base64.
export function addRs256Passkey(state: { passkeys: Row[] }, userId: string, counter = 0): PasskeyFixture {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
  const n = Buffer.from(jwk.n, 'base64url');
  const e = Buffer.from(jwk.e, 'base64url');
  // CBOR map {1: 3 (RSA), 3: -257 (RS256), -1: n, -2: e}
  const cose = Buffer.concat([
    Buffer.from([...cborHead(5, 4), 0x01, 0x03, 0x03, ...cborHead(1, 256), 0x20]),
    Buffer.from([...cborHead(2, n.length)]),
    n,
    Buffer.from([0x21]),
    Buffer.from([...cborHead(2, e.length)]),
    e,
  ]);
  const credentialID = randomBytes(16).toString('base64url');
  state.passkeys.push({
    id: `passkey_${state.passkeys.length + 1}`,
    userId,
    credentialID,
    publicKey: cose.toString('base64'),
    counter,
  });
  return { credentialID, privateKey };
}

// Creates an Ed25519 passkey with EdDSA (alg -8), the OKP key type that the
// raw-signature verification path handles. Stored as a COSE_Key in standard base64.
export function addEd25519Passkey(state: { passkeys: Row[] }, userId: string, counter = 0): PasskeyFixture {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const x = Buffer.from(jwk.x, 'base64url');
  // CBOR map {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}
  const cose = Buffer.concat([Buffer.from([0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]), x]);
  const credentialID = randomBytes(16).toString('base64url');
  state.passkeys.push({
    id: `passkey_${state.passkeys.length + 1}`,
    userId,
    credentialID,
    publicKey: cose.toString('base64'),
    counter,
  });
  return { credentialID, privateKey };
}

export function assertionFor(
  passkey: PasskeyFixture,
  challenge: string,
  options: { counter?: number; origin?: string; rpID?: string; userVerified?: boolean } = {},
): AuthenticationResponseJSON {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin: options.origin ?? ORIGIN, crossOrigin: false }),
  );
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(options.counter ?? 1);
  const flags = options.userVerified === false ? 0x01 : 0x05; // UP, plus UV unless disabled
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(options.rpID ?? RP_ID).digest(),
    Buffer.from([flags]),
    counter,
  ]);
  const signedData = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]);
  // Ed25519 signs the message itself; ECDSA and RSA sign its SHA-256 digest.
  const signature =
    passkey.privateKey.asymmetricKeyType === 'ed25519'
      ? sign(null, signedData, passkey.privateKey)
      : sign('sha256', signedData, passkey.privateKey);
  return {
    id: passkey.credentialID,
    rawId: passkey.credentialID,
    type: 'public-key',
    response: {
      clientDataJSON: clientDataJSON.toString('base64url'),
      authenticatorData: authenticatorData.toString('base64url'),
      signature: signature.toString('base64url'),
    },
    clientExtensionResults: {},
  };
}

// An ORG key owned by user_1 (OWNER grant), with one passkey for user_1.
export async function setupOrgKey(options: { counter?: number } = {}) {
  const { db, state, fail } = fakeDb();
  const tee = fakeTee();
  const key = await createOrgKey(asPrisma(db), tee, {
    userId: 'user_1',
    orgId: ORG_ID,
    orgName: 'Acme',
    slug: SLUG,
    label: null,
  });
  const passkey = addPasskey(state, 'user_1', options.counter ?? 0);
  addSession(state, 'user_1');
  return { db, state, fail, tee, key, passkey };
}

// A session row for the requireFreshPasskey gate. lastPasskeyAt defaults to now.
export function addSession(state: { sessions: Row[] }, userId: string, lastPasskeyAt: Date | null = new Date()) {
  const row = { id: 'session_1', userId, lastPasskeyAt, expiresAt: new Date(Date.now() + 60 * 60 * 1000) };
  state.sessions.push(row);
  return row;
}
