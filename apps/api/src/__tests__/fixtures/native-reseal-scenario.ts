import { mock } from 'bun:test';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { privateKeyToAddress } from 'viem/accounts';
import { verifyMessage } from 'viem';
import { SealingKeyring } from '../../../../../packages/tee/src/versioned-sealing';
import { prepareDelegationSession } from '../../routes/delegate-session';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { credentialHash } from '../../services/native-delegation/session-proof';
import { NATIVE_DELEGATION_ENDPOINT_PATHS, OPENKEY_SESSION_PROOF_HEADER } from '../../services/native-delegation/public-protocol';

// Subprocess isolation keeps these dependency replacements out of the API suite.
process.env.TEE_MODE = 'development';
process.env.NODE_ENV = 'test';
process.env.DEV_SEALING_KEY = 'TEST ONLY native maintenance scenario';
process.env.OPENKEY_NATIVE_RENEW_DISABLED = '0';
const operation = process.argv[2];
const corrupt = process.argv[3] === 'corrupt';
const secret = `0x${Buffer.alloc(32, 7).toString('hex')}` as const;
const address = privateKeyToAddress(secret);
const userId = 'TEST-native-maintenance-user';
const issuer = 'https://api.example/api/auth';
const clientId = 'TEST-native-maintenance-client';
const context = Buffer.alloc(32, 8).toString('base64url');
const binding = { recordId: 'TEST-native-key', sealingContext: `openkey/key/${context}` };
const providers = new Map([0, 1].map(kid => [kid, async (path: string) => createHash('sha256').update(`TEST native provider ${kid}/${path}`).digest()]));
const ring = new SealingKeyring({ providers, writeKid: 1 });
const legacyRing = new SealingKeyring({ providers });
const key = { id: binding.recordId, userId, address, sealedBlob: await legacyRing.seal(secret, binding), sealingContext: context };
const newBlob = corrupt ? 'TEST corrupt current blob' : await ring.seal(secret, binding);
let opens = 0;
mock.module('../../services/managed-key-signing', () => ({
  unsealManagedKey: async (row: typeof key, blob: string) => {
    opens++;
    return ring.unseal(blob, { recordId: row.id, sealingContext: `openkey/key/${row.sealingContext}` });
  },
  signManagedKey: async () => { throw new Error('Unexpected host signing'); },
}));
mock.module('../../auth', () => ({ auth: { api: { getSession: async () => ({ user: { id: userId }, session: { id: 'TEST-session' } }) } } }));

const sessionPrivateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 11)]),
  format: 'der', type: 'pkcs8',
});
const publicJwk = createPublicKey(sessionPrivateKey).export({ format: 'jwk' });
if (!publicJwk.x) throw new Error('TEST missing public coordinate');
const sessionJwk = { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x };
const sessionJkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: sessionJwk.x })).digest('base64url');
const permissions = [
  { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
  { service: 'tinycloud.kv', space: 'applications', path: 'xyz.example/notes/', actions: ['tinycloud.kv/get'] },
];
const client = { clientId, type: 'native', public: true, tokenEndpointAuthMethod: 'none', disabled: false,
  scopes: [TINYCLOUD_DELEGATION_SCOPE], tinycloudNativeDelegation: {
    version: 1, appId: 'xyz.example', tinycloudHost: 'https://tee.node.tinycloud.xyz',
    kv: { paths: ['xyz.example/notes/'], actions: ['get'] }, sql: null,
  } };
const prepared = prepareDelegationSession({ address, chainId: 1, prefix: 'applications', jwk: sessionJwk,
  permissions, expiryMs: 3600_000, domain: 'openkey.so', nonce: 'TESTNONCE12345', issuedAt: new Date() });
const requestRow = { id: 'TEST-request', userId, clientId, status: 'RESOLVED', expiresAt: new Date(Date.now() + 86_400_000),
  currentRevision: 1, siweNonce: 'TESTNONCE12345', sessionJwk, sessionJkt, sessionDid: prepared.prepared.verificationMethod };
const revision = { revision: 1, keyId: key.id, address, digest: 'TEST-digest', sessionSiwe: prepared.prepared.siwe,
  hostPlan: null, permissions, tinycloudHost: 'https://tee.node.tinycloud.xyz' };
const token = 'TEST-refresh-token';
const grant = { id: 'TEST-grant', userId, clientId, keyId: key.id, address,
  refreshTokenHash: credentialHash(token), previousRefreshTokenHash: null, sessionJwk, sessionJkt,
  sessionDid: prepared.prepared.verificationMethod, spaceId: prepared.spaceId,
  status: 'ACTIVE', rotatedAt: null, lastRenewedAt: null, consentId: 'TEST-consent', consentGeneration: 0n,
  approvedPermissions: permissions, ttlSeconds: 3600, absoluteExpiresAt: new Date(Date.now() + 86_400_000),
  tinycloudHost: 'https://tee.node.tinycloud.xyz' };
let changed = false;
const tx = {
  $executeRaw: async () => 0,
  $executeRawUnsafe: async () => 0,
  $queryRawUnsafe: async () => [{ generation: 0n }],
  $queryRaw: async (parts: TemplateStringsArray) => {
    const sql = parts.join('');
    if (sql.includes('oauth_consent')) return [{ id: 'TEST-consent', scopes: [TINYCLOUD_DELEGATION_SCOPE] }];
    if (sql.includes('consent_generation')) return [{ generation: 0n }];
    if (sql.includes('oauth_refresh_token')) return [{ id: 'TEST-refresh-row' }];
    return [];
  },
  ethereumKey: { findFirst: async () => structuredClone(key) },
  tinyCloudNativeRequest: {
    findUnique: async () => requestRow,
    findUniqueOrThrow: async () => requestRow,
    update: async ({ data }: { data: Record<string, unknown> }) => Object.assign(requestRow, data),
  },
  tinyCloudNativePreparation: { findUnique: async () => revision },
  oauthClient: { findUniqueOrThrow: async () => client, findUnique: async () => client },
  user: { findUnique: async () => ({ tinyCloudManageKeyMode: 'OPENKEY_MANAGED', tinyCloudManageKeyPolicyEpoch: 0n }) },
  tinyCloudNativeGrant: { findUnique: async () => grant, update: async () => grant },
  tinyCloudManageKeyAppPreference: { findUnique: async () => null },
  tinyCloudManageKeySigningDecision: { create: async () => ({}) },
  oauthRefreshToken: {
    findUnique: async () => ({ id: 'TEST-refresh-row', userId, clientId, scopes: [TINYCLOUD_DELEGATION_SCOPE], revoked: null,
      expiresAt: new Date(Date.now() + 86_400_000), sessionId: 'TEST-session', referenceId: null, authTime: new Date() }),
    update: async () => ({}), create: async () => ({}),
  },
};
const database = {
  ...tx,
  tinyCloudNativeGrant: { ...tx.tinyCloudNativeGrant, findFirst: async () => structuredClone(grant) },
  nativeSessionProofJti: { createMany: async () => ({ count: 1 }), deleteMany: async () => ({ count: 0 }) },
  $transaction: async <T>(callback: (transaction: typeof tx) => Promise<T>): Promise<T> => {
    if (!changed) { changed = true; key.sealedBlob = newBlob; }
    return callback(tx);
  },
};

try {
  let response: Response;
  if (operation === 'consent') {
    // Load only after the subprocess's auth and signing replacements exist.
    const { createNativeDelegationConsentRouter } = await import('../../routes/native-delegation-consent');
    // This in-memory adapter intentionally implements only the exercised Prisma operations.
    const router = createNativeDelegationConsentRouter(database as unknown as Parameters<typeof createNativeDelegationConsentRouter>[0], {
      fetchPeerId: async () => { throw new Error('Unexpected peer lookup'); },
      activateSessionWithHost: async () => ({ success: true, activated: [prepared.spaceId] }),
      submitHostDelegation: async () => { throw new Error('Unexpected host delegation'); },
      revokeDelegation: async () => { throw new Error('Unexpected revocation'); },
    });
    response = await router.request(`/${requestRow.id}/approve`, { method: 'POST',
      headers: { origin: 'http://localhost:5173', 'content-type': 'application/json' },
      body: JSON.stringify({ revision: 1, digest: revision.digest, sessionSiwe: revision.sessionSiwe }),
    });
  } else {
    // Load only after the subprocess's signing replacement exists.
    const { handleNativeRenewOrRevoke } = await import('../../services/native-delegation/renew-revoke');
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const header = encode({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: sessionJkt });
    const payload = encode({ jti: 'TEST-maintenance-proof-jti', iat: Math.floor(Date.now() / 1000), htm: 'POST',
      htu: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.renew}`, client_id: clientId, cred_hash: credentialHash(token) });
    const signature = sign(null, Buffer.from(`${header}.${payload}`), sessionPrivateKey).toString('base64url');
    response = await handleNativeRenewOrRevoke(new Request(`${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.renew}`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', [OPENKEY_SESSION_PROOF_HEADER]: `${header}.${payload}.${signature}` },
      body: new URLSearchParams({ client_id: clientId, refresh_token: token }),
    }), database as unknown as Parameters<typeof handleNativeRenewOrRevoke>[1], issuer, 'renew');
  }
  const body: unknown = await response.json();
  const artifact = operation === 'consent' ? ('delegation' in requestRow ? requestRow.delegation : undefined)
    : (typeof body === 'object' && body !== null && 'tinycloud_delegation' in body ? body.tinycloud_delegation : undefined);
  let signatureValid = false;
  if (artifact && typeof artifact === 'object' && 'signature' in artifact && 'siwe' in artifact
    && typeof artifact.signature === 'string' && typeof artifact.siwe === 'string') {
    signatureValid = await verifyMessage({ address, message: artifact.siwe, signature: artifact.signature as `0x${string}` });
  }
  process.stdout.write(JSON.stringify({ status: response.status, signatureValid, freshOpen: opens >= 2 }) + '\n');
} catch {
  process.stdout.write(JSON.stringify({ status: 500, signatureValid: false, freshOpen: opens >= 2 }) + '\n');
}
