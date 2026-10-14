import { afterEach, beforeEach, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { handleNativeRenewOrRevoke } from '../services/native-delegation/renew-revoke';
import { TINYCLOUD_DELEGATION_SCOPE } from '../oauth-config';
import { handlePar } from '../services/native-delegation/par';
import { NATIVE_DELEGATION_ENDPOINT_PATHS, OPENKEY_SESSION_PROOF_HEADER } from '../services/native-delegation/public-protocol';
import { credentialHash } from '../services/native-delegation/session-proof';

const emitted: string[] = [];
const stdoutWrite = process.stdout.write;

beforeEach(() => {
  emitted.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array) => { emitted.push(String(chunk)); return true; }) as typeof process.stdout.write;
});

afterEach(() => {
  process.stdout.write = stdoutWrite;
});

function captureInterval() {
  const original = globalThis.setInterval;
  let run: (() => void) | undefined;
  globalThis.setInterval = ((callback: () => void) => {
    run = callback;
    return { unref() {} } as Timer;
  }) as typeof globalThis.setInterval;
  return {
    tick() {
      if (!run) throw new Error('cleanup interval was not installed');
      run();
    },
    restore() { globalThis.setInterval = original; },
  };
}

async function waitForCleanupLog(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function assertCleanupRecord(event: string): void {
  const lines = emitted.map((line) => JSON.parse(line));
  const record = lines.find((line) => line.event === event);
  expect(record).toMatchObject({ event, request_id: 'scheduled', error_name: 'Error', error_code: 'P2010' });
  expect(Object.keys(record).sort()).toEqual(['error_code', 'error_name', 'event', 'level', 'request_id', 'ts']);
  expect(emitted.join('')).not.toContain('cleanup-canary');
}

test('PAR cleanup failure emits its allowlisted error record', async () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const sessionJwk = publicKey.export({ format: 'jwk' });
  if (!sessionJwk.x) throw new Error('test key is missing its public coordinate');
  const clientId = 'cleanup-client';
  const redirectUri = 'https://client.example/callback';
  const client = {
    clientId,
    type: 'native',
    public: true,
    tokenEndpointAuthMethod: 'none',
    disabled: false,
    redirectUris: [redirectUri],
    scopes: [TINYCLOUD_DELEGATION_SCOPE, 'offline_access'],
    tinycloudNativeDelegation: {
      version: 1,
      appId: 'cleanup-app',
      tinycloudHost: 'https://node.tinycloud.xyz',
      kv: { paths: ['cleanup-app/data'], actions: ['get'] },
      sql: null,
    },
  };
  let sweepCount = 0;
  const db = {
    oauthClient: { findUnique: async () => client },
    tinyCloudNativeRequest: {
      deleteMany: async () => {
        sweepCount++;
        if (sweepCount > 1) throw Object.assign(new Error('cleanup-canary'), { code: 'P2010' });
        return { count: 0 };
      },
      create: async () => ({}),
    },
  };
  const parameters = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    state: 'state-for-cleanup-test',
    code_challenge: Buffer.alloc(32, 1).toString('base64url'),
    code_challenge_method: 'S256',
    scope: `${TINYCLOUD_DELEGATION_SCOPE} offline_access`,
    authorization_details: JSON.stringify([{
      type: 'tinycloud_delegation',
      session_key: { kty: 'OKP', crv: 'Ed25519', x: sessionJwk.x },
      permissions: [
        { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
        { service: 'tinycloud.kv', space: 'applications', path: 'cleanup-app/data', actions: ['tinycloud.kv/get'] },
      ],
    }]),
  });
  const interval = captureInterval();
  try {
    const response = await handlePar(new Request('https://api.example/api/auth/oauth2/par', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: parameters,
    }), db as never);
    expect(response.status).toBe(201);
    interval.tick();
    await waitForCleanupLog();
  } finally {
    interval.restore();
  }
  assertCleanupRecord('native_par_request_cleanup_failed');
});

test('session-proof cleanup failure emits its allowlisted error record', async () => {
  const clientId = 'cleanup-client';
  const token = 'refresh-token-for-cleanup-test';
  const issuer = 'https://api.example/api/auth';
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const sessionJwk = publicKey.export({ format: 'jwk' });
  if (!sessionJwk.x) throw new Error('test key is missing its public coordinate');
  const sessionJkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: sessionJwk.x })).digest('base64url');
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    jti: 'cleanup-proof-jti-123456',
    iat,
    htm: 'POST',
    htu: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.revoke}`,
    client_id: clientId,
    cred_hash: credentialHash(token),
  };
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: sessionJkt });
  const encodedPayload = encode(payload);
  const signature = sign(null, Buffer.from(`${header}.${encodedPayload}`), privateKey).toString('base64url');
  const proof = `${header}.${encodedPayload}.${signature}`;
  const candidate = {
    id: 'grant-id',
    clientId,
    userId: 'user-id',
    refreshTokenHash: credentialHash(token),
    previousRefreshTokenHash: null,
    sessionJwk: { kty: 'OKP', crv: 'Ed25519', x: sessionJwk.x },
    sessionJkt,
    status: 'ACTIVE',
    rotatedAt: null,
    lastRenewedAt: null,
  };
  const grant = { ...candidate };
  let sweepCount = 0;
  const tx = {
    $executeRaw: async () => undefined,
    $queryRaw: async () => [],
    tinyCloudNativeGrant: {
      findUnique: async () => grant,
      update: async () => ({}),
    },
    oauthRefreshToken: {
      findMany: async () => [],
      deleteMany: async () => ({}),
    },
  };
  const db = {
    tinyCloudNativeGrant: { findFirst: async () => candidate },
    nativeSessionProofJti: {
      createMany: async () => ({ count: 1 }),
      deleteMany: async () => {
        sweepCount++;
        if (sweepCount > 1) throw Object.assign(new Error('cleanup-canary'), { code: 'P2010' });
        return { count: 0 };
      },
    },
    $transaction: async (operation: (transaction: typeof tx) => Promise<unknown>) => operation(tx),
  };
  const interval = captureInterval();
  try {
    const response = await handleNativeRenewOrRevoke(new Request(`${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS.revoke}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        [OPENKEY_SESSION_PROOF_HEADER]: proof,
      },
      body: new URLSearchParams({ client_id: clientId, refresh_token: token }),
    }), db as never, issuer, 'revoke');
    expect(response.status).toBe(200);
    interval.tick();
    await waitForCleanupLog();
  } finally {
    interval.restore();
  }
  assertCleanupRecord('native_session_proof_cleanup_failed');
});
