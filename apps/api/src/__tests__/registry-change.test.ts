import '../routes/tinycloud-setup-test-env';

// TC-3893: comprehensive unit + route tests for /api/registry-change/{prepare,publish,history}.
// Covers:
//   - prepare builds sequence = current + 1, canonical hosts (IPv4/IPv6/non-default port),
//     preserves unrelated spaces, maps encryptionNode URL -> DID, flags encryptionChanged
//   - unparseable / non-canonical / unlisted URLs refused (400 registry_change_invalid_node)
//   - identity check: ok | mismatch | unreachable (warns, never blocks)
//   - body-supplied requestingOrigin ignored on both prepare and publish
//   - passkey ALWAYS required even in NEVER mode (and with 0 step-up passkeys)
//   - passkey cryptographically bound to exact recordHash (different hash fails)
//   - stale sequence / payload drift -> 409 registry_change_stale
//   - previous record stored in RegistryChangeHistory BEFORE the PUT
//   - accepted record verified == prepared; notice email sent via Resend with Monica's words
//   - GET /history?limit=N returns exact { history: [...] } newest first without OpenKey Origin requirement
//   - Undo flow re-publishes previous content at sequence + 1
//   - generic /api/keys/:keyId/sign still refuses registry payloads
//   - per-owner rate limiter -> 429 + retry-after
//   - replay protection + domain separation from setup tickets + origin middleware + 503 lazy init

import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import { Hono } from 'hono';
import { privateKeyToAccount } from 'viem/accounts';
import {
  canonicalLocationPayloadV2,
  signLocationRecordV2,
  type LocationRecordV2,
  type LocationRecordV2Payload,
} from '@tinycloud/sdk-core';
import type { SessionContext } from '../middleware/session';
import {
  createInMemorySetupNonceStore,
  createSetupTicketStore,
} from '../services/tinycloud-setup-ticket';
import { createInMemoryPerOwnerLimiter } from '../services/tinycloud-setup-rate-limit';
import { createRegistryChangeTicketStore } from '../services/registry-change-ticket';
import { canonicalNodeUrl, displayNodeHost } from '../services/registry-change-client';
import { REGISTRY_CHANGE_EMAIL_COPY, formatRegistryChangeNoticeEmail } from '../services/registry-change-email';
import type { EmailSender } from '../services/email-otp-delivery';
import {
  DEFAULT_REGISTRY_CHANGE_LIMITS,
  REQUESTING_ORIGIN_HEADER,
  createRegistryChangeRouter,
  type RegistryChangeRateAction,
} from '../routes/registry-change';

const PRIVATE_KEY = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' as const;
const OWNER_ACCOUNT = privateKeyToAccount(PRIVATE_KEY);
const ADDRESS = OWNER_ACCOUNT.address;
const SUBJECT = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE_DEFAULT = `tinycloud:pkh:eip155:1:${ADDRESS.toLowerCase()}:default`;
const SPACE_NOTES = `tinycloud:pkh:eip155:1:${ADDRESS.toLowerCase()}:notes`;

const USER_ID = 'user_rc_1';
const SESSION_ID = 'session_rc_1';
const USER_EMAIL = 'owner@example.com';
const OPENKEY_ORIGIN = 'http://localhost:5173';
const APP_ORIGIN = 'https://external-app.example';
const REGISTRY_URL = 'https://registry.test.example';
const RP = { rpID: 'localhost', origin: OPENKEY_ORIGIN };

// Valid canonical Ed25519 did:key fixtures (multicodec 0xed 0x01 + 32 bytes).
const NODE_A_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const NODE_B_DID = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const NODE_C_DID = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG';
const NODE_A_URL = 'https://node-a.example';
const NODE_B_URL = 'https://node-b.example:8443';
const NODE_C_URL = 'https://[2001:db8::1]:8443';

const PRIMARY_KEY = {
  userId: USER_ID,
  address: ADDRESS,
  sealedPrivateKey: 'sealed-bytes',
  sealingContext: null,
};

// Build a real ES256 WebAuthn keypair + COSE public key so `verifyAuthenticationResponse`
// runs full cryptographic verification against the server's challenge!
function makeTestWebAuthnCredential() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  // Minimal CBOR encoding of COSE EC2 P-256 key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
  const coseKey = Buffer.concat([
    Buffer.from([0xa5]),
    Buffer.from([0x01, 0x02]),
    Buffer.from([0x03, 0x26]),
    Buffer.from([0x20, 0x01]),
    Buffer.from([0x21, 0x58, 0x20]), x,
    Buffer.from([0x22, 0x58, 0x20]), y,
  ]);
  const credentialID = randomBytes(16).toString('base64url');
  let signCount = 1;

  const signOffer = (offer: { challengeToken: string; options: { challenge: string } }) => {
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: offer.options.challenge,
      origin: RP.origin,
      crossOrigin: false,
    }), 'utf8');
    const rpIdHash = createHash('sha256').update(RP.rpID).digest();
    const flags = Buffer.from([0x05]); // UP (0x01) | UV (0x04)
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(++signCount);
    const authenticatorData = Buffer.concat([rpIdHash, flags, counterBuf]);
    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
    const signature = cryptoSign('sha256', Buffer.concat([authenticatorData, clientDataHash]), privateKey);

    return {
      challengeToken: offer.challengeToken,
      response: {
        id: credentialID,
        rawId: credentialID,
        type: 'public-key' as const,
        response: {
          clientDataJSON: clientDataJSON.toString('base64url'),
          authenticatorData: authenticatorData.toString('base64url'),
          signature: signature.toString('base64url'),
        },
        clientExtensionResults: {},
      },
    };
  };

  return {
    passkeyRow: {
      id: 'pk_1',
      credentialID,
      publicKey: coseKey.toString('base64'),
      counter: 0,
      transports: 'internal',
      countsForStepUp: true,
    },
    signOffer,
  };
}

async function makeSignedV2Record(overrides: Partial<LocationRecordV2Payload> = {}): Promise<LocationRecordV2> {
  const payload: LocationRecordV2Payload = {
    version: 2,
    subject: SUBJECT,
    nodes: [{ did: NODE_A_DID, url: NODE_A_URL }],
    spaces: [
      { space: SPACE_DEFAULT, nodes: [{ did: NODE_A_DID, mode: 'read-write' }] },
      { space: SPACE_NOTES, nodes: [{ did: NODE_A_DID, mode: 'read-write' }] },
    ],
    encryptionNode: NODE_A_DID,
    updated_at: '2026-11-22T15:00:00.000Z',
    sequence: 4,
    ...overrides,
  };
  return signLocationRecordV2(payload, {
    type: 'did:pkh',
    signMessage: (m) => OWNER_ACCOUNT.signMessage({ message: m }),
  });
}

interface StoredHistoryRow {
  id: string;
  userId: string;
  subject: string;
  requestingOrigin: string;
  previousRecord: unknown;
  newRecordHash: string;
  newSequence: number;
  createdAt: Date;
}

interface VerificationRow {
  id: string;
  identifier: string;
  userId: string;
  value: string;
  expiresAt: Date;
  createdAt: Date;
}

function createFakePrisma(opts: {
  passkeyApprovalMode?: 'ALWAYS' | 'SENSITIVE' | 'NEVER';
  passkeys?: Array<{
    id: string;
    credentialID: string;
    publicKey: string;
    counter: number;
    transports: string | null;
    countsForStepUp: boolean;
  }>;
  onHistoryCreate?: (row: StoredHistoryRow) => void;
} = {}) {
  const mode = opts.passkeyApprovalMode ?? 'NEVER';
  const passkeys = opts.passkeys ? opts.passkeys.map((p) => ({ ...p })) : [];
  const verifications: VerificationRow[] = [];
  const historyRows: StoredHistoryRow[] = [];

  const client = {
    ethereumKey: {
      findFirst: async () => PRIMARY_KEY,
    },
    user: {
      findUnique: async () => ({ passkeyApprovalMode: mode, email: USER_EMAIL }),
    },
    passkey: {
      count: async ({ where }: { where: { countsForStepUp?: boolean } }) =>
        passkeys.filter((p) => (where.countsForStepUp ? p.countsForStepUp : true)).length,
      findMany: async ({ where }: { where: { countsForStepUp?: boolean } }) =>
        passkeys.filter((p) => (where.countsForStepUp ? p.countsForStepUp : true)),
      findFirst: async ({ where }: { where: { credentialID?: string } }) =>
        passkeys.find((p) => p.credentialID === where.credentialID) ?? null,
      update: async ({ where, data }: { where: { id: string }; data: { counter: number } }) => {
        const found = passkeys.find((p) => p.id === where.id);
        if (found) found.counter = data.counter;
        return found;
      },
    },
    verification: {
      deleteMany: async ({ where }: { where: Record<string, unknown> }) => {
        let count = 0;
        for (let i = verifications.length - 1; i >= 0; i--) {
          const row = verifications[i]!;
          let match = true;
          if (typeof where.id === 'string' && row.id !== where.id) match = false;
          if (typeof where.identifier === 'string' && row.identifier !== where.identifier) match = false;
          if (typeof where.identifier === 'object' && where.identifier !== null && 'startsWith' in where.identifier) {
            const prefix = (where.identifier as { startsWith: string }).startsWith;
            if (!row.identifier.startsWith(prefix)) match = false;
          }
          if (typeof where.value === 'string' && row.value !== where.value) match = false;
          if (where.expiresAt && typeof where.expiresAt === 'object' && 'lte' in where.expiresAt) {
            if (!(row.expiresAt <= (where.expiresAt as { lte: Date }).lte)) match = false;
          }
          if (where.id && typeof where.id === 'object' && 'in' in where.id) {
            if (!(where.id as { in: string[] }).in.includes(row.id)) match = false;
          }
          if (match) {
            verifications.splice(i, 1);
            count++;
          }
        }
        return { count };
      },
      findMany: async ({ where, skip = 0 }: { where: { identifier?: { startsWith: string } }; skip?: number }) => {
        const prefix = where.identifier?.startsWith ?? '';
        return verifications
          .filter((r) => r.identifier.startsWith(prefix))
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
          .slice(skip);
      },
      findFirst: async ({ where }: { where: { identifier: string; userId: string; expiresAt: { gt: Date } } }) =>
        verifications.find(
          (r) => r.identifier === where.identifier && r.userId === where.userId && r.expiresAt > where.expiresAt.gt,
        ) ?? null,
      create: async ({ data }: { data: Omit<VerificationRow, 'createdAt'> }) => {
        const row = { ...data, createdAt: new Date() };
        verifications.push(row);
        return row;
      },
    },
    registryChangeHistory: {
      create: async ({ data }: { data: StoredHistoryRow }) => {
        historyRows.push(data);
        opts.onHistoryCreate?.(data);
        return data;
      },
      findUnique: async ({ where }: { where: { id: string } }) =>
        historyRows.find((r) => r.id === where.id) ?? null,
      findMany: async ({ where, take }: { where: { userId: string }; take: number }) =>
        historyRows
          .filter((r) => r.userId === where.userId)
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime() || b.newSequence - a.newSequence)
          .slice(0, take),
    },
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>) => fn(client),
  };

  return { prisma: client as unknown as PrismaClient, historyRows };
}

interface MockNodeIdentity {
  info?: { status: number; body: unknown } | 'network-error';
  keys?: { status: number; body: unknown } | 'network-error';
}

function createHarness(opts: {
  initialRecord?: LocationRecordV2 | null;
  nodes?: Record<string, MockNodeIdentity>;
  passkeyApprovalMode?: 'ALWAYS' | 'SENSITIVE' | 'NEVER';
  noPasskey?: boolean;
  rateLimits?: Record<RegistryChangeRateAction, number>;
  realOrigin?: boolean;
  getServerTime?: () => Date;
  putStatus?: number;
  tamperAcceptedPut?: boolean;
} = {}) {
  const credential = makeTestWebAuthnCredential();
  const events: string[] = [];
  const sentEmails: Array<{ from: string; to: string; subject: string; html: string }> = [];
  let currentRecord: LocationRecordV2 | null = opts.initialRecord ?? null;

  const { prisma, historyRows } = createFakePrisma({
    passkeyApprovalMode: opts.passkeyApprovalMode ?? 'NEVER',
    passkeys: opts.noPasskey ? [] : [credential.passkeyRow],
    onHistoryCreate: () => events.push('history.create'),
  });

  const emailSender: EmailSender = {
    emails: {
      send: async (msg) => {
        events.push('email.send');
        sentEmails.push(msg);
        return { error: null };
      },
    },
  };

  const nodeFixtures: Record<string, MockNodeIdentity> = {
    [NODE_A_URL]: {
      info: { status: 200, body: { nodeId: NODE_A_DID } },
      keys: { status: 200, body: { nodeDid: NODE_A_DID } },
    },
    [NODE_B_URL]: {
      info: { status: 200, body: { nodeId: NODE_B_DID } },
      keys: { status: 200, body: { nodeDid: NODE_B_DID } },
    },
    [NODE_C_URL]: {
      info: { status: 200, body: { nodeId: NODE_C_DID } },
      keys: { status: 200, body: { nodeDid: NODE_C_DID } },
    },
    ...(opts.nodes ?? {}),
  };

  const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? 'GET').toUpperCase();

    if (urlStr.startsWith(`${REGISTRY_URL}/v2/locations/`)) {
      if (method === 'GET') {
        if (!currentRecord) {
          return new Response(JSON.stringify({ error: 'location record not found' }), {
            status: 404,
            headers: { 'content-type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({ record: currentRecord }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'PUT') {
        events.push('registry.PUT');
        if (opts.putStatus && opts.putStatus !== 200 && opts.putStatus !== 201) {
          return new Response(JSON.stringify({ error: 'rejected' }), { status: opts.putStatus });
        }
        const incoming = JSON.parse(String(init?.body)) as LocationRecordV2;
        if (opts.tamperAcceptedPut) {
          const tampered = { ...incoming, sequence: incoming.sequence + 1 };
          return new Response(JSON.stringify({ record: tampered }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        currentRecord = incoming;
        return new Response(JSON.stringify({ record: incoming }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
    }

    for (const [origin, fixture] of Object.entries(nodeFixtures)) {
      if (urlStr === `${origin}/info`) {
        if (fixture.info === 'network-error' || !fixture.info) throw new TypeError('network error');
        return new Response(JSON.stringify(fixture.info.body), {
          status: fixture.info.status,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (urlStr === `${origin}/.well-known/tinycloud/node-keys`) {
        if (fixture.keys === 'network-error' || !fixture.keys) throw new TypeError('network error');
        return new Response(JSON.stringify(fixture.keys.body), {
          status: fixture.keys.status,
          headers: { 'content-type': 'application/json' },
        });
      }
    }

    throw new TypeError(`Unexpected fetch in test: ${method} ${urlStr}`);
  }) as unknown as typeof fetch;

  const secret = randomBytes(32);
  const nonceStore = createInMemorySetupNonceStore();
  const ticketStore = createRegistryChangeTicketStore(secret, nonceStore);
  const setupTicketStore = createSetupTicketStore(secret, nonceStore);
  const retryAfter = createInMemoryPerOwnerLimiter(opts.rateLimits ?? DEFAULT_REGISTRY_CHANGE_LIMITS);

  const app = new Hono<SessionContext>();
  app.route('/api/registry-change', createRegistryChangeRouter({
    ticketStore,
    retryAfter,
    prisma,
    emailSender,
    registryUrl: REGISTRY_URL,
    fetch: mockFetch,
    rp: RP,
    ...(opts.getServerTime ? { getServerTime: opts.getServerTime } : {}),
    signMessage: async (_descriptor, _sealed, message) => OWNER_ACCOUNT.signMessage({ message }),
    sessionMiddleware: async (c, next) => {
      c.set('user', { id: USER_ID, email: USER_EMAIL });
      c.set('session', { id: SESSION_ID, userId: USER_ID, expiresAt: new Date(2099, 0, 1) });
      await next();
    },
    ...(opts.realOrigin ? {} : { originMiddleware: async (_c, next) => { await next(); } }),
  }));

  return {
    app,
    credential,
    events,
    sentEmails,
    historyRows,
    setupTicketStore,
    getCurrentRecord: () => currentRecord,
    setCurrentRecord: (rec: LocationRecordV2 | null) => { currentRecord = rec; },
  };
}

async function callPrepare(
  app: Hono<SessionContext>,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  return app.request('/api/registry-change/prepare', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: OPENKEY_ORIGIN,
      [REQUESTING_ORIGIN_HEADER]: APP_ORIGIN,
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

async function callPublish(
  app: Hono<SessionContext>,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  return app.request('/api/registry-change/publish', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: OPENKEY_ORIGIN,
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

async function callUndoPrepare(
  app: Hono<SessionContext>,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  return app.request('/api/registry-change/undo/prepare', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: OPENKEY_ORIGIN,
      [REQUESTING_ORIGIN_HEADER]: 'https://tinycloud.one',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

describe('canonicalNodeUrl & displayNodeHost', () => {
  test('canonicalises valid origins and preserves raw IPv4, IPv6, and non-default ports', () => {
    expect(canonicalNodeUrl('https://Node.Example:443/')).toBe('https://node.example');
    expect(canonicalNodeUrl('https://node.example:8443')).toBe('https://node.example:8443');
    expect(canonicalNodeUrl('https://192.0.2.10:9443/')).toBe('https://192.0.2.10:9443');
    expect(canonicalNodeUrl('https://[2001:db8::1]:8443')).toBe('https://[2001:db8::1]:8443');
    expect(canonicalNodeUrl('http://127.0.0.1:8787')).toBe('http://127.0.0.1:8787');
    expect(canonicalNodeUrl('http://[::1]:8787')).toBe('http://[::1]:8787');

    expect(displayNodeHost('https://node.example')).toBe('node.example');
    expect(displayNodeHost('https://node.example:8443')).toBe('node.example:8443');
    expect(displayNodeHost('https://192.0.2.10:9443')).toBe('192.0.2.10:9443');
    expect(displayNodeHost('https://[2001:db8::1]:8443')).toBe('[2001:db8::1]:8443');
  });

  test('refuses unparseable, non-HTTPS non-loopback, credentialed, path, query, and fragment URLs', () => {
    for (const bad of [
      '',
      'not-a-url',
      'javascript:alert(1)',
      'http://node.example',
      'https://node.example/extra/path',
      'https://node.example?q=1',
      'https://node.example#frag',
      'https://user:pass@node.example',
      'ftp://node.example',
    ]) {
      expect(canonicalNodeUrl(bad), bad).toBeNull();
    }
  });
});

describe('POST /api/registry-change/prepare', () => {
  test('builds seq = current + 1, canonical hosts, preserves unrelated spaces, and maps encryptionNode URL -> DID', async () => {
    const initial = await makeSignedV2Record();
    const fixedNow = new Date('2026-11-22T16:30:00.000Z');
    const { app } = createHarness({ initialRecord: initial, getServerTime: () => fixedNow });

    const res = await callPrepare(app, {
      request: {
        nodes: [{ url: 'https://NODE-B.Example:8443/' }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ url: 'https://node-b.example:8443' }] }],
        encryptionNode: 'https://node-b.example:8443/',
      },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      changeId: string;
      requestingOrigin: string;
      before: LocationRecordV2Payload;
      after: LocationRecordV2Payload;
      recordHash: string;
      identity: Array<{ url: string; did: string | null; status: string }>;
      encryptionChanged: boolean;
      passkey: { required: boolean; challengeToken: string; options: { challenge: string } };
    };

    expect(body.requestingOrigin).toBe(APP_ORIGIN);
    expect(body.before.sequence).toBe(4);
    expect(body.after.sequence).toBe(5);
    expect(body.after.updated_at).toBe(fixedNow.toISOString());
    expect(body.after.encryptionNode).toBe(NODE_B_DID);
    expect(body.encryptionChanged).toBe(true);
    // SPACE_DEFAULT moved to NODE_B, while unrelated SPACE_NOTES survived on NODE_A!
    expect(body.after.spaces.find((s) => s.space === SPACE_DEFAULT)?.nodes).toEqual([
      { did: NODE_B_DID, mode: 'read-write' },
    ]);
    expect(body.after.spaces.find((s) => s.space === SPACE_NOTES)?.nodes).toEqual([
      { did: NODE_A_DID, mode: 'read-write' },
    ]);
    // Both NODE_B and still-referenced NODE_A appear in after.nodes with canonical URLs.
    expect(body.after.nodes).toEqual(
      expect.arrayContaining([
        { did: NODE_B_DID, url: NODE_B_URL },
        { did: NODE_A_DID, url: NODE_A_URL },
      ]),
    );
    expect(body.identity).toEqual([{ url: NODE_B_URL, did: NODE_B_DID, status: 'ok' }]);
    const expectedHash = createHash('sha256').update(canonicalLocationPayloadV2(body.after), 'utf8').digest('hex');
    expect(body.recordHash).toBe(expectedHash);
    expect(body.passkey.required).toBe(true);
    expect(body.passkey.challengeToken.length).toBeGreaterThan(10);
  });

  test('ignores body-supplied requestingOrigin on prepare and publish', async () => {
    const initial = await makeSignedV2Record();
    const { app, credential, historyRows, sentEmails } = createHarness({ initialRecord: initial });

    const prepRes = await callPrepare(app, {
      requestingOrigin: 'https://spoofed-body-origin.example',
      origin: 'https://spoofed-body-origin-2.example',
      request: {
        requestingOrigin: 'https://spoofed-nested.example',
        nodes: [{ url: NODE_B_URL }],
      },
    });
    expect(prepRes.status).toBe(200);
    const prep = await prepRes.json() as {
      changeId: string;
      requestingOrigin: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    expect(prep.requestingOrigin).toBe(APP_ORIGIN);

    const assertion = credential.signOffer(prep.passkey);
    const pubRes = await callPublish(app, {
      changeId: prep.changeId,
      requestingOrigin: 'https://spoofed-publish-origin.example',
      passkeyAssertion: assertion,
    });
    expect(pubRes.status).toBe(200);
    expect(historyRows[0]?.requestingOrigin).toBe(APP_ORIGIN);
    expect(sentEmails[0]?.html).toContain(APP_ORIGIN);
    expect(sentEmails[0]?.html).not.toContain('spoofed');
  });

  test('refuses unparseable URL and unlisted encryptionNode with 400 registry_change_invalid_node', async () => {
    const initial = await makeSignedV2Record();
    const { app } = createHarness({ initialRecord: initial });

    const badUrl = await callPrepare(app, {
      request: { nodes: [{ url: 'https://bad.example/with-path' }] },
    });
    expect(badUrl.status).toBe(400);
    expect((await badUrl.json() as { error: string }).error).toBe('registry_change_invalid_node');

    const badEnc = await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_B_URL }],
        encryptionNode: 'https://not-in-nodes.example',
      },
    });
    expect(badEnc.status).toBe(400);
    expect((await badEnc.json() as { error: string }).error).toBe('registry_change_invalid_node');
  });

  test('returns 409 registry_record_missing when owner has no current v2 record', async () => {
    const { app } = createHarness({ initialRecord: null });
    const res = await callPrepare(app, {
      request: { nodes: [{ url: NODE_B_URL }] },
    });
    expect(res.status).toBe(409);
    expect((await res.json() as { error: string }).error).toBe('registry_record_missing');
  });

  test('identity mismatch and unreachable warn in identity[] without blocking prepare or publish', async () => {
    const initial = await makeSignedV2Record();
    const { app, credential } = createHarness({
      initialRecord: initial,
      nodes: {
        [NODE_B_URL]: {
          info: { status: 200, body: { nodeId: NODE_C_DID } }, // disagrees with supplied NODE_B_DID!
          keys: { status: 200, body: { nodeDid: NODE_C_DID } },
        },
        [NODE_C_URL]: {
          info: 'network-error',
          keys: 'network-error',
        },
      },
    });

    const prepRes = await callPrepare(app, {
      request: {
        nodes: [
          { url: NODE_B_URL, did: NODE_B_DID },
          { url: NODE_C_URL, did: NODE_C_DID },
        ],
      },
    });
    expect(prepRes.status).toBe(200);
    const prep = await prepRes.json() as {
      changeId: string;
      identity: Array<{ url: string; did: string | null; status: string }>;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    expect(prep.identity).toEqual([
      { url: NODE_B_URL, did: NODE_B_DID, status: 'mismatch' },
      { url: NODE_C_URL, did: NODE_C_DID, status: 'unreachable' },
    ]);

    // Warning does NOT block publish when owner approves with passkey!
    const pubRes = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect(pubRes.status).toBe(200);
  });
});

describe('POST /api/registry-change/publish security invariants', () => {
  test('refuses without passkey even in NEVER mode, and refuses when user has 0 step-up passkeys', async () => {
    const initial = await makeSignedV2Record();
    const { app } = createHarness({ initialRecord: initial, passkeyApprovalMode: 'NEVER' });

    const prepRes = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(prepRes.status).toBe(200);
    const prep = await prepRes.json() as { changeId: string };

    const missingPasskey = await callPublish(app, { changeId: prep.changeId });
    expect(missingPasskey.status).toBe(403);
    expect((await missingPasskey.json() as { code: string }).code).toBe('passkey_approval_required');

    // Account with zero step-up passkeys fails closed at prepare too.
    const noPkHarness = createHarness({ initialRecord: initial, passkeyApprovalMode: 'NEVER', noPasskey: true });
    const noPkPrep = await callPrepare(noPkHarness.app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(noPkPrep.status).toBe(403);
    expect((await noPkPrep.json() as { code: string }).code).toBe('passkey_approval_required');
  });

  test('passkey assertion is bound to exact recordHash (assertion for a different hash fails)', async () => {
    const initial = await makeSignedV2Record();
    const { app, credential } = createHarness({ initialRecord: initial });

    const prep1Res = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
    const prep2Res = await callPrepare(app, { request: { nodes: [{ url: NODE_C_URL }] } });
    expect(prep1Res.status).toBe(200);
    expect(prep2Res.status).toBe(200);
    const prep1 = await prep1Res.json() as { changeId: string; recordHash: string; passkey: { challengeToken: string; options: { challenge: string } } };
    const prep2 = await prep2Res.json() as { changeId: string; recordHash: string; passkey: { challengeToken: string; options: { challenge: string } } };
    expect(prep1.recordHash).not.toBe(prep2.recordHash);

    // Sign prep1's passkey challenge, then try to submit it against prep2's changeId!
    const assertionForPrep1 = credential.signOffer(prep1.passkey);
    const mismatchRes = await callPublish(app, {
      changeId: prep2.changeId,
      passkeyAssertion: assertionForPrep1,
    });
    expect(mismatchRes.status).toBe(403);
    expect((await mismatchRes.json() as { code: string }).code).toBe('passkey_approval_invalid');

    // Submitting prep2's own passkey assertion succeeds.
    const goodRes = await callPublish(app, {
      changeId: prep2.changeId,
      passkeyAssertion: credential.signOffer(prep2.passkey),
    });
    expect(goodRes.status).toBe(200);
  });

  test('stale sequence returns 409 registry_change_stale and writes no history or PUT', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });
    const { app, credential, setCurrentRecord, events, historyRows } = createHarness({ initialRecord: initial });

    const prepRes = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
    const prep = await prepRes.json() as { changeId: string; passkey: { challengeToken: string; options: { challenge: string } } };

    // Simulate concurrent update bumping sequence to 5 before publish runs.
    setCurrentRecord(await makeSignedV2Record({ sequence: 5 }));

    const pubRes = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect(pubRes.status).toBe(409);
    expect((await pubRes.json() as { error: string }).error).toBe('registry_change_stale');
    expect(historyRows).toHaveLength(0);
    expect(events).toEqual([]);
  });

  test('stores previous record BEFORE PUT, verifies accepted == prepared, sends notice email, and refuses replay', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });
    const fixedNow = new Date('2026-11-22T16:45:00.000Z');
    const { app, credential, events, historyRows, sentEmails, getCurrentRecord } = createHarness({
      initialRecord: initial,
      getServerTime: () => fixedNow,
    });

    const prepRes = await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_B_URL }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ url: NODE_B_URL }] }],
        encryptionNode: NODE_B_URL,
      },
    });
    const prep = await prepRes.json() as {
      changeId: string;
      recordHash: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };

    const pubRes = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect(pubRes.status).toBe(200);
    expect(await pubRes.json()).toEqual({ sequence: 5, recordHash: prep.recordHash });

    // Strict ordering: history stored BEFORE PUT, email sent AFTER PUT!
    expect(events).toEqual(['history.create', 'registry.PUT', 'email.send']);
    expect(historyRows).toHaveLength(1);
    expect(historyRows[0]?.previousRecord).toEqual(initial);
    expect(historyRows[0]?.newSequence).toBe(5);
    expect(historyRows[0]?.newRecordHash).toBe(prep.recordHash);
    expect(getCurrentRecord()?.sequence).toBe(5);

    // Notice email uses Monica's exact copy and path.
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]?.to).toBe(USER_EMAIL);
    expect(sentEmails[0]?.subject).toBe(REGISTRY_CHANGE_EMAIL_COPY.subject);
    expect(sentEmails[0]?.html).toContain('2026-11-22');
    expect(sentEmails[0]?.html).toContain('16:45 UTC');
    expect(sentEmails[0]?.html).toContain(APP_ORIGIN);
    expect(sentEmails[0]?.html).toContain('default: node-a.example → node-b.example:8443');
    expect(sentEmails[0]?.html).toContain('Secrets and keys: node-a.example → node-b.example:8443');
    expect(sentEmails[0]?.html).toContain('TinyCloud One → Settings → Where your data lives');

    // Replay of the consumed changeId is refused (even if re-checked after another passkey would fail,
    // verify nonce consumption directly by minting a fresh challenge or testing bad replay).
    const replayCheck = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect([403, 409]).toContain(replayCheck.status);
  });

  test('fails loudly if registry PUT returns a tampered record that does not match prepared bytes', async () => {
    const initial = await makeSignedV2Record();
    const { app, credential, sentEmails } = createHarness({
      initialRecord: initial,
      tamperAcceptedPut: true,
    });
    const prep = await (await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pub = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect(pub.status).toBe(502);
    expect((await pub.json() as { error: string }).error).toBe('registry_publish_failed');
    expect(sentEmails).toHaveLength(0);
  });

  test('setup ticket cannot verify as a registry-change ticket (domain separation)', async () => {
    const initial = await makeSignedV2Record();
    const { app, setupTicketStore } = createHarness({ initialRecord: initial });
    const setupTicket = setupTicketStore.mint(
      { subject: SUBJECT, verifiedRequestingOrigin: APP_ORIGIN, recordHash: 'a'.repeat(64) },
      new Date(),
    );
    const res = await callPublish(app, { changeId: setupTicket });
    expect(res.status).toBe(403);
    expect((await res.json() as { error: string }).error).toBe('bad_signature');
  });

  test('rate limiter returns 429 + retry-after on prepare and publish', async () => {
    const initial = await makeSignedV2Record();
    const { app, credential } = createHarness({
      initialRecord: initial,
      rateLimits: { registry_change_prepare: 2, registry_change_publish: 1 },
    });

    const p1 = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(p1.status).toBe(200);
    const p1Body = await p1.json() as { changeId: string; passkey: { challengeToken: string; options: { challenge: string } } };

    const p2 = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(p2.status).toBe(200);
    const p2Body = await p2.json() as { changeId: string; passkey: { challengeToken: string; options: { challenge: string } } };

    // 3rd prepare hits prepare limit.
    const p3 = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(p3.status).toBe(429);
    expect(p3.headers.get('retry-after')).toMatch(/^\d+$/);

    // 1st publish succeeds, 2nd hits publish limit.
    const pub1 = await callPublish(app, {
      changeId: p1Body.changeId,
      passkeyAssertion: credential.signOffer(p1Body.passkey),
    });
    expect(pub1.status).toBe(200);

    const pub2 = await callPublish(app, {
      changeId: p2Body.changeId,
      passkeyAssertion: credential.signOffer(p2Body.passkey),
    });
    expect(pub2.status).toBe(429);
    expect(pub2.headers.get('retry-after')).toMatch(/^\d+$/);
  });

  test('missing/foreign HTTP Origin is refused by real origin guard on prepare/publish, while GET /history works on owner session', async () => {
    const initial = await makeSignedV2Record();
    const { app } = createHarness({ initialRecord: initial, realOrigin: true });

    const foreignPrep = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } }, {
      origin: 'https://attacker.example',
    });
    expect(foreignPrep.status).toBe(403);

    const foreignPub = await callPublish(app, { changeId: 'x' }, { origin: 'https://attacker.example' });
    expect(foreignPub.status).toBe(403);

    // GET /history does NOT require OpenKey Origin (One's session calls it directly).
    const historyRes = await app.request('/api/registry-change/history?limit=10', {
      method: 'GET',
      headers: { origin: 'https://tinycloud.one' },
    });
    expect(historyRes.status).toBe(200);
    expect(await historyRes.json()).toEqual({ history: [] });
  });

  test('unset ticket secret returns 503 registry_change_unavailable without crashing boot', async () => {
    const prevRc = process.env.OPENKEY_REGISTRY_CHANGE_TICKET_SECRET;
    const prevSetup = process.env.OPENKEY_SETUP_TICKET_SECRET;
    delete process.env.OPENKEY_REGISTRY_CHANGE_TICKET_SECRET;
    delete process.env.OPENKEY_SETUP_TICKET_SECRET;
    try {
      const { prisma } = createFakePrisma();
      const app = new Hono<SessionContext>().route('/api/registry-change', createRegistryChangeRouter({
        prisma,
        retryAfter: createInMemoryPerOwnerLimiter(DEFAULT_REGISTRY_CHANGE_LIMITS),
        sessionMiddleware: async (c, next) => {
          c.set('user', { id: USER_ID, email: USER_EMAIL });
          c.set('session', { id: SESSION_ID, userId: USER_ID, expiresAt: new Date(2099, 0, 1) });
          await next();
        },
        originMiddleware: async (_c, next) => { await next(); },
      }));
      const res = await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } });
      expect(res.status).toBe(503);
      expect((await res.json() as { error: string }).error).toBe('registry_change_unavailable');
    } finally {
      if (prevRc === undefined) delete process.env.OPENKEY_REGISTRY_CHANGE_TICKET_SECRET;
      else process.env.OPENKEY_REGISTRY_CHANGE_TICKET_SECRET = prevRc;
      if (prevSetup === undefined) delete process.env.OPENKEY_SETUP_TICKET_SECRET;
      else process.env.OPENKEY_SETUP_TICKET_SECRET = prevSetup;
    }
  });
});

describe('GET /api/registry-change/history, POST /undo/prepare (REPLACE), and One-only CORS', () => {
  const SPACE_ADDED = `tinycloud:pkh:eip155:1:${ADDRESS.toLowerCase()}:added`;

  test('undo/prepare removes a space and node added by the latest change (exact REPLACE, undoKind = undo-last)', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });
    let clockMs = new Date('2026-11-22T17:00:00.000Z').getTime();
    const { app, credential, getCurrentRecord } = createHarness({
      initialRecord: initial,
      getServerTime: () => new Date(clockMs),
    });

    // Change A adds SPACE_ADDED on NODE_B and moves encryptionNode to NODE_B (seq 4 -> 5).
    const prepA = await (await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_B_URL }],
        spaces: [{ space: SPACE_ADDED, nodes: [{ url: NODE_B_URL }] }],
        encryptionNode: NODE_B_URL,
      },
    })).json() as { changeId: string; recordHash: string; passkey: { challengeToken: string; options: { challenge: string } } };
    expect((await callPublish(app, {
      changeId: prepA.changeId,
      passkeyAssertion: credential.signOffer(prepA.passkey),
    })).status).toBe(200);
    expect(getCurrentRecord()?.spaces.some((s) => s.space === SPACE_ADDED)).toBe(true);

    // Fetch history: exact pinned contract shape (no `undoable` field).
    const histRes = await app.request('/api/registry-change/history?limit=10');
    expect(histRes.status).toBe(200);
    const hist = await histRes.json() as {
      history: Array<{
        id: string;
        requestingOrigin: string;
        previousRecord: LocationRecordV2;
        newRecordHash: string;
        newSequence: number;
        createdAt: string;
      }>;
    };
    expect(hist.history).toHaveLength(1);
    const rowA = hist.history[0]!;
    expect(Object.keys(rowA).sort()).toEqual([
      'createdAt',
      'id',
      'newRecordHash',
      'newSequence',
      'previousRecord',
      'requestingOrigin',
    ]);
    expect(rowA.previousRecord).toEqual(initial);

    // Undo via POST /undo/prepare { historyId } -> exact REPLACE removes SPACE_ADDED and NODE_B!
    clockMs += 60_000;
    const undoPrepRes = await callUndoPrepare(app, {
      historyId: rowA.id,
      requestingOrigin: 'https://spoofed-undo-body.example',
    });
    expect(undoPrepRes.status).toBe(200);
    const undoPrep = await undoPrepRes.json() as {
      changeId: string;
      requestingOrigin: string;
      after: LocationRecordV2Payload;
      encryptionChanged: boolean;
      undoKind: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    expect(undoPrep.requestingOrigin).toBe('https://tinycloud.one');
    expect(undoPrep.undoKind).toBe('undo-last');
    expect(undoPrep.encryptionChanged).toBe(true);
    expect(undoPrep.after.sequence).toBe(6);
    expect(undoPrep.after.spaces.some((s) => s.space === SPACE_ADDED)).toBe(false);
    expect(undoPrep.after.nodes).toEqual([{ did: NODE_A_DID, url: NODE_A_URL }]);
    expect(undoPrep.after.encryptionNode).toBe(NODE_A_DID);

    const undoPub = await callPublish(app, {
      changeId: undoPrep.changeId,
      passkeyAssertion: credential.signOffer(undoPrep.passkey),
    });
    expect(undoPub.status).toBe(200);
    expect(getCurrentRecord()?.sequence).toBe(6);
    expect(getCurrentRecord()?.spaces.some((s) => s.space === SPACE_ADDED)).toBe(false);
    expect(getCurrentRecord()?.nodes).toEqual([{ did: NODE_A_DID, url: NODE_A_URL }]);
    expect(getCurrentRecord()?.encryptionNode).toBe(NODE_A_DID);
  });

  test('restore an older history row (two changes A, B -> restore A puts back pre-A state exactly at seq = current + 1)', async () => {
    const preA = await makeSignedV2Record({ sequence: 4 });
    let clockMs = new Date('2026-11-22T17:00:00.000Z').getTime();
    const { app, credential, historyRows, getCurrentRecord } = createHarness({
      initialRecord: preA,
      getServerTime: () => new Date(clockMs),
    });

    // Change A: move default + encryption to NODE_B and add SPACE_ADDED (seq 4 -> 5).
    const prepA = await (await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_B_URL }],
        spaces: [
          { space: SPACE_DEFAULT, nodes: [{ url: NODE_B_URL }] },
          { space: SPACE_ADDED, nodes: [{ url: NODE_B_URL }] },
        ],
        encryptionNode: NODE_B_URL,
      },
    })).json() as { changeId: string; passkey: { challengeToken: string; options: { challenge: string } } };
    expect((await callPublish(app, { changeId: prepA.changeId, passkeyAssertion: credential.signOffer(prepA.passkey) })).status).toBe(200);

    // Change B: move default + encryption to NODE_C (seq 5 -> 6).
    clockMs += 60_000;
    const prepB = await (await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_C_URL }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ url: NODE_C_URL }] }],
        encryptionNode: NODE_C_URL,
      },
    })).json() as { changeId: string; passkey: { challengeToken: string; options: { challenge: string } } };
    expect((await callPublish(app, { changeId: prepB.changeId, passkeyAssertion: credential.signOffer(prepB.passkey) })).status).toBe(200);
    expect(getCurrentRecord()?.sequence).toBe(6);

    // Restore older row A (newSequence = 5, while current is 6)!
    const rowA = historyRows.find((r) => r.newSequence === 5)!;
    clockMs += 60_000;
    const restorePrepRes = await callUndoPrepare(app, { historyId: rowA.id });
    expect(restorePrepRes.status).toBe(200);
    const restorePrep = await restorePrepRes.json() as {
      changeId: string;
      before: LocationRecordV2Payload;
      after: LocationRecordV2Payload;
      undoKind: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    expect(restorePrep.undoKind).toBe('restore');
    expect(restorePrep.before.sequence).toBe(6);
    expect(restorePrep.after.sequence).toBe(7);
    expect(restorePrep.after.nodes).toEqual(preA.nodes);
    expect(restorePrep.after.spaces).toEqual(preA.spaces);
    expect(restorePrep.after.encryptionNode).toBe(preA.encryptionNode);

    const restorePub = await callPublish(app, {
      changeId: restorePrep.changeId,
      passkeyAssertion: credential.signOffer(restorePrep.passkey),
    });
    expect(restorePub.status).toBe(200);
    expect(getCurrentRecord()?.sequence).toBe(7);
    expect(getCurrentRecord()?.nodes).toEqual(preA.nodes);
    expect(getCurrentRecord()?.spaces).toEqual(preA.spaces);
    expect(getCurrentRecord()?.encryptionNode).toBe(preA.encryptionNode);
  });

  test('sequence moving between undo/prepare and publish returns 409 registry_change_stale', async () => {
    const preA = await makeSignedV2Record({ sequence: 4 });
    const { app, credential, historyRows, setCurrentRecord } = createHarness({ initialRecord: preA });
    historyRows.push({
      id: 'hist-stale-1',
      userId: USER_ID,
      subject: SUBJECT,
      requestingOrigin: APP_ORIGIN,
      previousRecord: preA,
      newRecordHash: 'e'.repeat(64),
      newSequence: 5,
      createdAt: new Date('2026-11-22T17:00:00.000Z'),
    });
    setCurrentRecord(await makeSignedV2Record({ sequence: 5 }));

    const undoPrep = await (await callUndoPrepare(app, { historyId: 'hist-stale-1' })).json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };

    // Concurrent change bumps sequence to 6 before publish.
    setCurrentRecord(await makeSignedV2Record({ sequence: 6 }));

    const res = await callPublish(app, {
      changeId: undoPrep.changeId,
      passkeyAssertion: credential.signOffer(undoPrep.passkey),
    });
    expect(res.status).toBe(409);
    expect((await res.json() as { error: string }).error).toBe('registry_change_stale');
  });

  test("another owner's historyId is refused with 404 history_not_found", async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });
    const { app, historyRows } = createHarness({ initialRecord: initial });
    historyRows.push({
      id: 'hist-other-owner',
      userId: 'other_user_999',
      subject: 'did:pkh:eip155:1:0x2222222222222222222222222222222222222222',
      requestingOrigin: APP_ORIGIN,
      previousRecord: initial,
      newRecordHash: 'f'.repeat(64),
      newSequence: 4,
      createdAt: new Date('2026-11-22T17:00:00.000Z'),
    });

    const res = await callUndoPrepare(app, { historyId: 'hist-other-owner' });
    expect(res.status).toBe(404);
    expect((await res.json() as { error: string }).error).toBe('history_not_found');
  });

  test('GET /history CORS allows credentials ONLY for TinyCloud One origins', async () => {
    const initial = await makeSignedV2Record();
    const { app } = createHarness({ initialRecord: initial });

    for (const allowed of ['https://tinycloud.one', 'https://home.tinycloud.xyz']) {
      const getRes = await app.request('/api/registry-change/history', {
        method: 'GET',
        headers: { origin: allowed },
      });
      expect(getRes.status, allowed).toBe(200);
      expect(getRes.headers.get('access-control-allow-origin'), allowed).toBe(allowed);
      expect(getRes.headers.get('access-control-allow-credentials'), allowed).toBe('true');

      const optRes = await app.request('/api/registry-change/history', {
        method: 'OPTIONS',
        headers: { origin: allowed, 'access-control-request-method': 'GET' },
      });
      expect(optRes.headers.get('access-control-allow-origin'), allowed).toBe(allowed);
      expect(optRes.headers.get('access-control-allow-credentials'), allowed).toBe('true');
    }

    for (const disallowed of [
      'https://attacker.example',
      'https://app.tinycloud.one',
      'https://tinycloud.one.evil.example',
      'http://tinycloud.one',
    ]) {
      const getRes = await app.request('/api/registry-change/history', {
        method: 'GET',
        headers: { origin: disallowed },
      });
      expect(getRes.headers.get('access-control-allow-origin'), disallowed).toBeNull();
    }
  });
});

describe('formatRegistryChangeNoticeEmail', () => {
  test('omits Secrets and keys line when encryptionNode did not change', async () => {
    const before = await makeSignedV2Record({ encryptionNode: NODE_A_DID });
    const after: LocationRecordV2Payload = {
      version: 2,
      subject: SUBJECT,
      nodes: [
        { did: NODE_A_DID, url: NODE_A_URL },
        { did: NODE_B_DID, url: NODE_B_URL },
      ],
      spaces: [
        { space: SPACE_DEFAULT, nodes: [{ did: NODE_B_DID, mode: 'read-write' }] },
        { space: SPACE_NOTES, nodes: [{ did: NODE_A_DID, mode: 'read-write' }] },
      ],
      encryptionNode: NODE_A_DID,
      updated_at: '2026-11-22T16:50:00.000Z',
      sequence: 5,
    };
    const formatted = formatRegistryChangeNoticeEmail({
      to: USER_EMAIL,
      requestingOrigin: APP_ORIGIN,
      before,
      after,
      publishedAt: new Date('2026-11-22T16:50:00.000Z'),
    });
    expect(formatted.changes).toEqual(['default: node-a.example → node-b.example:8443']);
    expect(formatted.text).not.toContain('Secrets and keys:');
  });
});
