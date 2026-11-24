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
import {
  MAX_IDENTITY_PROBE_CONCURRENCY,
  MAX_REGISTRY_CHANGE_NODES,
  MAX_REGISTRY_CHANGE_SPACES,
  canonicalNodeUrl,
  checkNodeIdentity,
  displayNodeHost,
  isBlockedProbeIp,
  type HostResolver,
} from '../services/registry-change-client';
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
  publishedAt: Date | null;
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
  onHistoryUpdate?: (row: StoredHistoryRow) => void;
  historyUpdateFailCount?: number;
} = {}) {
  const mode = opts.passkeyApprovalMode ?? 'NEVER';
  const passkeys = opts.passkeys ? opts.passkeys.map((p) => ({ ...p })) : [];
  const verifications: VerificationRow[] = [];
  const historyRows: StoredHistoryRow[] = [];
  let remainingUpdateFailures = opts.historyUpdateFailCount ?? 0;

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
        const row: StoredHistoryRow = { ...data, publishedAt: data.publishedAt ?? null };
        historyRows.push(row);
        opts.onHistoryCreate?.(row);
        return row;
      },
      update: async ({ where, data }: { where: { id: string }; data: Partial<StoredHistoryRow> }) => {
        if (remainingUpdateFailures > 0) {
          remainingUpdateFailures -= 1;
          throw new Error('simulated DB update failure');
        }
        const row = historyRows.find((r) => r.id === where.id);
        if (!row) throw new Error('Row not found');
        Object.assign(row, data);
        opts.onHistoryUpdate?.(row);
        return row;
      },
      delete: async ({ where }: { where: { id: string } }) => {
        const idx = historyRows.findIndex((r) => r.id === where.id);
        if (idx === -1) throw new Error('Row not found');
        const [removed] = historyRows.splice(idx, 1);
        return removed!;
      },
      findUnique: async ({ where }: { where: { id: string } }) =>
        historyRows.find((r) => r.id === where.id) ?? null,
      findMany: async ({
        where,
        take,
      }: {
        where: {
          userId: string;
          newSequence?: { lte?: number };
          publishedAt?: { not?: null };
          OR?: Array<{ publishedAt?: { not?: null }; newSequence?: number; newRecordHash?: string }>;
        };
        take: number;
      }) =>
        historyRows
          .filter((r) => {
            if (r.userId !== where.userId) return false;
            if (where.publishedAt && where.publishedAt.not === null && r.publishedAt === null) return false;
            if (where.newSequence?.lte !== undefined && r.newSequence > where.newSequence.lte) return false;
            if (where.OR && where.OR.length > 0) {
              const matchesOr = where.OR.some((branch) => {
                if (branch.publishedAt && branch.publishedAt.not === null && r.publishedAt === null) return false;
                if (branch.newSequence !== undefined && r.newSequence !== branch.newSequence) return false;
                if (branch.newRecordHash !== undefined && r.newRecordHash !== branch.newRecordHash) return false;
                return true;
              });
              if (!matchesOr) return false;
            }
            return true;
          })
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
  isProduction?: boolean;
  emailSender?: EmailSender | null;
  resolveHost?: HostResolver;
  onProbeFetch?: (url: string, init?: RequestInit) => Promise<Response | undefined>;
  getServerTime?: () => Date;
  putStatus?: number;
  registryReadStatus?: number;
  signMessageThrows?: boolean;
  historyUpdateFailCount?: number;
  tamperAcceptedPut?: boolean;
} = {}) {
  const credential = makeTestWebAuthnCredential();
  const events: string[] = [];
  const fetchedUrls: Array<{ url: string; method: string; redirect?: RequestRedirect }> = [];
  const sentEmails: Array<{ from: string; to: string; subject: string; html: string }> = [];
  let currentRecord: LocationRecordV2 | null = opts.initialRecord ?? null;

  const { prisma, historyRows } = createFakePrisma({
    passkeyApprovalMode: opts.passkeyApprovalMode ?? 'NEVER',
    passkeys: opts.noPasskey ? [] : [credential.passkeyRow],
    onHistoryCreate: () => events.push('history.create'),
    onHistoryUpdate: () => events.push('history.update'),
    ...(opts.historyUpdateFailCount ? { historyUpdateFailCount: opts.historyUpdateFailCount } : {}),
  });

  const defaultTestEmailSender: EmailSender = {
    emails: {
      send: async (msg) => {
        events.push('email.send');
        sentEmails.push(msg);
        return { error: null };
      },
    },
  };
  const emailSender = opts.emailSender === undefined ? defaultTestEmailSender : opts.emailSender;
  const resolveHost: HostResolver = opts.resolveHost ?? (async () => ['93.184.216.34']);

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
    fetchedUrls.push({ url: urlStr, method, ...(init?.redirect ? { redirect: init.redirect } : {}) });

    if (urlStr.startsWith(`${REGISTRY_URL}/v2/locations/`)) {
      if (method === 'GET') {
        if (opts.registryReadStatus && opts.registryReadStatus !== 200) {
          return new Response(JSON.stringify({ error: 'registry error' }), { status: opts.registryReadStatus });
        }
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

    if (opts.onProbeFetch) {
      const custom = await opts.onProbeFetch(urlStr, init);
      if (custom) return custom;
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
    isProduction: opts.isProduction ?? false,
    registryUrl: REGISTRY_URL,
    fetch: mockFetch,
    resolveHost,
    rp: RP,
    ...(opts.getServerTime ? { getServerTime: opts.getServerTime } : {}),
    signMessage: async (_descriptor, _sealed, message) => {
      if (opts.signMessageThrows) throw new Error('TEE unseal/sign failed');
      return OWNER_ACCOUNT.signMessage({ message });
    },
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
    fetchedUrls,
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

    // Strict ordering: history stored BEFORE PUT, publishedAt stamped AFTER PUT, email sent AFTER!
    expect(events).toEqual(['history.create', 'registry.PUT', 'history.update', 'email.send']);
    expect(historyRows).toHaveLength(1);
    expect(historyRows[0]?.previousRecord).toEqual(initial);
    expect(historyRows[0]?.newSequence).toBe(5);
    expect(historyRows[0]?.newRecordHash).toBe(prep.recordHash);
    expect(historyRows[0]?.publishedAt).toEqual(fixedNow);
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
      publishedAt: new Date('2026-11-22T17:00:00.000Z'),
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
      publishedAt: new Date('2026-11-22T17:00:00.000Z'),
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

describe('R-reg review #3 security & contract hardening (F1, F2, F3, F4, F6, F7)', () => {
  test('F1: caps request.nodes (<=16) and spaces (<=64) with 400 BEFORE any fetch', async () => {
    const initial = await makeSignedV2Record();
    const { app, fetchedUrls } = createHarness({ initialRecord: initial });

    const tooManyNodes = Array.from({ length: MAX_REGISTRY_CHANGE_NODES + 1 }, (_, i) => ({
      url: `https://node-${i}.example`,
    }));
    const nodesRes = await callPrepare(app, { request: { nodes: tooManyNodes } });
    expect(nodesRes.status).toBe(400);
    expect((await nodesRes.json() as { error: string }).error).toBe('registry_change_too_many_nodes');
    expect(fetchedUrls).toHaveLength(0);

    const tooManySpaces = Array.from({ length: MAX_REGISTRY_CHANGE_SPACES + 1 }, (_, i) => ({
      space: `tinycloud:pkh:eip155:1:${ADDRESS.toLowerCase()}:s${i}`,
      nodes: [{ url: NODE_B_URL }],
    }));
    const spacesRes = await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_B_URL }],
        spaces: tooManySpaces,
      },
    });
    expect(spacesRes.status).toBe(400);
    expect((await spacesRes.json() as { error: string }).error).toBe('registry_change_too_many_spaces');
    expect(fetchedUrls).toHaveLength(0);
  });

  test('F1: SSRF filter skips probing private, link-local, CGNAT, ULA, metadata, and (in prod) loopback hosts; probes use redirect: error and concurrency <= 4', async () => {
    expect(isBlockedProbeIp('10.0.0.1', true)).toBe(true);
    expect(isBlockedProbeIp('172.16.0.1', true)).toBe(true);
    expect(isBlockedProbeIp('192.168.1.1', true)).toBe(true);
    expect(isBlockedProbeIp('100.64.0.1', true)).toBe(true);
    expect(isBlockedProbeIp('169.254.169.254', true)).toBe(true);
    expect(isBlockedProbeIp('fd00:ec2::254', true)).toBe(true);
    expect(isBlockedProbeIp('fe80::1', true)).toBe(true);
    expect(isBlockedProbeIp('::ffff:169.254.169.254', true)).toBe(true);
    expect(isBlockedProbeIp('127.0.0.1', false)).toBe(true);
    expect(isBlockedProbeIp('::1', false)).toBe(true);
    expect(isBlockedProbeIp('127.0.0.1', true)).toBe(false);
    expect(isBlockedProbeIp('::1', true)).toBe(false);
    expect(isBlockedProbeIp('93.184.216.34', false)).toBe(false);

    const initial = await makeSignedV2Record();
    // Hostname resolving to AWS metadata IP + literal private IP + literal IPv6 metadata + loopback in prod: NONE may be fetched!
    const prodHarness = createHarness({
      initialRecord: initial,
      isProduction: true,
      resolveHost: async (host) => (host === 'imds-rebind.example' ? ['169.254.169.254'] : ['93.184.216.34']),
    });
    const ssrfRes = await callPrepare(prodHarness.app, {
      request: {
        nodes: [
          { url: 'https://imds-rebind.example', did: NODE_B_DID },
          { url: 'https://10.1.2.3:8443', did: NODE_C_DID },
          { url: 'https://[fd00:ec2::254]', did: NODE_A_DID },
          { url: 'http://127.0.0.1:8787', did: NODE_B_DID },
        ],
      },
    });
    // Note: NODE_B_DID appears twice above only if deduplicated — test distinct DIDs instead:
    expect(ssrfRes.status).toBe(400); // conflicting DIDs on two URLs, check probes first!
    const probeFetches = prodHarness.fetchedUrls.filter((f) => !f.url.startsWith(REGISTRY_URL));
    expect(probeFetches).toHaveLength(0);

    // Distinct valid DIDs on blocked private/metadata/loopback hosts -> 200 with unreachable warnings and 0 probe fetches.
    const ssrfValid = await callPrepare(prodHarness.app, {
      request: {
        nodes: [
          { url: 'https://imds-rebind.example', did: NODE_B_DID },
          { url: 'https://10.1.2.3:8443', did: NODE_C_DID },
          { url: 'http://127.0.0.1:8787', did: NODE_A_DID },
        ],
      },
    });
    expect(ssrfValid.status).toBe(200);
    const ssrfBody = await ssrfValid.json() as { identity: Array<{ url: string; did: string | null; status: string }> };
    expect(ssrfBody.identity).toEqual([
      { url: 'https://imds-rebind.example', did: NODE_B_DID, status: 'unreachable' },
      { url: 'https://10.1.2.3:8443', did: NODE_C_DID, status: 'unreachable' },
      { url: 'http://127.0.0.1:8787', did: NODE_A_DID, status: 'unreachable' },
    ]);
    expect(prodHarness.fetchedUrls.filter((f) => !f.url.startsWith(REGISTRY_URL))).toHaveLength(0);

    // Dev/test mode allows loopback probing, with redirect: 'error'.
    const devHarness = createHarness({
      initialRecord: initial,
      isProduction: false,
      nodes: {
        'http://127.0.0.1:8787': {
          info: { status: 200, body: { nodeId: NODE_B_DID } },
          keys: { status: 200, body: { nodeDid: NODE_B_DID } },
        },
      },
    });
    const devLoopback = await callPrepare(devHarness.app, {
      request: { nodes: [{ url: 'http://127.0.0.1:8787' }] },
    });
    expect(devLoopback.status).toBe(200);
    const devProbeFetches = devHarness.fetchedUrls.filter((f) => f.url.startsWith('http://127.0.0.1:8787'));
    expect(devProbeFetches).toHaveLength(2);
    expect(devProbeFetches.every((f) => f.redirect === 'error')).toBe(true);

    // Probe concurrency stays <= 4 concurrent HTTP REQUESTS total (across 8 nodes x 2 paths = 16 requests).
    let inFlightRequests = 0;
    let peakRequests = 0;
    let totalRequests = 0;
    const concHarness = createHarness({
      initialRecord: initial,
      onProbeFetch: async () => {
        totalRequests += 1;
        inFlightRequests += 1;
        if (inFlightRequests > peakRequests) peakRequests = inFlightRequests;
        try {
          await new Promise((r) => setTimeout(r, 15));
          return new Response(JSON.stringify({ nodeId: NODE_B_DID, nodeDid: NODE_B_DID }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        } finally {
          inFlightRequests -= 1;
        }
      },
    });
    const eightNodes = Array.from({ length: 8 }, (_, i) => ({
      url: `https://conc-${i}.example`,
    }));
    await callPrepare(concHarness.app, { request: { nodes: eightNodes } });
    expect(totalRequests).toBe(16);
    expect(peakRequests).toBeGreaterThan(0);
    expect(peakRequests).toBeLessThanOrEqual(MAX_IDENTITY_PROBE_CONCURRENCY);
  });

  test('F2: failed PUT and tampered PUT delete the pre-stored history row; GET /history excludes rows above current sequence', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });

    // Case 1: registry PUT returns 500 -> pre-stored history row is deleted!
    const failPut = createHarness({ initialRecord: initial, putStatus: 500 });
    const prep1 = await (await callPrepare(failPut.app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pub1 = await callPublish(failPut.app, {
      changeId: prep1.changeId,
      passkeyAssertion: failPut.credential.signOffer(prep1.passkey),
    });
    expect(pub1.status).toBe(502);
    expect(failPut.historyRows).toHaveLength(0);
    expect(failPut.sentEmails).toHaveLength(0);

    // Case 2: registry returns tampered accepted record -> pre-stored history row is deleted!
    const tamperPut = createHarness({ initialRecord: initial, tamperAcceptedPut: true });
    const prep2 = await (await callPrepare(tamperPut.app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pub2 = await callPublish(tamperPut.app, {
      changeId: prep2.changeId,
      passkeyAssertion: tamperPut.credential.signOffer(prep2.passkey),
    });
    expect(pub2.status).toBe(502);
    expect(tamperPut.historyRows).toHaveLength(0);

    // Case 3: defense-in-depth — GET /history excludes phantom row with newSequence > current.sequence!
    const histHarness = createHarness({ initialRecord: initial });
    histHarness.historyRows.push(
      {
        id: 'hist-valid',
        userId: USER_ID,
        subject: SUBJECT,
        requestingOrigin: APP_ORIGIN,
        previousRecord: initial,
        newRecordHash: '1'.repeat(64),
        newSequence: 4,
        createdAt: new Date('2026-11-22T15:00:00.000Z'),
        publishedAt: new Date('2026-11-22T15:00:00.000Z'),
      },
      {
        id: 'hist-phantom',
        userId: USER_ID,
        subject: SUBJECT,
        requestingOrigin: APP_ORIGIN,
        previousRecord: initial,
        newRecordHash: '2'.repeat(64),
        newSequence: 5, // > current.sequence (4)!
        createdAt: new Date('2026-11-22T15:05:00.000Z'),
        publishedAt: new Date('2026-11-22T15:05:00.000Z'),
      },
    );
    const histRes = await histHarness.app.request('/api/registry-change/history?limit=10');
    expect(histRes.status).toBe(200);
    const histBody = await histRes.json() as { history: Array<{ id: string }> };
    expect(histBody.history.map((r) => r.id)).toEqual(['hist-valid']);
  });

  test('F3: mode-only change appears in notice email with Monica exact wording', async () => {
    const initial = await makeSignedV2Record({
      sequence: 4,
      spaces: [
        { space: SPACE_DEFAULT, nodes: [{ did: NODE_A_DID, mode: 'read-only' }] },
        { space: SPACE_NOTES, nodes: [{ did: NODE_A_DID, mode: 'read-write' }] },
      ],
    });
    const { app, credential, sentEmails } = createHarness({ initialRecord: initial });

    // Flip `default` on the SAME host from read-only -> read-write (mode-only change).
    const prepRes = await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_A_URL }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ url: NODE_A_URL, mode: 'read-write' }] }],
      },
    });
    expect(prepRes.status).toBe(200);
    const prep = await prepRes.json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pubRes = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect(pubRes.status).toBe(200);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0]?.html).toContain('default: node-a.example, read-only → read and write');

    // Also verify reverse direction (read-write -> read-only) directly via formatter.
    const reverse = formatRegistryChangeNoticeEmail({
      to: USER_EMAIL,
      requestingOrigin: APP_ORIGIN,
      before: {
        version: 2,
        subject: SUBJECT,
        nodes: [{ did: NODE_A_DID, url: NODE_A_URL }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ did: NODE_A_DID, mode: 'read-write' }] }],
        encryptionNode: NODE_A_DID,
        updated_at: '2026-11-22T15:00:00.000Z',
        sequence: 4,
      },
      after: {
        version: 2,
        subject: SUBJECT,
        nodes: [{ did: NODE_A_DID, url: NODE_A_URL }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ did: NODE_A_DID, mode: 'read-only' }] }],
        encryptionNode: NODE_A_DID,
        updated_at: '2026-11-22T15:05:00.000Z',
        sequence: 5,
      },
      publishedAt: new Date('2026-11-22T15:05:00.000Z'),
    });
    expect(reverse.changes).toEqual(['default: node-a.example, read and write → read-only']);
  });

  test('F4: rejects Authorization header on prepare, undo/prepare, and publish; requires X-OpenKey-Requesting-Origin with no Origin fallback', async () => {
    const initial = await makeSignedV2Record();
    const { app } = createHarness({ initialRecord: initial, realOrigin: true });

    // Bearer Authorization header MUST be rejected on all 3 mutating/prepare endpoints even with valid OpenKey Origin.
    const bearerPrep = await callPrepare(
      app,
      { request: { nodes: [{ url: NODE_B_URL }] } },
      { authorization: 'Bearer some-oauth-token' },
    );
    expect(bearerPrep.status).toBe(403);

    const bearerUndo = await callUndoPrepare(
      app,
      { historyId: 'hist-1' },
      { authorization: 'Bearer some-oauth-token' },
    );
    expect(bearerUndo.status).toBe(403);

    const bearerPub = await callPublish(
      app,
      { changeId: 'ticket-1' },
      { authorization: 'Bearer some-oauth-token' },
    );
    expect(bearerPub.status).toBe(403);

    // Missing X-OpenKey-Requesting-Origin -> 400 (must NOT fall back to HTTP Origin!).
    const missingHeaderPrep = await app.request('/api/registry-change/prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: OPENKEY_ORIGIN },
      body: JSON.stringify({ request: { nodes: [{ url: NODE_B_URL }] } }),
    });
    expect(missingHeaderPrep.status).toBe(400);
    expect((await missingHeaderPrep.json() as { error: string }).error).toBe('requesting_origin_required');

    // Non-canonical X-OpenKey-Requesting-Origin (trailing path) -> 400.
    const nonCanonicalPrep = await callPrepare(
      app,
      { request: { nodes: [{ url: NODE_B_URL }] } },
      { [REQUESTING_ORIGIN_HEADER]: 'https://external-app.example/path' },
    );
    expect(nonCanonicalPrep.status).toBe(400);
    expect((await nonCanonicalPrep.json() as { error: string }).error).toBe('requesting_origin_required');

    // Missing X-OpenKey-Requesting-Origin on /undo/prepare -> 400.
    const missingHeaderUndo = await app.request('/api/registry-change/undo/prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: OPENKEY_ORIGIN },
      body: JSON.stringify({ historyId: 'hist-1' }),
    });
    expect(missingHeaderUndo.status).toBe(400);
    expect((await missingHeaderUndo.json() as { error: string }).error).toBe('requesting_origin_required');
  });

  test('F6 (Option A): unreachable new host without did -> 422 registry_change_node_did_required; unreachable host WITH known did (supplied or current) -> 200 + warning + publish allowed', async () => {
    const initial = await makeSignedV2Record();
    const { app, credential } = createHarness({
      initialRecord: initial,
      nodes: {
        [NODE_A_URL]: { info: 'network-error', keys: 'network-error' },
        [NODE_B_URL]: { info: 'network-error', keys: 'network-error' },
      },
    });

    // Branch 1: brand-new unreachable host WITHOUT did -> 422 registry_change_node_did_required (NOT 400!).
    const missingDidRes = await callPrepare(app, {
      request: { nodes: [{ url: NODE_B_URL }] },
    });
    expect(missingDidRes.status).toBe(422);
    const missingDidBody = await missingDidRes.json() as { error: string; host?: string };
    expect(missingDidBody.error).toBe('registry_change_node_did_required');
    expect(missingDidBody.host).toBe('node-b.example:8443');

    // Branch 2a: unreachable new host WITH supplied did -> 200 + unreachable warning + publish allowed.
    const suppliedDidRes = await callPrepare(app, {
      request: { nodes: [{ url: NODE_B_URL, did: NODE_B_DID }] },
    });
    expect(suppliedDidRes.status).toBe(200);
    const suppliedDid = await suppliedDidRes.json() as {
      changeId: string;
      identity: Array<{ url: string; did: string | null; status: string }>;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    expect(suppliedDid.identity).toEqual([{ url: NODE_B_URL, did: NODE_B_DID, status: 'unreachable' }]);

    // Branch 2b: unreachable EXISTING host (known DID in current.nodes, omitted in request) -> 200 + unreachable warning + publish allowed!
    const existingHostRes = await callPrepare(app, {
      request: {
        nodes: [{ url: NODE_A_URL }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ url: NODE_A_URL, mode: 'read-only' }] }],
      },
    });
    expect(existingHostRes.status).toBe(200);
    const existingHost = await existingHostRes.json() as {
      changeId: string;
      identity: Array<{ url: string; did: string | null; status: string }>;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    expect(existingHost.identity).toEqual([{ url: NODE_A_URL, did: NODE_A_DID, status: 'unreachable' }]);

    const pubRes = await callPublish(app, {
      changeId: existingHost.changeId,
      passkeyAssertion: credential.signOffer(existingHost.passkey),
    });
    expect(pubRes.status).toBe(200);
  });

  test('F7: production refuses prepare and undo/prepare with 503 registry_change_notice_unavailable when emailSender is unconfigured; dev/test allows it', async () => {
    const initial = await makeSignedV2Record();

    const prodNoEmail = createHarness({
      initialRecord: initial,
      isProduction: true,
      emailSender: null,
    });
    const prepProd = await callPrepare(prodNoEmail.app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(prepProd.status).toBe(503);
    expect((await prepProd.json() as { error: string }).error).toBe('registry_change_notice_unavailable');

    const undoProd = await callUndoPrepare(prodNoEmail.app, { historyId: 'hist-1' });
    expect(undoProd.status).toBe(503);
    expect((await undoProd.json() as { error: string }).error).toBe('registry_change_notice_unavailable');

    const devNoEmail = createHarness({
      initialRecord: initial,
      isProduction: false,
      emailSender: null,
    });
    const prepDev = await callPrepare(devNoEmail.app, { request: { nodes: [{ url: NODE_B_URL }] } });
    expect(prepDev.status).toBe(200);
  });

  test('N3: blocks 192.0.0.0/24, 198.18.0.0/15, 240.0.0.0/4, 255.255.255.255 and IPv6 embedded IPv4 prefixes (::/96, ::ffff:0:0/96, ::ffff:0:0:0/96, 64:ff9b::/96, 2002::/16)', async () => {
    // New IPv4 special-use ranges (blocked even with allowLoopback=true).
    for (const ip of [
      '192.0.0.1',
      '192.0.0.254',
      '198.18.0.1',
      '198.19.255.254',
      '240.0.0.1',
      '254.254.254.254',
      '255.255.255.255',
    ]) {
      expect(isBlockedProbeIp(ip, true), ip).toBe(true);
    }
    // Adjacent public IPs remain allowed.
    for (const ip of ['192.0.1.1', '198.17.0.1', '198.20.0.1', '223.255.255.254']) {
      expect(isBlockedProbeIp(ip, false), ip).toBe(false);
    }

    // Embedded IPv4 in IPv6: blocked private/metadata/special-use targets across all 5 prefixes.
    for (const ip of [
      // ::/96 (IPv4-compatible)
      '::10.0.0.1',
      '::169.254.169.254',
      '::192.0.0.1',
      '::198.18.0.1',
      '::240.0.0.1',
      '::255.255.255.255',
      // ::ffff:0:0/96 (IPv4-mapped)
      '::ffff:10.0.0.1',
      '::ffff:192.0.0.1',
      '::ffff:198.18.0.1',
      '::ffff:240.0.0.1',
      '::ffff:255.255.255.255',
      // ::ffff:0:0:0/96 (IPv4-translated RFC 2765)
      '::ffff:0:10.0.0.1',
      '::ffff:0:169.254.169.254',
      '::ffff:0:192.0.0.1',
      '::ffff:0:198.19.0.1',
      '::ffff:0:240.0.0.1',
      '::ffff:0:255.255.255.255',
      // 64:ff9b::/96 (NAT64 well-known prefix)
      '64:ff9b::10.0.0.1',
      '64:ff9b::169.254.169.254',
      '64:ff9b::192.0.0.1',
      '64:ff9b::198.18.0.1',
      '64:ff9b::240.0.0.1',
      '64:ff9b::255.255.255.255',
      // 2002::/16 (6to4 — bits 16-47 = embedded IPv4)
      '2002:0a00:0001::1', // 10.0.0.1
      '2002:a9fe:a9fe::1', // 169.254.169.254
      '2002:c000:0001::1', // 192.0.0.1
      '2002:c612:0001::1', // 198.18.0.1
      '2002:f000:0001::1', // 240.0.0.1
      '2002:ffff:ffff::1', // 255.255.255.255
      // Deprecated site-local fec0::/10
      'fec0::1',
    ]) {
      expect(isBlockedProbeIp(ip, true), ip).toBe(true);
    }

    // Embedded loopback respects allowLoopback (blocked in prod, allowed in dev/test).
    for (const ip of [
      '::127.0.0.1',
      '::ffff:127.0.0.1',
      '::ffff:0:127.0.0.1',
      '64:ff9b::127.0.0.1',
      '2002:7f00:0001::1',
    ]) {
      expect(isBlockedProbeIp(ip, false), `${ip} prod`).toBe(true);
      expect(isBlockedProbeIp(ip, true), `${ip} dev`).toBe(false);
    }

    // Embedded public IPv4 (93.184.216.34 = 0x5db8d822) is NOT blocked across all 5 prefixes.
    for (const ip of [
      '::93.184.216.34',
      '::ffff:93.184.216.34',
      '::ffff:0:93.184.216.34',
      '64:ff9b::93.184.216.34',
      '2002:5db8:d822::1',
    ]) {
      expect(isBlockedProbeIp(ip, false), ip).toBe(false);
    }

    // End-to-end: hosts resolving to NAT64 metadata or 6to4 metadata are NOT fetched.
    const initial = await makeSignedV2Record();
    const { app, fetchedUrls } = createHarness({
      initialRecord: initial,
      isProduction: true,
      resolveHost: async (host) => {
        if (host === 'nat64-imds.example') return ['64:ff9b::169.254.169.254'];
        if (host === 'sixtofour-imds.example') return ['2002:a9fe:a9fe::1'];
        return ['93.184.216.34'];
      },
    });
    const res = await callPrepare(app, {
      request: {
        nodes: [
          { url: 'https://nat64-imds.example', did: NODE_B_DID },
          { url: 'https://sixtofour-imds.example', did: NODE_C_DID },
        ],
      },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { identity: Array<{ url: string; did: string | null; status: string }> };
    expect(body.identity).toEqual([
      { url: 'https://nat64-imds.example', did: NODE_B_DID, status: 'unreachable' },
      { url: 'https://sixtofour-imds.example', did: NODE_C_DID, status: 'unreachable' },
    ]);
    expect(fetchedUrls.filter((f) => !f.url.startsWith(REGISTRY_URL))).toHaveLength(0);
  });

  test('N4(a)+(b): GET /history fails CLOSED (503) when registry read fails; excludes unpublished crash-phantom rows; undo refuses unpublished rows', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });

    // N4(a): registry read fails -> GET /history returns 503 registry_history_unavailable (NEVER unfiltered rows!).
    const failingRegistry = createHarness({
      initialRecord: initial,
      registryReadStatus: 500,
    });
    failingRegistry.historyRows.push({
      id: 'hist-must-not-leak',
      userId: USER_ID,
      subject: SUBJECT,
      requestingOrigin: APP_ORIGIN,
      previousRecord: initial,
      newRecordHash: '3'.repeat(64),
      newSequence: 4,
      createdAt: new Date('2026-11-22T15:00:00.000Z'),
      publishedAt: new Date('2026-11-22T15:00:00.000Z'),
    });
    const failHistRes = await failingRegistry.app.request('/api/registry-change/history?limit=10');
    expect(failHistRes.status).toBe(503);
    expect((await failHistRes.json() as { error: string }).error).toBe('registry_history_unavailable');

    // N4(b): crash-phantom row (publishedAt === null) is excluded from GET /history AND refused by /undo/prepare!
    const crashHarness = createHarness({ initialRecord: initial });
    crashHarness.historyRows.push(
      {
        id: 'hist-published',
        userId: USER_ID,
        subject: SUBJECT,
        requestingOrigin: APP_ORIGIN,
        previousRecord: initial,
        newRecordHash: '4'.repeat(64),
        newSequence: 4,
        createdAt: new Date('2026-11-22T15:00:00.000Z'),
        publishedAt: new Date('2026-11-22T15:00:01.000Z'),
      },
      {
        id: 'hist-crash-phantom',
        userId: USER_ID,
        subject: SUBJECT,
        requestingOrigin: APP_ORIGIN,
        previousRecord: initial,
        newRecordHash: '5'.repeat(64),
        newSequence: 4,
        createdAt: new Date('2026-11-22T15:01:00.000Z'),
        publishedAt: null, // crash before accepted==prepared completed!
      },
    );

    const histRes = await crashHarness.app.request('/api/registry-change/history?limit=10');
    expect(histRes.status).toBe(200);
    const histBody = await histRes.json() as { history: Array<{ id: string }> };
    expect(histBody.history.map((r) => r.id)).toEqual(['hist-published']);

    const undoPhantomRes = await callUndoPrepare(crashHarness.app, { historyId: 'hist-crash-phantom' });
    expect(undoPhantomRes.status).toBe(404);
    expect((await undoPhantomRes.json() as { error: string }).error).toBe('history_not_found');

    // Undo of the real published row still sees it as `undo-last` even with an unpublished crash phantom present.
    const undoRealRes = await callUndoPrepare(crashHarness.app, { historyId: 'hist-published' });
    expect(undoRealRes.status).toBe(200);
    expect((await undoRealRes.json() as { undoKind: string }).undoKind).toBe('undo-last');
  });

  test('N4(c): signer throw returns 502, deletes pre-stored history row, issues 0 PUTs, and sends 0 emails', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });
    const { app, credential, events, historyRows, sentEmails, getCurrentRecord } = createHarness({
      initialRecord: initial,
      signMessageThrows: true,
    });

    const prep = await (await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pubRes = await callPublish(app, {
      changeId: prep.changeId,
      passkeyAssertion: credential.signOffer(prep.passkey),
    });
    expect(pubRes.status).toBe(502);
    expect((await pubRes.json() as { error: string }).error).toBe('registry_publish_failed');
    expect(historyRows).toHaveLength(0);
    expect(events).toEqual(['history.create']); // no registry.PUT, no history.update, no email.send!
    expect(sentEmails).toHaveLength(0);
    expect(getCurrentRecord()?.sequence).toBe(4);
  });

  test('N5: publishedAt stamp failure retries once, still returns 200 + sends email, and row is visible/undoable via verified sequence+hash match; mismatched unstamped row stays hidden', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });

    // Case 1a: transient single failure succeeds on the single retry and stamps publishedAt.
    const transient = createHarness({ initialRecord: initial, historyUpdateFailCount: 1 });
    const prepRetry = await (await callPrepare(transient.app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pubRetry = await callPublish(transient.app, {
      changeId: prepRetry.changeId,
      passkeyAssertion: transient.credential.signOffer(prepRetry.passkey),
    });
    expect(pubRetry.status).toBe(200);
    expect(transient.historyRows).toHaveLength(1);
    expect(transient.historyRows[0]?.publishedAt).not.toBeNull();
    expect(transient.sentEmails).toHaveLength(1);

    // Case 1b: both stamp attempts fail -> publish STILL returns 200, email IS sent,
    // and the unstamped row IS visible in GET /history and accepted by /undo/prepare
    // because (newSequence, newRecordHash) matches the verified current registry record!
    const stampFail = createHarness({ initialRecord: initial, historyUpdateFailCount: 5 });
    const prep = await (await callPrepare(stampFail.app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      recordHash: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };
    const pub = await callPublish(stampFail.app, {
      changeId: prep.changeId,
      passkeyAssertion: stampFail.credential.signOffer(prep.passkey),
    });
    expect(pub.status).toBe(200);
    expect(await pub.json()).toEqual({ sequence: 5, recordHash: prep.recordHash });
    expect(stampFail.sentEmails).toHaveLength(1);
    expect(stampFail.historyRows).toHaveLength(1);
    expect(stampFail.historyRows[0]?.publishedAt).toBeNull();

    // Case 2: add an unstamped row at the SAME sequence (5) with a NON-matching hash -> stays HIDDEN!
    stampFail.historyRows.push({
      id: 'hist-unstamped-wrong-hash',
      userId: USER_ID,
      subject: SUBJECT,
      requestingOrigin: APP_ORIGIN,
      previousRecord: initial,
      newRecordHash: '0'.repeat(64),
      newSequence: 5,
      createdAt: new Date('2026-11-22T17:30:00.000Z'),
      publishedAt: null,
    });

    const histRes = await stampFail.app.request('/api/registry-change/history?limit=10');
    expect(histRes.status).toBe(200);
    const histBody = await histRes.json() as { history: Array<{ id: string }> };
    expect(histBody.history.map((r) => r.id)).toEqual([stampFail.historyRows[0]!.id]);

    // Unstamped row whose hash matches verified current is accepted by /undo/prepare as undo-last.
    const undoMatched = await callUndoPrepare(stampFail.app, { historyId: stampFail.historyRows[0]!.id });
    expect(undoMatched.status).toBe(200);
    expect((await undoMatched.json() as { undoKind: string }).undoKind).toBe('undo-last');

    // Unstamped row whose hash does NOT match verified current is refused by /undo/prepare.
    const undoMismatched = await callUndoPrepare(stampFail.app, { historyId: 'hist-unstamped-wrong-hash' });
    expect(undoMismatched.status).toBe(404);
    expect((await undoMismatched.json() as { error: string }).error).toBe('history_not_found');
  });

  test('Bobbie port ruling: production probes allow HTTPS :443 only (refusing :8443, :22, :80 without fetch; F6 422 applies when DID absent); dev/test unchanged', async () => {
    const initial = await makeSignedV2Record();
    const NODE_443_URL = 'https://node-443.example';

    // Direct probe filter checks in production (allowLoopback = false):
    // :8443, :22, and :80 (both https:80 and http:80) must NOT fetch and return unreachable.
    const directFetched: string[] = [];
    const trackingFetch = (async (input: string | URL | Request) => {
      const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      directFetched.push(urlStr);
      return new Response(JSON.stringify({ nodeId: NODE_B_DID, nodeDid: NODE_B_DID }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const publicDns: HostResolver = async () => ['93.184.216.34'];

    for (const blockedUrl of [
      'https://node-b.example:8443',
      'https://node-b.example:22',
      'https://node-b.example:80',
      'http://node-b.example:80',
      'http://node-b.example',
    ]) {
      const res = await checkNodeIdentity(blockedUrl, NODE_B_DID, {
        allowLoopback: false,
        fetch: trackingFetch,
        resolveHost: publicDns,
      });
      expect(res, blockedUrl).toEqual({ url: blockedUrl, did: NODE_B_DID, status: 'unreachable' });
    }
    expect(directFetched).toHaveLength(0);

    // Explicit :443 and implicit https (:443) ARE allowed and probed in production.
    const explicit443 = await checkNodeIdentity('https://node-443.example:443', undefined, {
      allowLoopback: false,
      fetch: trackingFetch,
      resolveHost: publicDns,
    });
    expect(explicit443.status).toBe('ok');
    expect(directFetched).toHaveLength(2);

    const implicit443 = await checkNodeIdentity(NODE_443_URL, undefined, {
      allowLoopback: false,
      fetch: trackingFetch,
      resolveHost: publicDns,
    });
    expect(implicit443.status).toBe('ok');
    expect(directFetched).toHaveLength(4);

    // Route-level in production:
    // 1) Supplied DID on :8443, :22, :80 -> 200 with unreachable warnings and 0 probe fetches.
    const prodHarness = createHarness({
      initialRecord: initial,
      isProduction: true,
      nodes: {
        [NODE_443_URL]: {
          info: { status: 200, body: { nodeId: NODE_B_DID } },
          keys: { status: 200, body: { nodeDid: NODE_B_DID } },
        },
      },
    });
    const prodBlockedWithDid = await callPrepare(prodHarness.app, {
      request: {
        nodes: [
          { url: 'https://node-8443.example:8443', did: NODE_A_DID },
          { url: 'https://node-22.example:22', did: NODE_B_DID },
          { url: 'https://node-80.example:80', did: NODE_C_DID },
        ],
      },
    });
    expect(prodBlockedWithDid.status).toBe(200);
    const blockedBody = await prodBlockedWithDid.json() as {
      identity: Array<{ url: string; did: string | null; status: string }>;
    };
    expect(blockedBody.identity).toEqual([
      { url: 'https://node-8443.example:8443', did: NODE_A_DID, status: 'unreachable' },
      { url: 'https://node-22.example:22', did: NODE_B_DID, status: 'unreachable' },
      { url: 'https://node-80.example:80', did: NODE_C_DID, status: 'unreachable' },
    ]);
    expect(prodHarness.fetchedUrls.filter((f) => !f.url.startsWith(REGISTRY_URL))).toHaveLength(0);

    // 2) F6 applies: brand-new host on disallowed port (:8443) WITHOUT a DID -> 422 registry_change_node_did_required, 0 probe fetches.
    const prodNoDid = await callPrepare(prodHarness.app, {
      request: { nodes: [{ url: 'https://node-8443.example:8443' }] },
    });
    expect(prodNoDid.status).toBe(422);
    expect(await prodNoDid.json()).toMatchObject({
      error: 'registry_change_node_did_required',
      host: 'node-8443.example:8443',
    });
    expect(prodHarness.fetchedUrls.filter((f) => !f.url.startsWith(REGISTRY_URL))).toHaveLength(0);

    // 3) Explicit :443 (normalised to implicit https) succeeds and probes in production.
    const prod443 = await callPrepare(prodHarness.app, {
      request: { nodes: [{ url: 'https://node-443.example:443' }] },
    });
    expect(prod443.status).toBe(200);
    const prod443Body = await prod443.json() as {
      identity: Array<{ url: string; did: string | null; status: string }>;
    };
    expect(prod443Body.identity).toEqual([{ url: NODE_443_URL, did: NODE_B_DID, status: 'ok' }]);
    expect(prodHarness.fetchedUrls.filter((f) => f.url.startsWith(NODE_443_URL))).toHaveLength(2);

    // 4) Dev/test (isProduction: false) keeps :8443 probing unchanged.
    const devHarness = createHarness({ initialRecord: initial, isProduction: false });
    const dev8443 = await callPrepare(devHarness.app, {
      request: { nodes: [{ url: NODE_B_URL }] },
    });
    expect(dev8443.status).toBe(200);
    const dev8443Body = await dev8443.json() as {
      identity: Array<{ url: string; did: string | null; status: string }>;
    };
    expect(dev8443Body.identity).toEqual([{ url: NODE_B_URL, did: NODE_B_DID, status: 'ok' }]);
    expect(devHarness.fetchedUrls.filter((f) => f.url.startsWith(NODE_B_URL))).toHaveLength(2);
  });

  test('Bobbie notice-failure note: failed email send logs registry_change_notice_failed (history_id only), publish still returns 200, and GET /history still shows the change', async () => {
    const initial = await makeSignedV2Record({ sequence: 4 });
    const failingEmailSender: EmailSender = {
      emails: {
        send: async () => ({ error: { name: 'internal_server_error', statusCode: 500 } }),
      },
    };
    const { app, credential, historyRows } = createHarness({
      initialRecord: initial,
      emailSender: failingEmailSender,
    });

    const prep = await (await callPrepare(app, { request: { nodes: [{ url: NODE_B_URL }] } })).json() as {
      changeId: string;
      recordHash: string;
      passkey: { challengeToken: string; options: { challenge: string } };
    };

    const capturedLines: string[] = [];
    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string | Uint8Array) => {
      capturedLines.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      return true;
    }) as typeof process.stdout.write;

    let pub: Response;
    try {
      pub = await callPublish(app, {
        changeId: prep.changeId,
        passkeyAssertion: credential.signOffer(prep.passkey),
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(pub.status).toBe(200);
    expect(await pub.json()).toEqual({ sequence: 5, recordHash: prep.recordHash });
    expect(historyRows).toHaveLength(1);
    const rowId = historyRows[0]!.id;
    expect(historyRows[0]!.publishedAt).not.toBeNull();

    // Logged `registry_change_notice_failed` with ONLY base fields + history_id (no email/subject/PII).
    const noticeLines = capturedLines
      .flatMap((chunk) => chunk.split('\n'))
      .filter((line) => line.includes('registry_change_notice_failed'));
    expect(noticeLines).toHaveLength(1);
    const parsed = JSON.parse(noticeLines[0]!) as Record<string, unknown>;
    expect(parsed.event).toBe('registry_change_notice_failed');
    expect(parsed.history_id).toBe(rowId);
    expect(Object.keys(parsed).sort()).toEqual(['event', 'history_id', 'level', 'request_id', 'ts']);
    expect(noticeLines[0]).not.toContain(USER_EMAIL);
    expect(noticeLines[0]).not.toContain(APP_ORIGIN);

    // One's GET /history still shows the published change.
    const histRes = await app.request('/api/registry-change/history?limit=10');
    expect(histRes.status).toBe(200);
    const histBody = await histRes.json() as { history: Array<{ id: string; newSequence: number }> };
    expect(histBody.history.map((r) => r.id)).toEqual([rowId]);
    expect(histBody.history[0]?.newSequence).toBe(5);
  });
});
