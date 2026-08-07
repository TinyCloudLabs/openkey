// Nostr key custody + signing routes.
//
// Structurally separate from routes/keys.ts (Ethereum/ECDSA): Nostr keys are
// secp256k1 Schnorr (BIP-340/NIP-01), never signed via the Ethereum wallet
// path, and never share a route with it. See packages/tee/src/nostr.ts.
//
// Authorization model (capability version 2): a grant scopes an exact
// client origin to a subset of signable event kinds plus a subset of named
// crypto operations (NIP-44 encrypt/decrypt, NIP-59 wrap/unwrap). Every
// result-producing route re-checks the grant immediately before releasing
// its result, and no route ever returns secret material - only signed
// events, ciphertext, plaintext, or an unwrapped rumor.
import { createHash } from 'node:crypto';
import { Hono, type Context } from 'hono';
import { createPrismaClient } from '@openkey/db';
import {
  createTeeClient,
  seal,
  generateNostrKeypair,
  signNostrEvent,
  SUPPORTED_NOSTR_KINDS,
  DESTINATION_BOUND_NOSTR_KINDS,
  isNostrOperation,
  isValidNip44PayloadShape,
  nip44DecryptWithSealedKey,
  nip44EncryptWithSealedKey,
  nip59UnwrapDm,
  nip59WrapDm,
  type NostrOperation,
  type SealedNostrSecret,
  type SignedNostrEvent,
  type UnsignedNostrEvent,
} from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import { createSealingContext, deriveKeyForRecord } from '../services/key-sealing';
import {
  eventDestinationMatchesGrant,
  maxContentLengthForKind,
  validateEventForKind,
  type NostrEventTemplate,
} from '../services/nostr-event-policy';

const prisma = createPrismaClient();
const tee = createTeeClient();

// Fail-closed bounds shared by every kind; per-kind validators narrow
// further (services/nostr-event-policy.ts).
const MAX_TAGS = 20;
const MAX_TAG_VALUES = 20;
const MAX_TAG_VALUE_LENGTH = 512;
const MAX_TIMESTAMP_SKEW_SECONDS = 120;
const DEFAULT_GRANT_TTL_SECONDS = 60 * 60 * 12; // 12h, local dev slice only
const MAX_GRANT_TTL_SECONDS = 60 * 60 * 24; // 24h ceiling regardless of requested ttl

// Crypto-operation bounds. Plaintexts accepted for encryption/wrapping stay
// at the channel-message ceiling; ciphertexts accepted for decryption are
// bounded by the NIP-44 spec's own payload maximum.
const MAX_CRYPTO_PLAINTEXT_LENGTH = 4096;
const MAX_NIP44_PAYLOAD_LENGTH = 87472;
const MAX_WRAP_RECIPIENTS = 8; // Buzz DMs allow 1..8 recipients
const MAX_UNWRAP_RUMOR_CONTENT_LENGTH = 65535;

export const nostrKeysRouter = new Hono<SessionContext>();

nostrKeysRouter.use('*', requireSession);

function digestEvent(event: UnsignedNostrEvent): string {
  return createHash('sha256').update(JSON.stringify(event)).digest('hex');
}

function isBoundedNostrTags(value: unknown): value is string[][] {
  if (!Array.isArray(value) || value.length > MAX_TAGS) return false;
  return value.every((tag) =>
    Array.isArray(tag)
    && tag.length > 0
    && tag.length <= MAX_TAG_VALUES
    && tag.every((item) => typeof item === 'string' && item.length <= MAX_TAG_VALUE_LENGTH),
  );
}

/**
 * Keep audit metadata useful without persisting authorization payloads.
 * Event tag values can contain relay challenges, invite URLs, payload hashes,
 * moderation reasons, and other client-controlled data. Store only bounded
 * tag names/counts. Named-operation callers pass small, purpose-built records;
 * retain only bounded primitive fields from those records.
 */
function sanitizeAuditMetadata(
  value: unknown,
): Record<string, string | number | boolean | null | string[]> | undefined {
  if (Array.isArray(value)) {
    return {
      count: Math.min(value.length, MAX_TAGS + 1),
      names: value.slice(0, MAX_TAGS).map((tag) =>
        Array.isArray(tag) && typeof tag[0] === 'string'
          ? tag[0].slice(0, 64)
          : 'invalid'),
    };
  }
  if (!value || typeof value !== 'object') return undefined;
  const sanitized: Record<string, string | number | boolean | null> = {};
  for (const [key, item] of Object.entries(value).slice(0, 8)) {
    if (typeof item === 'string') sanitized[key.slice(0, 64)] = item.slice(0, 128);
    else if (typeof item === 'number' && Number.isFinite(item)) sanitized[key.slice(0, 64)] = item;
    else if (typeof item === 'boolean' || item === null) sanitized[key.slice(0, 64)] = item;
  }
  return sanitized;
}

async function audit(entry: {
  userId?: string | null;
  keyId?: string | null;
  clientOrigin?: string | null;
  kind?: number | null;
  operation?: string | null;
  allowed: boolean;
  reasonCode: string;
  requestDigest?: string | null;
  tags?: unknown;
}): Promise<void> {
  await prisma.nostrSigningDecision.create({
    data: {
      userId: entry.userId ?? null,
      keyId: entry.keyId ?? null,
      clientOrigin: entry.clientOrigin ?? null,
      kind: entry.kind ?? null,
      operation: entry.operation ?? null,
      allowed: entry.allowed,
      reasonCode: entry.reasonCode,
      requestDigest: entry.requestDigest ?? null,
      // Bounded, non-secret metadata only - never tag values, plaintext,
      // ciphertext bodies, full authorization payloads, or sealed material.
      tags: sanitizeAuditMetadata(entry.tags),
    },
  });
}

/** A parseable absolute http(s) origin with no path, query, or credentials. */
function parseClientOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  if (url.search || url.hash) return null;
  return url.origin;
}

// Validates the scheme but returns the caller's original string (not
// `URL#toString()`, which appends a trailing slash to host-only URLs and
// would silently break exact-match comparison against the relay tag on the
// signed event, e.g. "ws://host:port" vs "ws://host:port/").
function parseRelayUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') return null;
  if (url.username || url.password || url.hash) return null;
  return value;
}

const PUBKEY_HEX_RE = /^[0-9a-f]{64}$/;

type NostrKeyRecord = {
  id: string;
  userId: string;
  pubkeyHex: string;
  sealedSecret: string;
  sealingContext: string;
};

async function sealedSecretForKey(key: NostrKeyRecord): Promise<SealedNostrSecret> {
  const sealingKey = await deriveKeyForRecord(tee, { userId: key.userId, sealingContext: key.sealingContext });
  return { sealedSecret: key.sealedSecret, sealingKey, expectedPubkeyHex: key.pubkeyHex };
}

/**
 * Final authoritative grant re-check, run immediately before a signature,
 * ciphertext, plaintext, or rumor is released - closing the revoke race
 * between the initial lookup and the moment the result leaves the API.
 */
async function grantStillValid(grantId: string): Promise<boolean> {
  const grant = await prisma.nostrSigningGrant.findFirst({
    where: { id: grantId, revokedAt: null, expiresAt: { gt: new Date() } },
  });
  return !!grant;
}

// Get-or-create: this slice supports exactly one Nostr identity per user.
nostrKeysRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{ label?: string }>().catch(() => ({}) as { label?: string });

  const existing = await prisma.nostrKey.findFirst({
    where: { userId: user.id, revokedAt: null },
    select: { id: true, pubkeyHex: true, npub: true, label: true, createdAt: true },
  });
  if (existing) {
    return c.json({ key: existing });
  }

  const keypair = generateNostrKeypair();
  const sealingContext = createSealingContext();
  const sealingKey = await tee.deriveKey(`openkey/key/${sealingContext}`);
  const sealedSecret = await seal(keypair.secretKeyHex, sealingKey);

  // The userId unique constraint makes the database the arbiter when two
  // first-connect requests race. Prisma emits a native upsert for this shape,
  // so both callers receive the same durable identity and the losing generated
  // key is never persisted.
  const key = await prisma.nostrKey.upsert({
    where: { userId: user.id },
    update: {},
    create: {
      userId: user.id,
      label: body.label || 'Nostr Identity',
      pubkeyHex: keypair.pubkeyHex,
      npub: keypair.npub,
      sealedSecret,
      sealingContext,
    },
    select: { id: true, pubkeyHex: true, npub: true, label: true, createdAt: true },
  });

  return c.json({ key }, 201);
});

nostrKeysRouter.get('/', async (c) => {
  const user = c.get('user');
  const keys = await prisma.nostrKey.findMany({
    where: { userId: user.id, revokedAt: null },
    select: { id: true, pubkeyHex: true, npub: true, label: true, createdAt: true },
    orderBy: { createdAt: 'asc' },
  });
  return c.json({ keys });
});

// Create/extend a silent-signing grant. Meant to be called from inside the
// OpenKey-origin widget page after real, explicit user consent - this route
// trusts the caller's own authenticated session, not any client-supplied
// identity claim.
nostrKeysRouter.post('/:keyId/grants', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const body = await c.req.json<{
    clientOrigin?: string;
    kinds?: number[];
    operations?: string[];
    relayUrl?: string;
    ttlSeconds?: number;
  }>();

  const key = await prisma.nostrKey.findFirst({ where: { id: keyId, userId: user.id, revokedAt: null } });
  if (!key) return c.json({ error: 'Key not found' }, 404);

  const clientOrigin = parseClientOrigin(body.clientOrigin);
  if (!clientOrigin) return c.json({ error: 'Invalid clientOrigin' }, 400);

  const kinds = Array.isArray(body.kinds) ? [...new Set(body.kinds)] : [];
  if (!kinds.every((k) => SUPPORTED_NOSTR_KINDS.has(k))) {
    return c.json({ error: 'kinds must be a subset of the supported Nostr kinds' }, 400);
  }

  const operations = Array.isArray(body.operations) ? [...new Set(body.operations)] : [];
  if (!operations.every((op) => isNostrOperation(op))) {
    return c.json({ error: 'operations must be a subset of the supported Nostr operations' }, 400);
  }

  if (kinds.length === 0 && operations.length === 0) {
    return c.json({ error: 'A grant must cover at least one kind or operation' }, 400);
  }

  let relayUrl: string | null = null;
  if (kinds.some((k) => DESTINATION_BOUND_NOSTR_KINDS.has(k))) {
    relayUrl = parseRelayUrl(body.relayUrl);
    if (!relayUrl) {
      return c.json({ error: 'relayUrl required and must be ws(s):// when granting a destination-bound kind' }, 400);
    }
  } else if (body.relayUrl !== undefined) {
    relayUrl = parseRelayUrl(body.relayUrl);
    if (!relayUrl) return c.json({ error: 'relayUrl must be ws(s):// when provided' }, 400);
  }

  const ttlSeconds = Math.min(Math.max(1, body.ttlSeconds ?? DEFAULT_GRANT_TTL_SECONDS), MAX_GRANT_TTL_SECONDS);
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

  const grant = await prisma.nostrSigningGrant.create({
    data: {
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      allowedKinds: kinds,
      allowedOperations: operations,
      relayUrl,
      expiresAt,
    },
    select: {
      id: true,
      clientOrigin: true,
      allowedKinds: true,
      allowedOperations: true,
      relayUrl: true,
      expiresAt: true,
    },
  });

  return c.json({ grant }, 201);
});

nostrKeysRouter.delete('/grants/:grantId', async (c) => {
  const user = c.get('user');
  const grantId = c.req.param('grantId');

  const result = await prisma.nostrSigningGrant.updateMany({
    where: { id: grantId, userId: user.id, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  if (result.count === 0) return c.json({ error: 'Grant not found' }, 404);
  return c.json({ success: true });
});

// Sign an unsigned Nostr event template. Silent iff an active grant covers
// (userId, keyId, clientOrigin, kind) - and, for destination-bound kinds,
// the event's own destination corresponds to the grant's approved relay.
// Otherwise fails closed with interaction_required.
nostrKeysRouter.post('/:keyId/sign-event', async (c) => {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const body = await c.req.json<{ event?: Partial<UnsignedNostrEvent>; clientOrigin?: string }>();

  const clientOrigin = parseClientOrigin(body.clientOrigin);
  const template = body.event;

  const key = await prisma.nostrKey.findFirst({ where: { id: keyId, userId: user.id, revokedAt: null } });
  if (!key) {
    await audit({ userId: user.id, keyId, allowed: false, reasonCode: 'key_not_found' });
    return c.json({ error: 'Key not found' }, 404);
  }

  const deny = async (reasonCode: string, status: 400 | 403 = 403, extra?: Record<string, unknown>) => {
    await audit({
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      kind: template?.kind ?? null,
      allowed: false,
      reasonCode,
      requestDigest: template ? digestEvent(template as UnsignedNostrEvent) : null,
      tags: template?.tags,
    });
    return c.json({ error: reasonCode, ...extra }, status);
  };

  if (!clientOrigin) return deny('invalid_client_origin', 400);
  if (!template || typeof template.kind !== 'number' || typeof template.created_at !== 'number') {
    return deny('malformed_template', 400);
  }
  if (!SUPPORTED_NOSTR_KINDS.has(template.kind)) return deny('kind_not_supported', 400);
  if (typeof template.pubkey !== 'string' || template.pubkey.toLowerCase() !== key.pubkeyHex.toLowerCase()) {
    return deny('pubkey_mismatch', 400);
  }
  const content = template.content ?? '';
  if (typeof content !== 'string' || content.length > maxContentLengthForKind(template.kind)) {
    return deny('content_too_large', 400);
  }
  if (!isBoundedNostrTags(template.tags)) return deny('tags_invalid', 400);
  const tags = template.tags;
  const skew = Math.abs(Math.floor(Date.now() / 1000) - template.created_at);
  if (skew > MAX_TIMESTAMP_SKEW_SECONDS) return deny('timestamp_out_of_window', 400);

  const policyTemplate: NostrEventTemplate = {
    pubkey: template.pubkey,
    created_at: template.created_at,
    kind: template.kind,
    tags,
    content,
  };
  const policy = validateEventForKind(policyTemplate);
  if (!policy.ok) return deny(policy.reason, 400);

  // Grant match: kind coverage in the query, destination correspondence in
  // code (the 24242/27235 comparisons are derivations, not string equality).
  const candidates = await prisma.nostrSigningGrant.findMany({
    where: {
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      revokedAt: null,
      expiresAt: { gt: new Date() },
      allowedKinds: { has: template.kind },
    },
    orderBy: { createdAt: 'desc' },
  });
  const grant = candidates.find((candidate) => eventDestinationMatchesGrant(policyTemplate, candidate.relayUrl));

  if (!grant) {
    const reasonCode = DESTINATION_BOUND_NOSTR_KINDS.has(template.kind) && candidates.length > 0
      ? 'destination_not_granted'
      : 'interaction_required';
    const approvalUrl = `/widget/embed/nostr/approve?origin=${encodeURIComponent(clientOrigin)}&keyId=${encodeURIComponent(key.id)}&kind=${template.kind}`;
    await audit({
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      kind: template.kind,
      allowed: false,
      reasonCode,
      requestDigest: digestEvent(template as UnsignedNostrEvent),
      tags,
    });
    return c.json({ error: 'interaction_required', reason: reasonCode, approvalUrl }, 403);
  }

  const unsignedEvent: UnsignedNostrEvent = {
    pubkey: key.pubkeyHex,
    created_at: template.created_at,
    kind: template.kind,
    tags,
    content,
  };

  const signed = await signNostrEvent(await sealedSecretForKey(key), unsignedEvent);

  // Final authoritative re-check immediately before the signature leaves
  // the API, closing the revoke race for the full duration of the request.
  if (!(await grantStillValid(grant.id))) {
    await audit({
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      kind: template.kind,
      allowed: false,
      reasonCode: 'grant_revoked_at_signing_time',
      requestDigest: digestEvent(template as UnsignedNostrEvent),
      tags,
    });
    return c.json({ error: 'interaction_required' }, 403);
  }

  await audit({
    userId: user.id,
    keyId: key.id,
    clientOrigin,
    kind: template.kind,
    allowed: true,
    reasonCode: 'granted',
    requestDigest: digestEvent(unsignedEvent),
    tags,
  });

  return c.json({ event: signed });
});

// ===== Named crypto operations (NIP-44 / NIP-59) =====
//
// Each operation is authorized like a signature: exact client origin, an
// unrevoked/unexpired grant that names the operation, and a final re-check
// before the result is released. Inputs and outputs are bounded; secret
// material and conversation keys never leave the TEE package.

type OperationAuth =
  | { ok: true; key: NostrKeyRecord; grantId: string; clientOrigin: string }
  | { ok: false; response: Response };

type OperationContext = Context<SessionContext>;

async function authorizeOperation(
  c: OperationContext,
  operation: NostrOperation,
  rawClientOrigin: unknown,
  auditTags?: unknown,
): Promise<OperationAuth> {
  const user = c.get('user');
  const keyId = c.req.param('keyId');
  const clientOrigin = parseClientOrigin(rawClientOrigin);

  const key = await prisma.nostrKey.findFirst({ where: { id: keyId, userId: user.id, revokedAt: null } });
  if (!key) {
    await audit({ userId: user.id, keyId, operation, allowed: false, reasonCode: 'key_not_found' });
    return { ok: false, response: c.json({ error: 'Key not found' }, 404) };
  }
  if (!clientOrigin) {
    await audit({ userId: user.id, keyId: key.id, operation, allowed: false, reasonCode: 'invalid_client_origin' });
    return { ok: false, response: c.json({ error: 'invalid_client_origin' }, 400) };
  }

  const grant = await prisma.nostrSigningGrant.findFirst({
    where: {
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      revokedAt: null,
      expiresAt: { gt: new Date() },
      allowedOperations: { has: operation },
    },
    orderBy: { createdAt: 'desc' },
  });

  if (!grant) {
    const approvalUrl = `/widget/embed/nostr/approve?origin=${encodeURIComponent(clientOrigin)}&keyId=${encodeURIComponent(key.id)}&operation=${operation}`;
    await audit({
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      operation,
      allowed: false,
      reasonCode: 'interaction_required',
      tags: auditTags,
    });
    return { ok: false, response: c.json({ error: 'interaction_required', approvalUrl }, 403) };
  }

  return { ok: true, key, grantId: grant.id, clientOrigin };
}

async function releaseOperationResult(
  c: OperationContext,
  auth: Extract<OperationAuth, { ok: true }>,
  operation: NostrOperation,
  result: Record<string, unknown>,
  auditTags?: unknown,
): Promise<Response> {
  const user = c.get('user');
  if (!(await grantStillValid(auth.grantId))) {
    await audit({
      userId: user.id,
      keyId: auth.key.id,
      clientOrigin: auth.clientOrigin,
      operation,
      allowed: false,
      reasonCode: 'grant_revoked_at_signing_time',
      tags: auditTags,
    });
    return c.json({ error: 'interaction_required' }, 403);
  }
  await audit({
    userId: user.id,
    keyId: auth.key.id,
    clientOrigin: auth.clientOrigin,
    operation,
    allowed: true,
    reasonCode: 'granted',
    tags: auditTags,
  });
  return c.json(result);
}

async function denyOperation(
  c: OperationContext,
  auth: Extract<OperationAuth, { ok: true }>,
  operation: NostrOperation,
  reasonCode: string,
  auditTags?: unknown,
): Promise<Response> {
  await audit({
    userId: c.get('user').id,
    keyId: auth.key.id,
    clientOrigin: auth.clientOrigin,
    operation,
    allowed: false,
    reasonCode,
    tags: auditTags,
  });
  return c.json({ error: reasonCode }, 400);
}

/** First `code`-shaped token of a custody-boundary error, e.g. "nip59_wrong_recipient". */
function teeErrorCode(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message : '';
  const code = message.split(':', 1)[0]?.trim();
  return code && /^[a-z0-9_]+$/.test(code) ? code : fallback;
}

// NIP-44 v2 encrypt-to-self (Buzz encrypted reminders). Peer is required to
// be the key's own pubkey: no supported Buzz journey encrypts to a third
// party outside a gift wrap, so this endpoint refuses to become one.
nostrKeysRouter.post('/:keyId/nip44/encrypt', async (c) => {
  const body = await c.req.json<{ clientOrigin?: string; peerPubkey?: string; plaintext?: string }>()
    .catch(() => ({}) as Record<string, never>);
  const auth = await authorizeOperation(c, 'nip44_encrypt', body.clientOrigin);
  if (!auth.ok) return auth.response;

  const peer = typeof body.peerPubkey === 'string' ? body.peerPubkey.toLowerCase() : '';
  if (!PUBKEY_HEX_RE.test(peer)) return denyOperation(c, auth, 'nip44_encrypt', 'nip44_peer_invalid');
  if (peer !== auth.key.pubkeyHex.toLowerCase()) {
    return denyOperation(c, auth, 'nip44_encrypt', 'nip44_peer_must_be_self');
  }
  if (
    typeof body.plaintext !== 'string'
    || body.plaintext.length === 0
    || body.plaintext.length > MAX_CRYPTO_PLAINTEXT_LENGTH
  ) {
    return denyOperation(c, auth, 'nip44_encrypt', 'nip44_plaintext_invalid');
  }

  let ciphertext: string;
  try {
    ciphertext = await nip44EncryptWithSealedKey(await sealedSecretForKey(auth.key), peer, body.plaintext);
  } catch (error) {
    return denyOperation(c, auth, 'nip44_encrypt', teeErrorCode(error, 'nip44_encrypt_failed'));
  }
  return releaseOperationResult(c, auth, 'nip44_encrypt', { ciphertext });
});

// NIP-44 v2 decrypt from self (reminders) or a peer (observer frames). The
// grant scope - user, key, exact origin, explicit operation - is what keeps
// this from being an open decryption oracle; every call is audited with the
// peer pubkey, and only bounded plaintext ever leaves.
nostrKeysRouter.post('/:keyId/nip44/decrypt', async (c) => {
  const body = await c.req.json<{ clientOrigin?: string; peerPubkey?: string; payload?: string }>()
    .catch(() => ({}) as Record<string, never>);
  const peerForAudit = typeof body.peerPubkey === 'string' ? body.peerPubkey.slice(0, 64) : null;
  const auth = await authorizeOperation(c, 'nip44_decrypt', body.clientOrigin, { peer: peerForAudit });
  if (!auth.ok) return auth.response;

  const peer = typeof body.peerPubkey === 'string' ? body.peerPubkey.toLowerCase() : '';
  if (!PUBKEY_HEX_RE.test(peer)) return denyOperation(c, auth, 'nip44_decrypt', 'nip44_peer_invalid', { peer: peerForAudit });
  if (
    typeof body.payload !== 'string'
    || body.payload.length > MAX_NIP44_PAYLOAD_LENGTH
    || !isValidNip44PayloadShape(body.payload)
  ) {
    return denyOperation(c, auth, 'nip44_decrypt', 'nip44_payload_invalid', { peer });
  }

  let plaintext: string;
  try {
    plaintext = await nip44DecryptWithSealedKey(await sealedSecretForKey(auth.key), peer, body.payload);
  } catch (error) {
    return denyOperation(c, auth, 'nip44_decrypt', teeErrorCode(error, 'nip44_decrypt_failed'), { peer });
  }
  return releaseOperationResult(c, auth, 'nip44_decrypt', { plaintext }, { peer });
});

// NIP-59 gift-wrap a direct message: builds the kind-14 rumor, per-target
// kind-13 seals, and kind-1059 wraps (self-wrap first) entirely inside the
// custody boundary. Seal/wrap timestamps are randomized in the TEE package;
// the rumor keeps the caller's send time, which must be current.
nostrKeysRouter.post('/:keyId/nip59/wrap', async (c) => {
  const body = await c.req.json<{
    clientOrigin?: string;
    content?: string;
    recipients?: string[];
    createdAt?: number;
  }>().catch(() => ({}) as Record<string, never>);
  const recipientCount = Array.isArray(body.recipients) ? body.recipients.length : 0;
  const auth = await authorizeOperation(c, 'nip59_wrap', body.clientOrigin, { recipients: recipientCount });
  if (!auth.ok) return auth.response;
  const auditTags = { recipients: recipientCount };

  if (
    typeof body.content !== 'string'
    || body.content.length === 0
    || body.content.length > MAX_CRYPTO_PLAINTEXT_LENGTH
  ) {
    return denyOperation(c, auth, 'nip59_wrap', 'nip59_content_invalid', auditTags);
  }
  if (!Array.isArray(body.recipients) || body.recipients.length < 1 || body.recipients.length > MAX_WRAP_RECIPIENTS) {
    return denyOperation(c, auth, 'nip59_wrap', 'nip59_recipients_invalid', auditTags);
  }
  const ownPubkey = auth.key.pubkeyHex.toLowerCase();
  const recipients = [...new Set(body.recipients.map((r) => String(r).trim().toLowerCase()))];
  if (recipients.length !== body.recipients.length
    || !recipients.every((r) => PUBKEY_HEX_RE.test(r) && r !== ownPubkey)) {
    return denyOperation(c, auth, 'nip59_wrap', 'nip59_recipients_invalid', auditTags);
  }

  const now = Math.floor(Date.now() / 1000);
  const createdAt = body.createdAt ?? now;
  if (!Number.isInteger(createdAt) || Math.abs(now - createdAt) > MAX_TIMESTAMP_SKEW_SECONDS) {
    return denyOperation(c, auth, 'nip59_wrap', 'timestamp_out_of_window', auditTags);
  }

  let wraps: SignedNostrEvent[];
  try {
    wraps = await nip59WrapDm(await sealedSecretForKey(auth.key), {
      content: body.content,
      recipients,
      createdAt,
    });
  } catch (error) {
    return denyOperation(c, auth, 'nip59_wrap', teeErrorCode(error, 'nip59_wrap_failed'), auditTags);
  }
  return releaseOperationResult(c, auth, 'nip59_wrap', { wraps }, auditTags);
});

// NIP-59 unwrap a kind-1059 gift wrap addressed to this key. The TEE
// package verifies the wrap signature, recipient binding, seal structure
// and signature, sender consistency, and the rumor's recomputed id before
// any plaintext is returned. No timestamp window: wraps are backdated by
// design and may be fetched from arbitrary relay history.
nostrKeysRouter.post('/:keyId/nip59/unwrap', async (c) => {
  const body = await c.req.json<{ clientOrigin?: string; wrap?: Partial<SignedNostrEvent> }>()
    .catch(() => ({}) as Record<string, never>);
  const wrap = body.wrap;
  const wrapIdForAudit = wrap && typeof wrap.id === 'string' ? wrap.id.slice(0, 64) : null;
  const auth = await authorizeOperation(c, 'nip59_unwrap', body.clientOrigin, { wrapId: wrapIdForAudit });
  if (!auth.ok) return auth.response;
  const auditTags = { wrapId: wrapIdForAudit };

  if (
    !wrap
    || typeof wrap !== 'object'
    || typeof wrap.id !== 'string'
    || typeof wrap.sig !== 'string'
    || typeof wrap.pubkey !== 'string'
    || typeof wrap.kind !== 'number'
    || typeof wrap.created_at !== 'number'
    || typeof wrap.content !== 'string'
    || wrap.content.length > MAX_NIP44_PAYLOAD_LENGTH
    || !Array.isArray(wrap.tags)
    || wrap.tags.length > MAX_TAGS
    || !wrap.tags.every((tag) =>
      Array.isArray(tag)
      && tag.length <= MAX_TAG_VALUES
      && tag.every((item) => typeof item === 'string' && item.length <= MAX_TAG_VALUE_LENGTH))
  ) {
    return denyOperation(c, auth, 'nip59_unwrap', 'nip59_wrap_invalid', auditTags);
  }

  let rumor;
  try {
    rumor = await nip59UnwrapDm(await sealedSecretForKey(auth.key), wrap as SignedNostrEvent, {
      maxContentLength: MAX_UNWRAP_RUMOR_CONTENT_LENGTH,
    });
  } catch (error) {
    return denyOperation(c, auth, 'nip59_unwrap', teeErrorCode(error, 'nip59_unwrap_failed'), auditTags);
  }
  return releaseOperationResult(c, auth, 'nip59_unwrap', { rumor }, auditTags);
});
