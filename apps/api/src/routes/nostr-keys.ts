// Nostr key custody + signing routes.
//
// Structurally separate from routes/keys.ts (Ethereum/ECDSA): Nostr keys are
// secp256k1 Schnorr (BIP-340/NIP-01), never signed via the Ethereum wallet
// path, and never share a route with it. See packages/tee/src/nostr.ts.
import { createHash } from 'node:crypto';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import {
  createTeeClient,
  seal,
  unseal,
  generateNostrKeypair,
  computeEventId,
  signNostrEvent,
  SUPPORTED_NOSTR_KINDS,
  type UnsignedNostrEvent,
} from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import { createSealingContext, deriveKeyForRecord } from '../services/key-sealing';

const prisma = createPrismaClient();
const tee = createTeeClient();

// Fail-closed bounds. Kept intentionally small: this slice supports exactly
// two kinds, never a range.
const MAX_CONTENT_LENGTH = 4096;
const MAX_TAGS = 20;
const MAX_TAG_VALUE_LENGTH = 512;
const MAX_TIMESTAMP_SKEW_SECONDS = 120;
const DEFAULT_GRANT_TTL_SECONDS = 60 * 60 * 12; // 12h, local dev slice only
const MAX_GRANT_TTL_SECONDS = 60 * 60 * 24; // 24h ceiling regardless of requested ttl

export const nostrKeysRouter = new Hono<SessionContext>();

nostrKeysRouter.use('*', requireSession);

function digestEvent(event: UnsignedNostrEvent): string {
  return createHash('sha256').update(JSON.stringify(event)).digest('hex');
}

async function audit(entry: {
  userId?: string | null;
  keyId?: string | null;
  clientOrigin?: string | null;
  kind?: number | null;
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
      allowed: entry.allowed,
      reasonCode: entry.reasonCode,
      requestDigest: entry.requestDigest ?? null,
      // Bounded, non-secret metadata only - never raw content or sealed material.
      tags: entry.tags ? JSON.parse(JSON.stringify(entry.tags)) : undefined,
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
  return value;
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

  const key = await prisma.nostrKey.create({
    data: {
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
    relayUrl?: string;
    ttlSeconds?: number;
  }>();

  const key = await prisma.nostrKey.findFirst({ where: { id: keyId, userId: user.id, revokedAt: null } });
  if (!key) return c.json({ error: 'Key not found' }, 404);

  const clientOrigin = parseClientOrigin(body.clientOrigin);
  if (!clientOrigin) return c.json({ error: 'Invalid clientOrigin' }, 400);

  const kinds = Array.isArray(body.kinds) ? [...new Set(body.kinds)] : [];
  if (kinds.length === 0 || !kinds.every((k) => SUPPORTED_NOSTR_KINDS.has(k))) {
    return c.json({ error: 'kinds must be a non-empty subset of {22242, 9}' }, 400);
  }

  let relayUrl: string | null = null;
  if (kinds.includes(22242)) {
    relayUrl = parseRelayUrl(body.relayUrl);
    if (!relayUrl) return c.json({ error: 'relayUrl required and must be ws(s):// when granting kind 22242' }, 400);
  }

  const ttlSeconds = Math.min(Math.max(1, body.ttlSeconds ?? DEFAULT_GRANT_TTL_SECONDS), MAX_GRANT_TTL_SECONDS);
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

  const grant = await prisma.nostrSigningGrant.create({
    data: {
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      allowedKinds: kinds,
      relayUrl,
      expiresAt,
    },
    select: { id: true, clientOrigin: true, allowedKinds: true, relayUrl: true, expiresAt: true },
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
// (userId, keyId, clientOrigin, kind) - and for kind 22242, the exact
// relayUrl too. Otherwise fails closed with interaction_required.
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
  if (typeof content !== 'string' || content.length > MAX_CONTENT_LENGTH) return deny('content_too_large', 400);
  const tags = Array.isArray(template.tags) ? template.tags : [];
  if (tags.length > MAX_TAGS || tags.some((t) => !Array.isArray(t) || t.some((v) => String(v).length > MAX_TAG_VALUE_LENGTH))) {
    return deny('tags_invalid', 400);
  }
  const skew = Math.abs(Math.floor(Date.now() / 1000) - template.created_at);
  if (skew > MAX_TIMESTAMP_SKEW_SECONDS) return deny('timestamp_out_of_window', 400);

  let relayTag: string | null = null;
  if (template.kind === 22242) {
    if (content !== '') return deny('auth_content_must_be_empty', 400);
    const relayTags = tags.filter((t) => t[0] === 'relay');
    const challengeTags = tags.filter((t) => t[0] === 'challenge');
    if (relayTags.length !== 1 || challengeTags.length !== 1 || tags.length !== 2) {
      return deny('auth_tags_invalid', 400);
    }
    relayTag = relayTags[0]![1] ?? null;
    if (!relayTag) return deny('auth_tags_invalid', 400);
  }

  const grant = await prisma.nostrSigningGrant.findFirst({
    where: {
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      revokedAt: null,
      expiresAt: { gt: new Date() },
      allowedKinds: { has: template.kind },
      ...(template.kind === 22242 ? { relayUrl: relayTag } : {}),
    },
    orderBy: { createdAt: 'desc' },
  });

  if (!grant) {
    const approvalUrl = `/widget/embed/nostr/approve?origin=${encodeURIComponent(clientOrigin)}&keyId=${encodeURIComponent(key.id)}&kind=${template.kind}`;
    await audit({
      userId: user.id,
      keyId: key.id,
      clientOrigin,
      kind: template.kind,
      allowed: false,
      reasonCode: 'interaction_required',
      requestDigest: digestEvent(template as UnsignedNostrEvent),
      tags,
    });
    return c.json({ error: 'interaction_required', approvalUrl }, 403);
  }

  // Final authoritative re-check immediately before releasing the signature,
  // closing the revoke-race window between the lookup above and this point.
  const stillValid = await prisma.nostrSigningGrant.findFirst({
    where: { id: grant.id, revokedAt: null, expiresAt: { gt: new Date() } },
  });
  if (!stillValid) {
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

  const sealingKey = await deriveKeyForRecord(tee, { userId: key.userId, sealingContext: key.sealingContext });
  const unsignedEvent: UnsignedNostrEvent = {
    pubkey: key.pubkeyHex,
    created_at: template.created_at,
    kind: template.kind,
    tags,
    content,
  };

  const signed = await signNostrEvent(
    { sealedSecret: key.sealedSecret, sealingKey, expectedPubkeyHex: key.pubkeyHex },
    unsignedEvent,
  );

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
