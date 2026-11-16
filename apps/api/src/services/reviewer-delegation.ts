import { encodeBase58 } from 'ethers';
import type { PrismaClient } from '@openkey/db';
import { HTTPException } from 'hono/http-exception';
import { parsePreparedRecap, canonicalizeServiceName, type RecapEntry } from '../routes/delegate-session';
import { PUBLIC_JWK_FIELDS } from '../routes/delegation-codes';
import { parseStrictSiwe } from './signed-subset';
import { REVIEWER_MAX_SECONDS, capturedReviewer, reviewerActive, reviewerForUser, type ReviewerBinding } from './reviewer-accounts';

function refuse(): never {
  throw new HTTPException(403, { message: 'Reviewer delegation refused' });
}

export function reviewerSessionDid(jwk: unknown): string | null {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return null;
  const key = jwk as Record<string, unknown>;
  if (Object.keys(key).some((field) => !Object.hasOwn(PUBLIC_JWK_FIELDS, field))
    || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string'
    || (key.kid !== undefined && typeof key.kid !== 'string')) return null;
  const publicKey = Buffer.from(key.x, 'base64url');
  if (publicKey.length !== 32 || publicKey.toString('base64url') !== key.x) return null;
  return 'did:key:z' + encodeBase58(Buffer.concat([Buffer.from([0xed, 0x01]), publicKey]));
}

export function reviewerPermissionAllowed(binding: ReviewerBinding, entry: RecapEntry): boolean {
  if (entry.space !== binding.spaceId || !entry.actions.length) return false;
  const service = canonicalizeServiceName(entry.service);
  if (service === 'tinycloud.capabilities') return entry.path === '' && entry.actions.every((action) => action === 'tinycloud.capabilities/read');
  if (service !== 'tinycloud.kv') return false;
  const todo = entry.path === 'xyz.tinycloud.tinyapps.todos' || entry.path.startsWith('xyz.tinycloud.tinyapps.todos/');
  const catalog = entry.path === 'xyz.tinycloud.tinyapps.catalog/todos' || entry.path.startsWith('xyz.tinycloud.tinyapps.catalog/todos/');
  const catalogRead = entry.path === 'xyz.tinycloud.tinyapps.catalog/' && entry.actions.every((action) => ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata'].includes(action));
  return (todo || catalog || catalogRead)
    && entry.actions.every((action) => ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put', 'tinycloud.kv/del'].includes(action));
}

export async function currentReviewerDelegate(database: PrismaClient, userId: string): Promise<ReviewerBinding | null> {
  const binding = await reviewerForUser(database, userId);
  if (!binding) return null;
  const captured = capturedReviewer();
  if (!captured?.sessionId || captured.userId !== userId || !reviewerActive(binding, captured.epoch)
    || !binding.sessionDid || binding.grantSessionId !== captured.sessionId) refuse();
  const [session, consent, client] = await Promise.all([
    database.session.findFirst({ where: {
      id: captured.sessionId, userId, reviewerEpoch: captured.epoch, expiresAt: { gt: new Date() },
      createdAt: { gt: new Date(Date.now() - REVIEWER_MAX_SECONDS * 1000) },
    } }),
    database.oauthConsent.findUnique({ where: { userId_clientId: { userId, clientId: binding.clientId! } } }),
    database.oauthClient.findUnique({
      where: { clientId: binding.clientId! }, select: { disabled: true, redirectUris: true, scopes: true },
    }),
  ]);
  if (!session || consent?.reviewerEpoch !== binding.installEpoch || !consent.scopes.includes('tinycloud:mcp')
    || !client || client.disabled || !client.redirectUris.includes(binding.redirectUri!)
    || !client.scopes?.includes('tinycloud:mcp')) refuse();
  return binding;
}

export async function assertReviewerSignedDelegation(database: PrismaClient, userId: string, message: string): Promise<void> {
  const binding = await currentReviewerDelegate(database, userId);
  if (!binding) return;
  const key = await database.ethereumKey.findFirst({ where: { id: binding.keyId!, userId, archivedAt: null } });
  const parsed = parseStrictSiwe(message);
  if (!key || !parsed.ok) refuse();
  const siwe = parsed.siwe;
  const now = Date.now();
  const expiresAt = Date.parse(siwe.expirationTime ?? '');
  const issuedAt = Date.parse(siwe.issuedAt);
  if (siwe.address.toLowerCase() !== key.address.toLowerCase() || siwe.chainId !== '1'
    || (siwe.uri !== binding.sessionDid && siwe.uri !== binding.sessionDid + '#' + binding.sessionDid!.slice('did:key:'.length))
    || !Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + 3600_000
    || !Number.isFinite(issuedAt) || issuedAt > now + 30_000 || issuedAt < now - 600_000
    || (siwe.notBefore && (Date.parse(siwe.notBefore) < now - 30_000 || Date.parse(siwe.notBefore) > now + 30_000))
    || !siwe.recap || siwe.recap.prf.length !== 0) refuse();
  const entries = parsePreparedRecap(message);
  if (!entries.length || !entries.every((entry) => reviewerPermissionAllowed(binding, entry))) refuse();
}
