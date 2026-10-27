import { randomBytes } from 'node:crypto';
import { Hono, type MiddlewareHandler } from 'hono';
import { verifyMessage } from 'ethers';
import { buildOwnerRevocationSiwe, ownerRevocationAddress, ownerRevocationResult } from '@openkey/capability-review';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import type { SessionContext } from '../middleware/session';
import { resolveOriginPolicy } from '../origin-policy';
import { PreparedHandoffError, type PreparedHandoffService } from '../services/prepared-handoff';

export type OwnerRevocationKey = { id: string; userId: string | null; address: string; keyType: string; sealedBlob: string | null; sealingContext?: string | null };
export type OwnerRevocationDependencies = {
  findKey: (keyId: string, userId: string) => Promise<OwnerRevocationKey | null>;
  signManaged: (key: OwnerRevocationKey, blob: string, message: string) => Promise<string>;
};

export function createOwnerRevocationRouter(service: PreparedHandoffService, dependencies: OwnerRevocationDependencies, sessionMiddleware: MiddlewareHandler<SessionContext>) {
  const router = new Hono<SessionContext>();
  router.onError((error, c) => {
    if (error instanceof PreparedHandoffError) return c.json({ code: error.code, error: error.message }, error.status);
    throw error;
  });
  router.use('*', requireOpenKeyOriginForBearer, sessionMiddleware);

  router.post('/prepare', async c => {
    const body: unknown = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
      Object.keys(body).sort().join(',') !== 'keyId,ticket' ||
      !('ticket' in body) || typeof body.ticket !== 'string' ||
      !('keyId' in body) || typeof body.keyId !== 'string') {
      return c.json({ error: 'ticket and keyId are required' }, 400);
    }
    const origin = c.req.header('origin');
    if (!origin || origin !== (process.env.WEBAUTHN_ORIGIN || resolveOriginPolicy('http://localhost:5173')[0]) ||
      !resolveOriginPolicy('http://localhost:5173').includes(origin)) return c.json({ error: 'OpenKey web signing origin required' }, 403);
    const request = await service.ownerRevocation(body.ticket, c.get('user').id);
    const key = await dependencies.findKey(body.keyId, c.get('user').id);
    if (!key || key.address.toLowerCase() !== ownerRevocationAddress(request).toLowerCase()) {
      return c.json({ error: 'The signed-in owner account does not match this request' }, 403);
    }
    const issuedAt = new Date();
    const token = `${issuedAt.getTime()}.${Buffer.from(origin).toString('base64url')}.${randomBytes(32).toString('base64url')}`;
    await service.bindOwnerRevocation(body.ticket, c.get('user').id, key.id, token);
    c.header('Cache-Control', 'no-store');
    return c.json({ authorizationContextToken: token, siwe: buildOwnerRevocationSiwe(request, new URL(origin).host, issuedAt) });
  });

  router.post('/sign', async c => {
    const body: unknown = await c.req.json().catch(() => null);
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
      Object.keys(body).some(field => !['ticket', 'keyId', 'authorizationContextToken', 'externalSignature'].includes(field)) ||
      !('ticket' in body) || typeof body.ticket !== 'string' ||
      !('keyId' in body) || typeof body.keyId !== 'string' ||
      !('authorizationContextToken' in body) || typeof body.authorizationContextToken !== 'string' ||
      ('externalSignature' in body && typeof body.externalSignature !== 'string')) {
      return c.json({ error: 'Invalid owner-revocation signing request' }, 400);
    }
    const request = await service.ownerRevocation(body.ticket, c.get('user').id);
    const record = await service.assertContext(body.ticket, c.get('user').id, body.authorizationContextToken, 'owner-revocation');
    if (record.selectedKeyId !== body.keyId) return c.json({ error: 'Owner signing key differs from the reviewed key' }, 403);
    const key = await dependencies.findKey(body.keyId, c.get('user').id);
    if (!key || key.address.toLowerCase() !== ownerRevocationAddress(request).toLowerCase()) {
      return c.json({ error: 'The signed-in owner account does not match this request' }, 403);
    }
    const [time, encodedOrigin, random, extra] = body.authorizationContextToken.split('.');
    const issuedAt = new Date(Number(time));
    const origin = c.req.header('origin');
    if (extra || !time || !random || !/^[A-Za-z0-9_-]{43}$/.test(random) || !origin ||
      Buffer.from(encodedOrigin ?? '', 'base64url').toString() !== origin ||
      origin !== (process.env.WEBAUTHN_ORIGIN || resolveOriginPolicy('http://localhost:5173')[0]) ||
      !resolveOriginPolicy('http://localhost:5173').includes(origin) ||
      !Number.isFinite(issuedAt.getTime()) || issuedAt.getTime() > Date.now() ||
      issuedAt.getTime() + 300_000 < Date.now() || issuedAt.getTime() >= Date.parse(request.expiresAt)) {
      return c.json({ error: 'Owner signing preview expired or changed' }, 410);
    }
    const siwe = buildOwnerRevocationSiwe(request, new URL(origin).host, issuedAt);
    let signature: string;
    if (key.keyType === 'EXTERNAL') {
      if (!('externalSignature' in body) || typeof body.externalSignature !== 'string') return c.json({ error: 'Owner wallet signature required' }, 400);
      signature = body.externalSignature;
    } else {
      if ('externalSignature' in body || !key.sealedBlob) return c.json({ error: 'Managed owner key required' }, 400);
      // The ticket is reserved before the managed key can sign again.
      await service.reserveSigning(body.ticket, c.get('user').id, body.authorizationContextToken, key.id, 'owner-revocation');
      signature = await dependencies.signManaged(key, key.sealedBlob, siwe);
    }
    try {
      if (verifyMessage(siwe, signature).toLowerCase() !== key.address.toLowerCase()) throw new Error();
    } catch {
      return c.json({ error: 'Owner signature does not match the reviewed account' }, 403);
    }
    if (key.keyType === 'EXTERNAL') await service.reserveSigning(body.ticket, c.get('user').id, body.authorizationContextToken, key.id, 'owner-revocation');
    const delivery = await service.completeSigning(body.ticket, c.get('user').id, body.authorizationContextToken, key.id);
    c.header('Cache-Control', 'no-store');
    return c.json({ ...ownerRevocationResult(siwe, signature), ...delivery });
  });
  return router;
}
