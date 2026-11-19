import { Hono, type Context, type MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { isOrgKeyCustodyEnabled, isOrgKeyOwnerAccount } from '../services/org-keys';
import { IssuerDidUnavailable, type IssuerFetch } from '../services/issuer-jws';
import { createOrgOwnerCheckVerifier, OrgOwnerCheckUnauthorized } from '../services/org-owner-check';

// TC-128 OK-1: a server-to-server read-only question from OpenCredentials. The caller is authenticated only by
// its issuer-signed JWS (no cookie, no session). The route sets no CORS header and index.ts exempts its path from
// the credentialed CORS policy. No replay store: a replayed, unexpired JWS re-asks the same read-only question.

const MAX_EMPTY_CHUNKS = 8;

export interface OrgOwnerCheckRouterDeps {
  prisma: PrismaClient;
  fetch?: IssuerFetch;
}

const requireOrgKeyCustodyEnabled: MiddlewareHandler = async (c, next) => {
  if (!isOrgKeyCustodyEnabled()) return c.json({ error: 'Not found' }, 404);
  await next();
};

function reply(c: Context, status: 200 | 400 | 401 | 503, body: Record<string, unknown>): Response {
  c.header('Cache-Control', 'no-store');
  return c.json(body, status);
}

/** True when the request carries any body byte. Reads at most the first non-empty chunk. */
async function hasBody(request: Request): Promise<boolean> {
  const length = request.headers.get('content-length');
  if (length !== null && length !== '0') return true;
  if (request.body === null) return false;
  const reader = request.body.getReader();
  try {
    for (let i = 0; i < MAX_EMPTY_CHUNKS; i += 1) {
      const { done, value } = await reader.read();
      if (done) return false;
      if (value.length > 0) return true;
    }
    return true;
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

export function createOrgOwnerCheckRouter(deps: OrgOwnerCheckRouterDeps) {
  const verify = createOrgOwnerCheckVerifier(deps.fetch);
  const router = new Hono();
  router.use('*', requireOrgKeyCustodyEnabled);
  router.post('/', async (c) => {
    if (await hasBody(c.req.raw)) return reply(c, 400, { error: 'bad_request' });
    let claims;
    try {
      claims = await verify(c.req.header('authorization'));
    } catch (error) {
      if (error instanceof OrgOwnerCheckUnauthorized) return reply(c, 401, { error: 'unauthorized' });
      if (error instanceof IssuerDidUnavailable) return reply(c, 503, { error: 'issuer_unavailable' });
      throw error;
    }
    return reply(c, 200, { owner: await isOrgKeyOwnerAccount(deps.prisma, claims.keyId, claims.account) });
  });
  return router;
}
