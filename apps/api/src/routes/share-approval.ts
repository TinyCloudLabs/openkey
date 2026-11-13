import { Hono, type MiddlewareHandler } from 'hono';
import { getAddress, verifyMessage } from 'ethers';
import type { SessionContext } from '../middleware/session';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';
import { ShareWindowContexts } from '../services/share-window-context';
import { ShareApprovalError } from '../services/share-approval';
import { ShareApprovalRequests, type ShareApprovalAccount } from '../services/share-approval-request';

type Preview = ReturnType<ShareApprovalRequests['preview']>;
export interface ShareApprovalLifecycle {
  options(preview: Preview, account: ShareApprovalAccount): Promise<unknown>;
  verify(preview: Preview, account: ShareApprovalAccount, token: string, response: unknown): Promise<void>;
  resume(preview: Preview, account: ShareApprovalAccount, token: string): void;
  assertResumed(preview: Preview, account: ShareApprovalAccount, token: string): void;
  consume(preview: Preview, account: ShareApprovalAccount, token: string): void;
  cancel(preview: Preview, account: ShareApprovalAccount, token: string): void;
}
export interface ShareApprovalDependencies {
  findAccount(userId: string, authSessionId: string, keyId: string): Promise<ShareApprovalAccount | null>;
  signManaged(account: ShareApprovalAccount, message: string): Promise<string>;
  lifecycle: ShareApprovalLifecycle;
}

/** The caller mounts this only with the reviewed purpose-bound continuation runtime. */
export function createShareApprovalRouter(requests: ShareApprovalRequests, windows: ShareWindowContexts, deps: ShareApprovalDependencies,
  sessionMiddleware: MiddlewareHandler<SessionContext>) {
  const router = new Hono<SessionContext>();
  router.onError((error, c) => {
    if (error instanceof ShareApprovalError) return c.json({ code: error.code }, 403);
    return c.json({ code: 'share_approval_refused' }, 403);
  });
  router.use('*', sessionMiddleware);
  router.use('*', async (c, next) => {
    const refused = rejectNonBrowserControlRequest(c);
    if (refused) return refused;
    c.header('Cache-Control', 'no-store');
    await next();
  });
  router.post('/window', async c => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).sort().join(',') !== 'keyId,observedOrigin,requestId' ||
      typeof body.keyId !== 'string' || typeof body.requestId !== 'string' || typeof body.observedOrigin !== 'string') {
      return c.json({ code: 'invalid_share_window' }, 400);
    }
    const account = await deps.findAccount(c.get('user').id, c.get('session').id, body.keyId);
    if (!account) return c.json({ code: 'share_account_changed' }, 403);
    const issued = windows.issue(account, body.requestId, body.observedOrigin);
    return c.json({ windowContextToken: issued.token, requestId: issued.context.requestId, expiresAt: issued.context.expiresAt });
  });
  router.post('/window/cancel', async c => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).sort().join(',') !== 'keyId,requestId,windowContextToken' ||
      typeof body.keyId !== 'string' || typeof body.requestId !== 'string' || typeof body.windowContextToken !== 'string') {
      return c.json({ code: 'invalid_share_window' }, 400);
    }
    const account = await deps.findAccount(c.get('user').id, c.get('session').id, body.keyId);
    if (!account) return c.json({ code: 'share_account_changed' }, 403);
    windows.cancel(body.windowContextToken, account, body.requestId);
    return c.json({ cancelled: true });
  });
  router.post('/options', async c => {
    const body = await c.req.json().catch(() => null);
    if (!body || Object.keys(body).sort().join(',') !== 'intent,requestId,windowContextToken' ||
      typeof body.windowContextToken !== 'string' || typeof body.requestId !== 'string' || !body.intent || typeof body.intent.keyId !== 'string') {
      return c.json({ code: 'invalid_share_intent' }, 400);
    }
    const account = await deps.findAccount(c.get('user').id, c.get('session').id, body.intent.keyId);
    if (!account) return c.json({ code: 'share_account_changed' }, 403);
    const window = windows.read(body.windowContextToken, account, body.requestId);
    const preview = requests.prepare(body.intent, account, window,
      () => windows.consume(body.windowContextToken, account, body.requestId));
    try {
      return c.json({ ...preview, assertion: await deps.lifecycle.options(preview, account) });
    } catch (error) {
      requests.cancel(preview.requestId, account);
      throw error;
    }
  });
  for (const phase of ['verify', 'resume', 'preview', 'sign', 'cancel'] as const) {
    router.post(`/${phase}`, async c => {
      const body = await c.req.json().catch(() => null);
      const allowed = ['requestId', 'keyId', 'token', ...(phase === 'verify' ? ['response'] : []),
        ...(phase === 'sign' ? ['externalSignature', 'intentDigest'] : [])];
      if (!body || Object.keys(body).some(key => !allowed.includes(key)) ||
        typeof body.requestId !== 'string' || typeof body.keyId !== 'string' || typeof body.token !== 'string') {
        return c.json({ code: 'invalid_share_request' }, 400);
      }
      const account = await deps.findAccount(c.get('user').id, c.get('session').id, body.keyId);
      if (!account) return c.json({ code: 'share_account_changed' }, 403);
      const preview = requests.preview(body.requestId, account);
      if (phase === 'cancel') {
        deps.lifecycle.cancel(preview, account, body.token);
        requests.cancel(body.requestId, account);
        return c.json({ cancelled: true });
      }
      if (phase === 'verify') {
        await deps.lifecycle.verify(preview, account, body.token, body.response);
        return c.json({ verified: true });
      }
      if (phase === 'resume') {
        deps.lifecycle.resume(preview, account, body.token);
        return c.json({ resumed: true });
      }
      deps.lifecycle.assertResumed(preview, account, body.token);
      if (phase === 'preview') return c.json(preview);
      if (body.intentDigest !== preview.intentDigest) return c.json({ code: 'share_approval_binding_mismatch' }, 403);
      const signature = body.externalSignature;
      if ((account.keyType === 'EXTERNAL' && typeof signature !== 'string') ||
        (account.keyType === 'MANAGED' && signature !== undefined)) {
        return c.json({ code: 'invalid_share_signer' }, 400);
      }
      if (account.keyType === 'EXTERNAL') {
        try {
          if (getAddress(verifyMessage(preview.prepared.siwe, signature)) !== getAddress(account.address)) {
            return c.json({ code: 'share_signature_mismatch' }, 403);
          }
        } catch { return c.json({ code: 'share_signature_mismatch' }, 403); }
      }
      const result = await requests.sign(body.requestId, account, preview.intentDigest,
        () => deps.lifecycle.consume(preview, account, body.token), message =>
          account.keyType === 'EXTERNAL' ? Promise.resolve(signature) : deps.signManaged(account, message));
      // A key archival, account/session change or logout during signing cannot deliver a result.
      const current = await deps.findAccount(account.userId, account.authSessionId, account.keyId);
      if (!current || (['userId', 'authSessionId', 'keyId', 'keyType', 'address'] as const)
        .some(field => current[field] !== account[field])) return c.json({ code: 'share_account_changed' }, 403);
      return c.json(result);
    });
  }
  return router;
}
