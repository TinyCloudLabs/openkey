import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { createShareApprovalMount } from '../routes/share-approval-mount';
import type { SessionContext } from '../middleware/session';
import { requireShareApproval } from '../middleware/share-approval';

function fixture() {
  let processed = 0;
  const app = new Hono();
  app.use('/api/delegate/share/*', requireShareApproval);
  app.use('*', cors({ origin: 'https://openkey.test', credentials: true }));
  const runtime = new Hono<SessionContext>();
  runtime.use('*', async (_c, next) => { processed++; await next(); });
  runtime.post('/window', c => c.json({ processed: true }));
  app.route('/api/delegate/share', createShareApprovalMount(runtime));
  return { app, processed: () => processed };
}

test('share routes are dark before CORS, authentication and request processing unless explicitly enabled', async () => {
  const previous = process.env.OPENKEY_SHARE_APPROVAL;
  try {
    for (const flag of [undefined, '', 'false', '1', 'TRUE']) {
      if (flag === undefined) delete process.env.OPENKEY_SHARE_APPROVAL;
      else process.env.OPENKEY_SHARE_APPROVAL = flag;
      const f = fixture();
      for (const method of ['GET', 'POST', 'OPTIONS']) {
        for (const path of ['capabilities', 'window', 'options', 'verify', 'resume', 'preview', 'sign', 'cancel', 'window/cancel']) {
          const response = await f.app.request(`https://api.openkey.test/api/delegate/share/${path}`, {
            method, headers: { origin: 'https://thirdparty.example', 'access-control-request-method': 'POST' },
          });
          expect(response.status).toBe(404);
        }
      }
      expect(f.processed()).toBe(0);
    }
  } finally {
    if (previous === undefined) delete process.env.OPENKEY_SHARE_APPROVAL;
    else process.env.OPENKEY_SHARE_APPROVAL = previous;
  }
});

test('enabled share advertisement is public and credential-free while mutation routes retain credentialed CORS', async () => {
  const previous = process.env.OPENKEY_SHARE_APPROVAL;
  try {
    process.env.OPENKEY_SHARE_APPROVAL = 'true';
    const f = fixture();
    const response = await f.app.request('https://api.openkey.test/api/delegate/share/capabilities', {
      headers: { origin: 'https://thirdparty.example' },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ enabled: true, protocolVersion: 1 });
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(response.headers.get('Access-Control-Allow-Credentials')).toBeNull();
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(f.processed()).toBe(0);
    const mutation = await f.app.request('https://api.openkey.test/api/delegate/share/window', {
      method: 'POST', headers: { origin: 'https://openkey.test' },
    });
    expect(mutation.headers.get('Access-Control-Allow-Origin')).toBe('https://openkey.test');
    expect(mutation.headers.get('Access-Control-Allow-Credentials')).toBe('true');
    expect(f.processed()).toBe(1);
  } finally {
    if (previous === undefined) delete process.env.OPENKEY_SHARE_APPROVAL;
    else process.env.OPENKEY_SHARE_APPROVAL = previous;
  }
});
