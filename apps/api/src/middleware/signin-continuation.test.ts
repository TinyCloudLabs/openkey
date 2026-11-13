import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import { requireSignInContinuation } from './signin-continuation';

test('default-off routes match nonexistent routes without touching authentication or assertion state', async () => {
  const original = process.env.OPENKEY_SIGNIN_CONTINUATION;
  try {
    const app = new Hono();
    app.notFound(c => c.json({ error: 'Not found' }, 404));
    let handled = 0;
    const router = new Hono();
    router.use('*', requireSignInContinuation);
    router.all('/*', c => { handled++; return c.json({ enabled: true }); });
    app.route('/api/delegate/signin', router);
    for (const setting of [undefined, 'false', '1']) {
      if (setting === undefined) delete process.env.OPENKEY_SIGNIN_CONTINUATION;
      else process.env.OPENKEY_SIGNIN_CONTINUATION = setting;
      const missing = await app.request('/missing', { method: 'POST' });
      for (const phase of ['options', 'verify', 'cancel', 'capabilities']) {
        const response = await app.request(`/api/delegate/signin/${phase}`, { method: phase === 'capabilities' ? 'GET' : 'POST', body: phase === 'capabilities' ? undefined : 'not json' });
        expect(response.status).toBe(missing.status);
        expect(await response.text()).toBe(await missing.clone().text());
      }
    }
    expect(handled).toBe(0);
    process.env.OPENKEY_SIGNIN_CONTINUATION = 'true';
    expect((await app.request('/api/delegate/signin/options', { method: 'POST' })).status).toBe(200);
    expect(handled).toBe(1);
  } finally {
    if (original === undefined) delete process.env.OPENKEY_SIGNIN_CONTINUATION;
    else process.env.OPENKEY_SIGNIN_CONTINUATION = original;
  }
});
