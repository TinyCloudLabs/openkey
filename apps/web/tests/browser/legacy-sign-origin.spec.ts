import { readFileSync } from 'node:fs';
import { test, expect, type Page } from '@playwright/test';
import { ORIGIN, LOOPBACK_ORIGIN } from './e2e-port';
const address = '0x1111111111111111111111111111111111111111';
const key = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
  label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' };
async function fixture(page: Page) {
  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'fixture-session'));
  await page.context().route('**/api/auth/get-session**', route => route.fulfill({
    json: { session: { id: 'fixture-session' }, user: { id: 'fixture-user' } },
  }));
  await page.context().route('**/api/keys**', route => route.fulfill({ json:
    route.request().url().endsWith('/sign') ? { signature: '0x00', address } :
    route.request().url().includes('selected-key') ? { key } : { keys: [key] },
  }));
  await page.goto('/__parity_harness');
  // Observe actual targetOrigin arguments, including targets a receiver would silently drop.
  await page.evaluate(() => {
    (window as any).posts = [];
    const post = window.postMessage.bind(window);
    window.postMessage = ((data: any, target: any) => {
      (window as any).posts.push({ data, target }); post(data, target);
    }) as typeof window.postMessage;
  });
}
for (const surface of ['embed/sign', 'sign']) {
  for (const outcome of ['success', 'cancel']) {
    for (const configuredOrigin of [false, true]) {
    test(`legacy ${surface} ${outcome} ${configuredOrigin ? 'configured' : 'wildcard'} pins every target to event.origin and ignores a later origin`, async ({ page }) => {
      await fixture(page);
      await page.evaluate(({ surface, configuredOrigin }) => {
        const frame = document.createElement('iframe'); frame.id = 'legacy';
        frame.src = `/widget/${surface}${configuredOrigin ? `?origin=${encodeURIComponent(location.origin)}` : ''}`; document.body.append(frame);
      }, { surface, configuredOrigin });
      await expect.poll(() => page.evaluate(() => (window as any).posts.some((p: any) => p.data.type === 'openkey:ready'))).toBe(true);
      await page.evaluate(() => document.querySelector<HTMLIFrameElement>('#legacy')!.contentWindow!.postMessage({
        type: 'openkey:sign:request', message: 'exact legacy bytes', keyId: 'selected-key', origin: 'https://different.example',
      }, location.origin));
      const frame = page.frames().find(f => f.url().includes(`/widget/${surface}`))!;
      await expect(frame.getByRole('button', { name: /^(Sign|Approve)$/ })).toBeVisible();
      await frame.evaluate(() => window.dispatchEvent(new MessageEvent('message', {
        source: window.parent, origin: 'https://later.example',
        data: { type: 'openkey:sign:request', message: 'must not replace the request', keyId: 'other-key' },
      })));
      await expect(frame.getByText('exact legacy bytes', { exact: true })).toHaveCount(1);
      await expect(frame.getByText('must not replace the request', { exact: true })).toHaveCount(0);
      await frame.getByRole('button', { name: outcome === 'success' ? /^(Sign|Approve)$/ : /^(Cancel|Decline)$/ }).click();
      await expect.poll(() => page.evaluate(() => (window as any).posts.some((p: any) => p.data.type === 'openkey:close'))).toBe(true);
      const posts = await page.evaluate(() => (window as any).posts.filter((p: any) => p.data.type !== 'openkey:sign:request'));
      expect(posts.find((p: any) => p.data.type === 'openkey:sign:response').data).toMatchObject(
        outcome === 'success' ? { signature: '0x00' } : { success: false });
      expect(posts.every((p: any) => p.target === ORIGIN)).toBe(true);
      if (surface === 'embed/sign' && configuredOrigin) {
        expect(posts.some((p: any) => p.data.type === 'openkey:resize')).toBe(true);
      }
    });
    }
  }
  test(`legacy ${surface} ignores opaque and unusable request origins`, async ({ page }) => {
    await fixture(page);
    await page.evaluate(surface => {
      const frame = document.createElement('iframe'); frame.id = 'legacy';
      frame.src = `/widget/${surface}`; document.body.append(frame);
    }, surface);
    await expect.poll(() => page.evaluate(() => (window as any).posts.length)).toBeGreaterThan(0);
    const frame = page.frames().find(f => f.url().includes(`/widget/${surface}`))!;
    await frame.evaluate(() => {
      for (const origin of ['null', '', '*', 'file:///tmp/caller']) {
        window.dispatchEvent(new MessageEvent('message', { source: window.parent, origin,
          data: { type: 'openkey:sign:request', message: 'opaque request', keyId: 'selected-key' } }));
      }
    });
    await expect(frame.getByText('opaque request', { exact: true })).toHaveCount(0);
    expect(await page.evaluate(() => (window as any).posts.some((p: any) => p.data.type === 'openkey:sign:response'))).toBe(false);
  });
}
  for (const wildcard of [false, true]) {
  test(`real SDK legacy signMessage completes in popup ${wildcard ? 'wildcard' : 'configured'} with default referrer policy`, async ({ page }) => {
    await fixture(page);
    // Also exercise the wildcard widget's browser-derived ready bootstrap.
    if (wildcard) await page.context().route('**/widget/**', route => {
      const url = new URL(route.request().url());
      if (!url.searchParams.has('origin')) return route.continue();
      url.searchParams.delete('origin');
      return route.fulfill({ status: 302, headers: { location: url.href } });
    });
    await page.route('**/__sdk.mjs', route => route.fulfill({ contentType: 'text/javascript',
      body: readFileSync(new URL('../../../../packages/sdk/dist/index.mjs', import.meta.url)),
    }));
    await page.addScriptTag({ type: 'module', content: `import { OpenKey } from '/__sdk.mjs'; window.OpenKeyTest = OpenKey;` });
    await expect.poll(() => page.evaluate(() => typeof (window as any).OpenKeyTest)).toBe('function');
    const popupPromise = page.waitForEvent('popup');
    await page.evaluate((host) => {
      const sdk = new (window as any).OpenKeyTest({ host, oauthHost: host, mode: 'popup' });
      (window as any).result = null;
      sdk.signMessage({ message: 'SDK legacy exact bytes', keyId: 'selected-key' }).then((result: unknown) => { (window as any).result = result; });
    }, LOOPBACK_ORIGIN);
    const popup = await popupPromise;
    await popup.getByRole('button', { name: /^(Sign|Approve)$/ }).click();
    await expect.poll(() => page.evaluate(() => (window as any).result)).toMatchObject({ signature: '0x00', address });
  });
}

for (const configuredOrigin of [false, true]) {
  test(`popup close before a request ${configuredOrigin ? 'posts to configured origin' : 'closes without posting'}`, async ({ page }) => {
    await fixture(page);
    const opened = page.waitForEvent('popup');
    await page.evaluate(configured => window.open(
      `/widget/sign${configured ? `?origin=${encodeURIComponent(location.origin)}` : ''}`,
      'pre-request-sign', 'popup=true',
    ), configuredOrigin);
    const popup = await opened;
    const close = popup.getByRole('button', { name: '×', exact: true });
    await expect(close).toBeVisible();
    // Discard bootstrap ready: assert only messages caused by the pre-request close.
    await page.evaluate(() => { (window as any).posts = []; });
    const closed = popup.waitForEvent('close');
    await close.click();
    await closed;
    if (configuredOrigin) {
      await expect.poll(() => page.evaluate(() => (window as any).posts)).toEqual([
        { data: { type: 'openkey:close' }, target: ORIGIN },
      ]);
    } else {
      expect(await page.evaluate(() => (window as any).posts)).toEqual([]);
    }
  });
}
