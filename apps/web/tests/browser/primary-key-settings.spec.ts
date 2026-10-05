// TC-704: exercise key settings against a mocked API, including confirmation
// and server-owned primary state. No API server is required.
import { test, expect, type Page, type Route } from '@playwright/test';
import type { EthereumKey } from '../../src/lib/api';

const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const formerPrimary: EthereumKey = {
  id: 'key_0', address: '0x1111111111111111111111111111111111111111', publicKey: '0x',
  keyIndex: 0, label: 'Original owner', keyType: 'MANAGED', isPrimary: true,
  createdAt: '2026-10-01T00:00:00.000Z',
};
const target: EthereumKey = {
  id: 'key_1', address: '0x2222222222222222222222222222222222222222', publicKey: '0x',
  keyIndex: 1, label: 'Work owner', keyType: 'MANAGED', isPrimary: false,
  createdAt: '2026-10-02T00:00:00.000Z',
};

async function mock(page: Page, options: {
  keys?: EthereumKey[];
  fail?: boolean;
  beforeChange?: () => Promise<void>;
  failReadsAfterChange?: boolean;
} = {}) {
  let keys = (options.keys ?? [formerPrimary, target]).map((key) => ({ ...key }));
  const mutations: string[] = [];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') {
      return json(route, 200, {
        session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
      });
    }
    if (options.failReadsAfterChange && mutations.length && request.method() === 'GET' && path.startsWith('/api/keys')) {
      return json(route, 503, { error: 'Key reads temporarily unavailable' });
    }
    if (path === '/api/keys' && request.method() === 'GET') {
      return json(route, 200, { keys: keys.filter((key) => !key.archivedAt) });
    }
    const selected = keys.find((key) => path === `/api/keys/${key.id}`);
    if (selected && request.method() === 'GET') return json(route, 200, { key: selected });
    if (path === `/api/keys/${target.id}/primary` && request.method() === 'POST') {
      mutations.push(target.id);
      await options.beforeChange?.();
      if (options.fail) {
        return json(route, 409, { error: { code: 'CONFLICT', message: 'Another key change is in progress. Try again.' } });
      }
      keys = keys.map((key) => ({ ...key, isPrimary: key.id === target.id }));
      return json(route, 200, {
        changed: true,
        key: keys.find((key) => key.isPrimary),
      });
    }
    return json(route, 404, { error: `unmocked ${request.method()} ${path}` });
  });
  return mutations;
}

const makePrimary = (page: Page) => page.getByRole('button', { name: 'Make primary', exact: true });
const primaryBadge = (page: Page) => page.getByText('Primary', { exact: true });

test.describe('TC-704 primary key settings', () => {
  test('cancel leaves the current owner unchanged and sends no mutation', async ({ page }) => {
    const mutations = await mock(page);
    await page.goto(`/dashboard/keys/${target.id}`);
    let confirmation = '';
    page.once('dialog', async (dialog) => {
      confirmation = dialog.message();
      await dialog.dismiss();
    });
    await makePrimary(page).click();
    await expect(makePrimary(page)).toBeEnabled();
    expect(confirmation).toContain(target.address);
    expect(mutations).toEqual([]);
    await expect(primaryBadge(page)).toHaveCount(0);
    await page.getByRole('link', { name: /Back to Dashboard/ }).click();
    const originalRow = page.locator('div.rounded-xl').filter({ has: page.getByText(formerPrimary.label!, { exact: true }) });
    await expect(originalRow.getByText('Primary', { exact: true })).toBeVisible();
  });

  test('confirm waits for the server, then moves the badge to the selected owner', async ({ page }) => {
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const mutations = await mock(page, { beforeChange: () => pending });
    await page.goto(`/dashboard/keys/${target.id}`);
    page.once('dialog', (dialog) => dialog.accept());
    await makePrimary(page).click();
    await expect(page.getByRole('button', { name: 'Making primary...' })).toBeDisabled();
    await expect(primaryBadge(page)).toHaveCount(0);
    release();
    await expect(primaryBadge(page)).toBeVisible();
    await expect(makePrimary(page)).toHaveCount(0);
    expect(mutations).toEqual([target.id]);

    await page.getByRole('link', { name: /Back to Dashboard/ }).click();
    const targetRow = page.locator('div.rounded-xl').filter({ has: page.getByText(target.label!, { exact: true }) });
    const originalRow = page.locator('div.rounded-xl').filter({ has: page.getByText(formerPrimary.label!, { exact: true }) });
    await expect(targetRow.getByText('Primary', { exact: true })).toBeVisible();
    await expect(originalRow.getByText('Primary', { exact: true })).toHaveCount(0);
  });

  test('a committed switch stays successful when subsequent key GETs fail', async ({ page }) => {
    const mutations = await mock(page, { failReadsAfterChange: true });
    await page.goto(`/dashboard/keys/${target.id}`);
    page.once('dialog', (dialog) => dialog.accept());
    await makePrimary(page).click();
    await expect(primaryBadge(page)).toBeVisible();
    await expect(makePrimary(page)).toHaveCount(0);
    await expect(page.getByRole('alert')).toHaveCount(0);
    expect(mutations).toEqual([target.id]);
    // The read outage is real, but cannot undo or misreport the committed POST.
    expect(await page.evaluate(async (id) => (await fetch(`/api/keys/${id}`)).status, target.id)).toBe(503);
    await expect(primaryBadge(page)).toBeVisible();
  });

  test('another key can become primary when the old primary is archived', async ({ page }) => {
    const mutations = await mock(page, { keys: [{ ...formerPrimary, archivedAt: '2026-10-03T00:00:00.000Z' }, target] });
    await page.goto(`/dashboard/keys/${target.id}`);
    page.once('dialog', (dialog) => dialog.accept());
    await makePrimary(page).click();
    await expect(primaryBadge(page)).toBeVisible();
    expect(mutations).toEqual([target.id]);
  });

  for (const [name, key] of [
    ['already primary', { ...target, isPrimary: true }],
    ['external', { ...target, keyType: 'EXTERNAL' }],
    ['archived', { ...target, archivedAt: '2026-10-03T00:00:00.000Z' }],
  ] satisfies Array<[string, EthereumKey]>) {
    test(`${name} keys offer no primary mutation`, async ({ page }) => {
      const mutations = await mock(page, { keys: [key] });
      await page.goto(`/dashboard/keys/${key.id}`);
      await expect(page.getByRole('heading', { name: key.label!, exact: true })).toBeVisible();
      await expect(makePrimary(page)).toHaveCount(0);
      expect(mutations).toEqual([]);
    });
  }

  test('a rejected change shows feedback without changing primary state', async ({ page }) => {
    const mutations = await mock(page, { fail: true });
    await page.goto(`/dashboard/keys/${target.id}`);
    page.once('dialog', (dialog) => dialog.accept());
    await makePrimary(page).click();
    await expect(page.getByRole('alert')).toContainText('Another key change is in progress');
    await expect(makePrimary(page)).toBeEnabled();
    await expect(primaryBadge(page)).toHaveCount(0);
    expect(mutations).toEqual([target.id]);
  });
});
