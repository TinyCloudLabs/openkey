// TC-2272 / TC-2933: the expiry line on the approval screen ("This permission expires in 7 days") and its
// "How long it lasts" fold, driven with real keyboard and touch-sized input in Chromium through the dev-only
// parity harness, which mounts the production popup adapter. Set TC2272_SHOTS_DIR to save screenshots.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

const SHOTS = process.env.TC2272_SHOTS_DIR;

function model() {
  return parseCapabilityReview({
    message: EXPLORER_PERMISSION_POPUP_REQUEST,
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'explorer.tinycloud.xyz', verifiedOrigin: 'https://explorer.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    signer: { label: 'Managed key', address: '0xd559CCd9EB87c530A9a349262669386dE93cf412', chainId: 1, provenance: 'managed' },
  });
}

async function load(page: Page, withExpiry = true) {
  const m = model();
  const initialSelection = m.permissions.flatMap((g) => g.actions.filter((a) => a.selected).map((a) => a.id));
  await page.addInitScript((cfg) => {
    (window as any).__openkeyParityHarness = { ...cfg, surface: 'popup', calls: [] };
  }, { model: m, initialSelection, withExpiry, canUseAuthorizeSign: true });
  await page.goto('/__parity_harness');
  await page.waitForFunction(() => (window as any).__openkeyParityHarnessReady === true);
}

const calls = (page: Page) => page.evaluate(() => (window as any).__openkeyParityHarness.calls as Array<{ name: string; args?: unknown }>);
const line = (page: Page) => page.getByTestId('approval-expiry-line');
const fold = (page: Page) => page.getByText('How long it lasts');
const shot = async (page: Page, name: string) => {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
};
const noSidewaysScroll = (page: Page) =>
  page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);

for (const viewport of [{ name: '390', width: 390, height: 844 }, { name: 'desktop', width: 1280, height: 800 }]) {
  test.describe(`approval expiry at ${viewport.name}px`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } });

    test('shows the requested time, and a preset is chosen with the keyboard alone', async ({ page }) => {
      await load(page);
      await expect(line(page)).toHaveText('This permission expires in 7 days');
      await shot(page, `${viewport.name}-line`);

      await fold(page).focus();
      await page.keyboard.press('Enter');
      await expect(page.getByRole('button', { name: '1 hour' })).toBeVisible();
      expect(await noSidewaysScroll(page)).toBe(true);
      await shot(page, `${viewport.name}-picker`);

      await page.keyboard.press('Tab');
      await page.keyboard.press('Enter'); // 1 hour
      await expect(line(page)).toHaveText('This permission expires in 1 hour');
      expect((await calls(page)).filter((c) => c.name === 'expiryChange')).toEqual([{ name: 'expiryChange', args: 3_600_000 }]);
    });

    test('a typed time is set with Enter, in any case', async ({ page }) => {
      await load(page);
      await fold(page).click();
      await page.getByLabel('Or type a time').fill('90M');
      await page.keyboard.press('Enter');
      await expect(line(page)).toHaveText('This permission expires in 90 minutes');
      expect((await calls(page)).at(-1)).toEqual({ name: 'expiryChange', args: 5_400_000 });
    });

    test('a time that does not parse shows a plain error and changes nothing', async ({ page }) => {
      await load(page);
      await fold(page).click();
      const input = page.getByLabel('Or type a time');
      await input.fill('0d');
      await page.keyboard.press('Enter');
      await expect(page.getByRole('alert')).toHaveText('Enter a time longer than zero.');
      expect(await noSidewaysScroll(page)).toBe(true);
      await shot(page, `${viewport.name}-error`);
      await input.fill('soon');
      await page.keyboard.press('Enter');
      await expect(page.getByRole('alert')).toContainText('Use a number and a unit');
      expect((await calls(page)).filter((c) => c.name === 'expiryChange')).toEqual([]);
      await expect(line(page)).toHaveText('This permission expires in 7 days');
    });

    test('a very long time is allowed and shows the warning', async ({ page }) => {
      await load(page);
      await fold(page).click();
      await page.getByLabel('Or type a time').fill('5y');
      await page.keyboard.press('Enter');
      await expect(line(page)).toHaveText('This permission expires in 5 years');
      await expect(page.getByText("That's a long time. OpenKey can't cancel it early once you approve.")).toBeVisible();
      expect(await noSidewaysScroll(page)).toBe(true);
      await shot(page, `${viewport.name}-warning`);
      expect((await calls(page)).at(-1)).toEqual({ name: 'expiryChange', args: 5 * 365 * 86_400_000 });
    });

    test('controls are big enough to tap', async ({ page }) => {
      await load(page);
      await fold(page).click();
      for (const name of ['1 hour', '24 hours', '7 days', '30 days', 'Set']) {
        const box = await page.getByRole('button', { name, exact: true }).boundingBox();
        expect(box!.height).toBeGreaterThanOrEqual(40);
      }
    });
  });
}

test('the line is absent where the signing path cannot write the choice into the message', async ({ page }) => {
  await load(page, false);
  await expect(page.locator('[role="dialog"]')).toBeVisible();
  await expect(page.locator('.expiry')).toHaveCount(0);
});
