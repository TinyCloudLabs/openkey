// The popup request from the explorer reads the secrets vault in KV, so the approval screen holds its choice to 7 days:
// no longer preset is offered and a longer typed time is refused. Driven through the dev-only parity harness, which
// mounts the production popup adapter, with the request exactly as it was signed.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

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

async function load(page: Page) {
  const m = model();
  const initialSelection = m.permissions.flatMap((g) => g.actions.filter((a) => a.selected).map((a) => a.id));
  await page.addInitScript((cfg) => {
    (window as any).__openkeyParityHarness = { ...cfg, surface: 'popup', calls: [] };
  }, { model: m, initialSelection, withExpiry: true, canUseAuthorizeSign: true });
  await page.goto('/__parity_harness');
  await page.waitForFunction(() => (window as any).__openkeyParityHarnessReady === true);
  await page.getByText('Advanced details', { exact: true }).click();
  await page.getByText('How long it lasts').click();
}

const calls = (page: Page) => page.evaluate(() => (window as any).__openkeyParityHarness.calls as Array<{ name: string; args?: unknown }>);
const line = (page: Page) => page.getByTestId('approval-expiry-line');

test('the longest preset is 7 days, with no 30 days button', async ({ page }) => {
  await load(page);
  await expect(line(page)).toContainText('7 days');
  await expect(page.getByRole('button', { name: '7 days', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '30 days', exact: true })).toHaveCount(0);
});

test('a typed time past 7 days is refused and the choice does not change', async ({ page }) => {
  await load(page);
  await page.getByLabel('Or type a time').fill('5y');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('alert')).toContainText('up to 7 days');
  await expect(line(page)).toContainText('7 days');
  expect((await calls(page)).filter((c) => c.name === 'expiryChange')).toEqual([]);
});
