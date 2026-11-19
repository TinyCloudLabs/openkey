// "How long it lasts" lives under Advanced details; the card's face keeps only the one expiry line. Driven
// through the dev-only parity harness, which mounts the production popup adapter, at the phone width.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

test.use({ viewport: { width: 390, height: 844 } });

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
}

const calls = (page: Page) => page.evaluate(() => (window as any).__openkeyParityHarness.calls as Array<{ name: string; args?: unknown }>);
const line = (page: Page) => page.getByTestId('approval-expiry-line');

test('the chooser is not on the card until Advanced details is opened, and picking a time there changes the line', async ({ page }) => {
  await load(page);
  await expect(line(page)).toContainText('7 days');
  await expect(page.getByText('How long it lasts')).toBeHidden();
  await expect(page.getByRole('button', { name: '1 hour', exact: true })).toBeHidden();
  await expect(page.getByLabel('Or type a time')).toBeHidden();

  await page.getByText('Advanced details', { exact: true }).click();
  await expect(page.getByText('How long it lasts')).toBeVisible();
  await page.getByText('How long it lasts').click();
  await expect(page.getByLabel('Or type a time')).toBeVisible();

  await page.getByRole('button', { name: '1 hour', exact: true }).click();
  await expect(line(page)).toContainText('1 hour');
  expect((await calls(page)).filter((c) => c.name === 'expiryChange')).toEqual([{ name: 'expiryChange', args: 3_600_000 }]);
});
