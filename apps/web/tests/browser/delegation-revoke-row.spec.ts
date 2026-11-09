// TC-2232: the approval screen for an undo request (`tinycloud.delegation/revoke`) reads
// "Remove access you gave" in the existing permission list, not "Unknown action: ...". Driven in
// Chromium through the dev-only parity harness, which mounts the production popup adapter.
// Set TC2232_SHOTS_DIR to save a screenshot.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from '../../../../packages/capability-review/test/fixtures/index';

const SHOTS = process.env.TC2232_SHOTS_DIR;
const SIGNER = FIXTURE_META.address;

function model() {
  const resource = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${SIGNER}:default/delegation`;
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource({ [resource]: { 'tinycloud.delegation/revoke': [{}] } })]),
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'cli.tinycloud.xyz', verifiedOrigin: 'https://cli.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    signer: { label: 'Managed key', address: SIGNER, chainId: FIXTURE_META.chainId, provenance: 'managed' },
  });
}

async function load(page: Page) {
  const m = model();
  const initialSelection = m.permissions.flatMap((g) => g.actions.filter((a) => a.selected).map((a) => a.id));
  await page.addInitScript((cfg) => {
    (window as unknown as Record<string, unknown>).__openkeyParityHarness = { ...cfg, surface: 'popup', calls: [] };
  }, { model: m, initialSelection, withExpiry: true, canUseAuthorizeSign: true });
  await page.goto('/__parity_harness');
  await page.waitForFunction(
    () => (window as unknown as Record<string, unknown>).__openkeyParityHarnessReady === true,
  );
}

test.describe('undo request at 390px', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the revoke row reads "Remove access you gave" and is still marked sensitive', async ({ page }) => {
    await load(page);
    const dialog = page.locator('[role="dialog"]');
    await expect(dialog).toContainText('Remove access you gave');
    await expect(dialog).not.toContainText('Unknown action');
    await expect(dialog).toContainText(/sensitive/i);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/390-revoke-row.png`, fullPage: true });
  });
});
