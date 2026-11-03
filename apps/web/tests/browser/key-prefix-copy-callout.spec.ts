// TC-2232: a request for keys under `share/` and an app's keys shows plain row text (no literal
// backquotes), and the orange callout counts the rows marked Sensitive. Driven in Chromium through
// the dev-only parity harness, which mounts the production popup adapter. Set TC2232_SHOTS_DIR to
// save a screenshot.

import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from '../../../../packages/capability-review/test/fixtures/index';

const SHOTS = process.env.TC2232_SHOTS_DIR;
const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';

function model() {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource({
        [urn('/share/')]: { [`${E}key.create`]: [{}], [`${E}decrypt`]: [{}] },
        [urn('/apps/xyz.tinycloud.listen/')]: { [`${E}key.create`]: [{}], [`${E}decrypt`]: [{}] },
      }),
    ]),
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'listen.tinycloud.xyz', verifiedOrigin: 'https://listen.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    signer: { label: 'Managed key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
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

test.describe('share/ and app keys request at 390px', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('plain row text, and the callout count equals the Sensitive rows', async ({ page }) => {
    await load(page);
    const rows = page.locator('.summary-statement');
    await expect(rows.filter({ hasText: 'Create keys for files you share' })).toHaveCount(1);
    await expect(page.locator('.summary-statements')).not.toContainText('`');
    const sensitiveRows = await page.locator('.summary-statement[data-severity="sensitive"]').count();
    expect(sensitiveRows).toBe(3);
    await expect(page.locator('.sensitive-callout')).toHaveText('3 permissions reach secrets or decryption');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/390-key-prefix-callout.png`, fullPage: true });
  });
});
