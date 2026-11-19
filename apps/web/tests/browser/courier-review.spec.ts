import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { parseCapabilityReview, defaultSelection } from '../../../../packages/capability-review/src/index';
import { courierContext } from '../../../../packages/capability-review/test/fixtures/courier';

// The production approval adapter renders the producer's eight grant tuples. Details: TC-2905
test('Courier review on a phone preserves exact grants and requester status', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const model = process.env.TC2905_BEFORE ? JSON.parse(readFileSync("/var/tmp/tc-2905-baseline-model.json", "utf8")) : process.env.TC2905_PRODUCER_MODEL ? JSON.parse(readFileSync(process.env.TC2905_PRODUCER_MODEL, "utf8")) : parseCapabilityReview(courierContext());
  await page.addInitScript(({ model, selection }) => {
    (window as any).__openkeyParityHarness = { model, initialSelection: selection, surface: 'cli', calls: [] };
  }, { model, selection: [...defaultSelection(model)] });
  await page.goto('/__parity_harness');
  await expect(page.locator('.summary-statements')).toBeVisible();
  const phase = process.env.TC2905_BEFORE ? 'before' : 'after';
  await page.screenshot({ path: `/var/tmp/tc-2905-${phase}-summary.png` });
  await page.screenshot({ path: `/var/tmp/tc-2905-${phase}-summary-full.png`, fullPage: true });
  if (!process.env.TC2905_BEFORE) {
    await expect(page.getByText('Courier: send and receive messages with other agents', { exact: true }).first()).toBeVisible();
    await expect(page.locator('.summary-statements').getByText('See all your Courier data, including your requests and approvals', { exact: true })).toBeVisible();
    await expect(page.getByText('Delete those saved copies', { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  }
  await page.locator(".advanced-details > summary").click();
  await page.locator('[aria-label="Exact grants"]').scrollIntoViewIfNeeded();
  await page.screenshot({ path: `/var/tmp/tc-2905-${phase}-exact.png` });
  await page.screenshot({ path: `/var/tmp/tc-2905-${phase}-exact-full.png`, fullPage: true });
  if (!process.env.TC2905_BEFORE) {
    expect(await page.locator(".grant-target").count()).toBe(8);
    for (const grant of model.permissions) {
      const target = `${grant.space}/${grant.resourceService}/${grant.path}`;
      await expect(page.locator(".grant-target").and(page.locator(`[title="${target}"]`))).toHaveCount(1);
    }
    await expect(page.locator(".advanced-details")).toContainText("no manifest");
    expect(await page.evaluate(() => (window as any).__openkeyParityHarness.calls)).toEqual([]);
  }
});
