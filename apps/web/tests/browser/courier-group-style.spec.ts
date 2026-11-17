import { test, expect } from '@playwright/test';
import { parseCapabilityReview, defaultSelection } from '../../../../packages/capability-review/src/index';
import { courierContext } from '../../../../packages/capability-review/test/fixtures/courier';

// The Courier group uses the same heading and Sensitive marker as the other permission lists.
test('Courier group heading and Sensitive marker use the standard styles', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const model = parseCapabilityReview(courierContext());
  await page.addInitScript(({ model, selection }) => {
    (window as any).__openkeyParityHarness = { model, initialSelection: selection, surface: 'cli', calls: [] };
  }, { model, selection: [...defaultSelection(model)] });
  await page.goto('/__parity_harness');
  const group = page.locator('.summary [role="group"]');
  await expect(group).toHaveCount(1);
  const heading = group.locator('h3');
  await expect(heading).toHaveClass(/permissions-heading/);
  expect(await heading.evaluate((el) => getComputedStyle(el).fontSize)).toBe('15px');
  await expect(group.locator('.summary-sensitive-pill')).toHaveCount(5);
  await expect(group.locator('.summary-statement')).toHaveCount(9);
});
