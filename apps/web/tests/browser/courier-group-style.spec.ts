import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview, defaultSelection } from '../../../../packages/capability-review/src/index';
import { courierContext } from '../../../../packages/capability-review/test/fixtures/courier';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

// The Courier group uses the same heading, rows and Sensitive marker as the other permission lists,
// with no card of its own inside the summary card.
async function open(page: Page, context: ReturnType<typeof courierContext>) {
  const model = parseCapabilityReview(context);
  await page.addInitScript(({ model, selection }) => {
    (window as any).__openkeyParityHarness = { model, initialSelection: selection, surface: 'cli', calls: [] };
  }, { model, selection: [...defaultSelection(model)] });
  await page.goto('/__parity_harness');
  await expect(page.locator('.summary-statements').first()).toBeVisible();
}

const props = ['fontSize', 'fontWeight', 'color', 'lineHeight', 'padding', 'borderBottom', 'backgroundColor', 'borderRadius'] as const;
const read = (page: Page, selector: string) => page.locator(selector).first().evaluate((el, names) => {
  const style = getComputedStyle(el);
  return Object.fromEntries(names.map((name) => [name, style.getPropertyValue(name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`))]));
}, [...props]);

test('Courier group heading, rows and Sensitive marker use the standard styles', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page, courierContext());
  const group = page.locator('.summary [role="group"]');
  await expect(group).toHaveCount(1);

  // No card of its own: the group wrapper and its heading have no border, background or radius.
  for (const selector of ['.summary [role="group"]', '.summary [role="group"] h3']) {
    expect(await read(page, selector)).toMatchObject({ backgroundColor: 'rgba(0, 0, 0, 0)', borderRadius: '0px' });
    expect(await page.locator(selector).first().evaluate((el) => getComputedStyle(el).borderTopWidth)).toBe('0px');
  }

  // The heading is the screen's standard heading (the one "Exact grants" uses): 15px, bold, ink colour, no margin.
  const heading = group.locator('h3');
  await expect(heading).toHaveClass(/permissions-heading/);
  expect(await heading.evaluate((el) => { const s = getComputedStyle(el); return [s.fontSize, s.fontWeight, s.color, s.marginTop, s.marginBottom]; }))
    .toEqual(['15px', '700', 'rgb(15, 23, 42)', '0px', '0px']);

  await expect(group.locator('.summary-sensitive-pill')).toHaveCount(5);
  await expect(group.locator('.summary-statement')).toHaveCount(9);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);

  // Rows and the Sensitive marker compute to exactly what the rows of a non-Courier request do.
  const courierRow = await read(page, '.summary-statement .statement-primary');
  const courierPill = await read(page, '.summary-sensitive-pill');
  const standard = await page.context().newPage();
  await standard.setViewportSize({ width: 390, height: 844 });
  await open(standard, { ...courierContext(), message: EXPLORER_PERMISSION_POPUP_REQUEST });
  expect(await read(standard, '.summary-statement .statement-primary')).toEqual(courierRow);
  expect(await read(standard, '.summary-sensitive-pill')).toEqual(courierPill);
});
