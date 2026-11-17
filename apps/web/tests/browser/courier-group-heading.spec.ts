import { test, expect, type Page } from '@playwright/test';
import { parseCapabilityReview, defaultSelection } from '../../../../packages/capability-review/src/index';
import { courierContext } from '../../../../packages/capability-review/test/fixtures/courier';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

// The Courier group heading is a small label with a divider under it, inside the one summary card.
// Rows and the Sensitive marker use the same styles as the other permission lists.
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

test('Courier group heading is a small label with a divider; rows and Sensitive marker use the standard styles', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page, courierContext());
  const group = page.locator('.summary [role="group"]');
  await expect(group).toHaveCount(1);

  // No card of its own: the group wrapper and its heading have no border, background or radius.
  for (const selector of ['.summary [role="group"]', '.summary [role="group"] h3']) {
    expect(await read(page, selector)).toMatchObject({ backgroundColor: 'rgba(0, 0, 0, 0)', borderRadius: '0px' });
    expect(await page.locator(selector).first().evaluate((el) => getComputedStyle(el).borderTopWidth)).toBe('0px');
  }

  // The heading is a small label inside the card: smaller than the rows it introduces, and divided from
  // them by the same 1px line the rows use.
  const heading = group.locator('h3');
  await expect(heading).toHaveClass(/summary-group-heading/);
  const rowSize = await page.locator('.summary-statement .statement-primary').first().evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
  const label = await heading.evaluate((el) => { const s = getComputedStyle(el); return { size: parseFloat(s.fontSize), weight: s.fontWeight, marginTop: s.marginTop, marginBottom: s.marginBottom, line: [s.borderBottomWidth, s.borderBottomStyle, s.borderBottomColor] }; });
  expect(label.size).toBeLessThan(rowSize);
  expect(label).toMatchObject({ weight: '700', marginTop: '0px', marginBottom: '0px' });
  const rowLine = await page.locator('.summary-statement').first().evaluate((el) => { const s = getComputedStyle(el); return [s.borderBottomWidth, s.borderBottomStyle, s.borderBottomColor]; });
  expect(label.line).toEqual(rowLine);
  expect(rowLine).toEqual(['1px', 'solid', 'rgb(226, 232, 240)']);

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
