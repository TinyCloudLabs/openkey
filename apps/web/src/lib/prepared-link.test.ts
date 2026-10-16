// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { expect, test } from 'bun:test';
import { fitsPreparedLinkBudget } from './prepared-link';

test('counts the canonical fragment URL, not the internal navigation marker', () => {
  const fragment = `#tv2=${'A'.repeat(8160)}`;
  const atLimit = new URL('https://openkey.so/delegate?transportVersion=2');
  const overLimit = new URL('https://openkey.dev/delegate?transportVersion=2');
  expect(Buffer.byteLength(`${atLimit.origin}${atLimit.pathname}${fragment}`)).toBe(8192);
  expect(Buffer.byteLength(`${overLimit.origin}${overLimit.pathname}${fragment}`)).toBe(8193);
  expect(fitsPreparedLinkBudget(atLimit, fragment)).toBe(true);
  expect(fitsPreparedLinkBudget(overLimit, fragment)).toBe(false);
});
