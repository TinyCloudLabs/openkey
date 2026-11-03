import { expect, test } from 'bun:test';
interface AuthFlowModule { normalizeAuthReturnTo(value: string, origin: string): string | null }
// Execute the real frontend helper without importing frontend sources into the API typecheck root.
const { normalizeAuthReturnTo }: AuthFlowModule = await import(new URL('../../../web/src/lib/auth-flow.ts', import.meta.url).href);

test('sign-in returns to consent only for the exact token-free relative path', () => {
  expect(normalizeAuthReturnTo('/org-registration/consent', 'https://openkey.so')).toBe('/org-registration/consent');
  for (const value of [
    '/org-registration/consent?x', '/org-registration/consent#x',
    '//evil/org-registration/consent', 'https://evil/org-registration/consent',
    'https://openkey.so/org-registration/consent',
  ]) expect(normalizeAuthReturnTo(value, 'https://openkey.so')).toBeNull();
});
