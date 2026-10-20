import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

// The API runtime image ships only apps/api/src, so the guard is vendored here
// from packages/capability-review (which the web widgets import). A drifted
// copy would let the widget and the server disagree about what is signable.
test('the API siwe-origin guard is byte-identical to the capability-review source', () => {
  const canonical = readFileSync(new URL('../../../../packages/capability-review/src/siwe-origin.ts', import.meta.url), 'utf8');
  const vendored = readFileSync(new URL('../services/siwe-origin.ts', import.meta.url), 'utf8');
  expect(vendored).toBe(canonical);
});
