import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

// The API runtime image ships only apps/api/src, so the key-resource parser is
// vendored here from packages/capability-review (which the web widgets import).
// The two copies are the same bytes.
test('the API key-resource parser is byte-identical to the capability-review source', () => {
  const canonical = readFileSync(new URL('../../../../packages/capability-review/src/key-resource.ts', import.meta.url), 'utf8');
  const vendored = readFileSync(new URL('../services/key-resource.ts', import.meta.url), 'utf8');
  expect(vendored).toBe(canonical);
});
