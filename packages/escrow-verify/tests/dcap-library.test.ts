import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { verify } from '@phala/dcap-qvl';
import type { Collateral } from '@phala/dcap-qvl';

// Public upstream v0.7.0 fixture; historical clock applies to this test only.
const quote = readFileSync(new URL('./fixtures/tdx_quote', import.meta.url));
const collateral = JSON.parse(readFileSync(new URL('./fixtures/tdx_quote_collateral.json', import.meta.url), 'utf8')) as Collateral;
const fixtureTime = 1752552000;

test('pinned DCAP library verifies the upstream Intel-rooted fixture and rejects tampering/expired collateral', () => {
  expect(verify(quote, collateral, fixtureTime).status).toBe('UpToDate');
  const modified = Buffer.from(quote); modified[200] = modified[200]! ^ 1;
  expect(() => verify(modified, collateral, fixtureTime)).toThrow();
  expect(() => verify(quote, collateral, 2000000000)).toThrow();
});
