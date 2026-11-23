import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// The production compose fixes where account deletion sends its bearer secret: an https origin only,
// with no path and no trailing slash, since the API appends `/api/account-delete/<address>` itself.
test('the production compose pins BILLING_API_URL to an https origin without path or trailing slash', () => {
  const compose = readFileSync(resolve(import.meta.dir, '../docker-compose.prod.yml'), 'utf8');
  const entries = [...compose.matchAll(/^\s*-\s*BILLING_API_URL=(.*?)\s*$/gm)].map((match) => match[1]);
  expect(entries).toHaveLength(1);
  const value = entries[0];
  const url = new URL(value);
  expect(url.protocol).toBe('https:');
  expect(url.username + url.password).toBe('');
  expect(url.search + url.hash).toBe('');
  expect(value).toBe(url.origin);
});
