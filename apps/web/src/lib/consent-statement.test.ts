// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { displayConsentStatement } from './consent-statement';

const home = mkdtempSync('/var/tmp/tc1783ff-webtest.');
for (const name of ['HOME', 'COURIER_HOME', 'TC_HOME', 'XDG_CONFIG_HOME', 'BUN_INSTALL_CACHE_DIR']) process.env[name] = home;
if (process.env.HOME !== home || !home.startsWith('/var/tmp/tc1783ff-webtest.')) throw new Error('isolated test home required');
afterAll(() => rmSync(home, { recursive: true, force: true }));

test('already escaped failing-URN row is displayed exactly once', () => {
  const primaryText = 'Perform tinycloud.encryption/decrypt on tinycloud.\\u202e';
  expect(displayConsentStatement({ primaryText, literalEscaped: true })).toBe(primaryText);
});

test('unescaped fallback markup is escaped and capped', () => {
  const output = displayConsentStatement({ primaryText: `Perform ${'<script>'.repeat(100)} on tinycloud.kv` });
  expect(output).toContain('\\u003cscript\\u003e');
  expect(output.length).toBeLessThanOrEqual(281);
  expect(output.endsWith('…')).toBe(true);
});

test('worded consent remains legible', () => {
  expect(displayConsentStatement({ primaryText: 'Your account’s key — qa/' })).toBe('Your account’s key — qa/');
});
