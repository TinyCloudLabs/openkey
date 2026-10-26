import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { render, summarize } from './web-browser-summary.mjs';

const script = fileURLToPath(new URL('./web-browser-summary.mjs', import.meta.url));

// Playwright's JSON report: suites hold specs; each spec holds one test per project, with a status
// of expected, unexpected, flaky or skipped.
const spec = (file, line, title, status, results, project = 'chromium') => ({
  file, line, title, tests: [{ projectName: project, status, results }],
});
const passed = [{ status: 'passed' }];
const failedTwice = [{ status: 'failed', error: { message: 'Error: expect(locator).toBeVisible() failed\nLocator: x' } }, { status: 'failed', error: { message: 'again' } }];
const failedThenPassed = [{ status: 'failed', error: { message: 'Expected: 1\nReceived: 0' } }, { status: 'passed' }];

const known = [
  { project: 'chromium', file: 'red.spec.ts', line: 73, title: 'a known red', reason: 'stale spec' },
];

const report = (specs, extra = {}) => ({ suites: [{ file: 'x', specs: [], suites: [{ specs }] }], errors: [], stats: { duration: 61000 }, ...extra });

test('an all-green report passes', () => {
  const result = summarize(report([spec('a.spec.ts', 1, 'ok', 'expected', passed)]), known.slice(0, 0));
  assert.equal(result.failed, false);
  assert.deepEqual(result.perProject.chromium, { passed: 1, failed: 0, flaky: 0, skipped: 0 });
});

test('a failure that is not on the known-red list is a new failure and fails the run', () => {
  const result = summarize(report([spec('b.spec.ts', 9, 'brand new break', 'unexpected', failedTwice)]), known);
  assert.equal(result.failed, true);
  assert.equal(result.newFailures.length, 1);
  assert.equal(result.newFailures[0].failure, 'Error: expect(locator).toBeVisible() failed');
  assert.equal(result.knownRed.length, 0);
});

test('a listed failure is a known red and does not fail the run', () => {
  const result = summarize(report([spec('red.spec.ts', 80, 'a known red', 'unexpected', failedTwice)]), known);
  assert.equal(result.failed, false);
  assert.equal(result.knownRed.length, 1);
  assert.equal(result.knownRed[0].reason, 'stale spec');
  assert.equal(result.newFailures.length, 0);
});

test('a known red is matched by project, file and title, not by line', () => {
  const moved = summarize(report([spec('red.spec.ts', 200, 'a known red', 'unexpected', failedTwice)]), known);
  assert.equal(moved.knownRed.length, 1);
  const otherProject = summarize(report([spec('red.spec.ts', 73, 'a known red', 'unexpected', failedTwice, 'webkit')]), known);
  assert.equal(otherProject.newFailures.length, 1);
  const otherTitle = summarize(report([spec('red.spec.ts', 73, 'a known red, reworded', 'unexpected', failedTwice)]), known);
  assert.equal(otherTitle.newFailures.length, 1);
});

test('a test that failed and passed on its retry is a flake and does not fail the run', () => {
  const result = summarize(report([spec('login.spec.ts', 241, 'a wrong code shows one line', 'flaky', failedThenPassed)]), known);
  assert.equal(result.failed, false);
  assert.equal(result.flaky.length, 1);
  assert.equal(result.flaky[0].failure, 'Expected: 1');
  assert.deepEqual(result.perProject.chromium, { passed: 0, failed: 0, flaky: 1, skipped: 0 });
});

test('a listed test that passes is reported as a known red that now passes', () => {
  const result = summarize(report([spec('red.spec.ts', 73, 'a known red', 'expected', passed)]), known);
  assert.equal(result.failed, false);
  assert.equal(result.knownNowPasses.length, 1);
  assert.match(render(result), /Known red now passes: delete it from the list/);
});

test('a listed entry that matches no test is reported and does not fail the run', () => {
  const result = summarize(report([spec('a.spec.ts', 1, 'ok', 'expected', passed)]), known);
  assert.equal(result.failed, false);
  assert.equal(result.unmatchedKnown.length, 1);
  assert.match(render(result), /match no test/);
});

test('skipped tests are counted and do not fail the run', () => {
  const result = summarize(report([spec('a.spec.ts', 1, 'skipped one', 'skipped', [])]), []);
  assert.equal(result.failed, false);
  assert.equal(result.skipped, 1);
});

test('a run-level error (for example the dev server not starting) fails the run even with every listed test green', () => {
  const result = summarize(report([spec('a.spec.ts', 1, 'ok', 'expected', passed)], { errors: [{ message: 'Error: Timed out waiting 180000ms from config.webServer.' }] }), []);
  assert.equal(result.failed, true);
  assert.deepEqual(result.errors, ['Error: Timed out waiting 180000ms from config.webServer.']);
});

test('the summary lists new failures first, then known reds, flakes and the delete-it notes', () => {
  const text = render(summarize(report([
    spec('b.spec.ts', 9, 'brand new break', 'unexpected', failedTwice),
    spec('red.spec.ts', 73, 'a known red', 'unexpected', failedTwice),
    spec('login.spec.ts', 241, 'a flake', 'flaky', failedThenPassed),
    spec('other.spec.ts', 5, 'ok', 'expected', passed, 'webkit-sign-handshake'),
  ]), known));
  const order = ['### New failures', '### Known reds', '### Flakes', '### Totals'].map((heading) => text.indexOf(heading));
  assert.ok(order.every((position) => position >= 0), text);
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.match(text, /\*\*FAIL\*\*: 1 new failure/);
  assert.match(text, /\| webkit-sign-handshake \| 1 \| 0 \| 0 \| 0 \|/);
});

test('the command exits 1 on a new failure, 0 with only known reds and flakes, and 1 without a report', () => {
  const dir = mkdtempSync(join(tmpdir(), 'web-browser-summary-'));
  try {
    const knownPath = join(dir, 'known.json');
    writeFileSync(knownPath, JSON.stringify({ knownReds: known }));
    const run = (specs, list = knownPath) => {
      const reportPath = join(dir, 'report.json');
      writeFileSync(reportPath, JSON.stringify(report(specs)));
      return spawnSync(process.execPath, [script, reportPath, list], { encoding: 'utf8' });
    };
    assert.equal(run([spec('b.spec.ts', 9, 'brand new break', 'unexpected', failedTwice)]).status, 1);
    const clean = run([spec('red.spec.ts', 73, 'a known red', 'unexpected', failedTwice), spec('login.spec.ts', 241, 'a flake', 'flaky', failedThenPassed)]);
    assert.equal(clean.status, 0, clean.stdout);
    assert.match(clean.stdout, /\*\*PASS\*\*/);
    // With no list file the same known red is a new failure.
    assert.equal(run([spec('red.spec.ts', 73, 'a known red', 'unexpected', failedTwice)], join(dir, 'missing.json')).status, 1);
    const none = spawnSync(process.execPath, [script, join(dir, 'absent.json'), knownPath], { encoding: 'utf8' });
    assert.equal(none.status, 1);
    assert.match(none.stdout, /no readable Playwright report/);
    writeFileSync(join(dir, 'broken.json'), '{ not json');
    const broken = spawnSync(process.execPath, [script, join(dir, 'report.json'), join(dir, 'broken.json')], { encoding: 'utf8' });
    assert.equal(broken.status, 1);
    assert.match(broken.stdout, /known-red list cannot be read/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
