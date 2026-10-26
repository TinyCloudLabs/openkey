import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { render, summarize } from './web-browser-summary.mjs';

const script = fileURLToPath(new URL('./web-browser-summary.mjs', import.meta.url));

// Playwright's JSON report: suites hold specs; each spec holds one test per project, with a status
// of expected, unexpected, flaky or skipped, and the result of every attempt.
const spec = (file, line, title, status, results, project = 'chromium') => ({
  file, line, title, tests: [{ projectName: project, status, results }],
});
const passed = [{ status: 'passed' }];
const failedTwice = [{ status: 'failed', error: { message: 'Error: expect(locator).toBeVisible() failed\nLocator: x' } }, { status: 'failed', error: { message: 'again' } }];
const failedThenPassed = [{ status: 'failed', error: { message: 'Expected: 1\nReceived: 0' } }, { status: 'passed' }];
const ok = (file, line, title, project) => spec(file, line, title, 'expected', passed, project);

/** A whole report: its stats are counted from the specs, unless `stats` overrides them. */
function report(specs, extra = {}) {
  const stats = { expected: 0, unexpected: 0, flaky: 0, skipped: 0, duration: 61000 };
  for (const s of specs) for (const t of s.tests) if (t.status in stats) stats[t.status] += 1;
  return { suites: [{ file: 'x', specs: [], suites: [{ specs }] }], errors: [], stats, ...extra };
}

const known = [{ project: 'chromium', file: 'red.spec.ts', line: 73, title: 'a known red', reason: 'stale spec' }];
const whole = [ok('a.spec.ts', 1, 'one'), ok('b.spec.ts', 2, 'two'), ok('c.spec.ts', 3, 'three', 'webkit')];
const options = (extra = {}) => ({ exitCode: 0, minTests: 3, ...extra });

test('the happy path passes: a whole, green report with exit status 0', () => {
  const result = summarize(report(whole), options({ projects: ['chromium', 'webkit'], specFiles: ['a.spec.ts', 'b.spec.ts', 'c.spec.ts'] }));
  assert.equal(result.failed, false, JSON.stringify(result.problems));
  assert.equal(result.total, 3);
  assert.deepEqual(result.perProject.chromium, { passed: 2, failed: 0, flaky: 0, skipped: 0 });
  assert.match(render(result), /\*\*PASS\*\*: 3 tests/);
});

test('the empty report fails, even with exit status 0 and no errors', () => {
  const result = summarize({ suites: [], errors: [], stats: { expected: 0, unexpected: 0, flaky: 0, skipped: 0 } }, options({ minTests: 1 }));
  assert.equal(result.failed, true);
  assert.ok(result.problems.includes('the report has no tests'));
});

test('an all-skipped report fails: skipped tests are not passes', () => {
  const result = summarize(report([spec('a.spec.ts', 1, 'one', 'skipped', []), spec('b.spec.ts', 2, 'two', 'skipped', [])]), options({ minTests: 2 }));
  assert.equal(result.failed, true);
  assert.equal(result.problems.filter((problem) => /not on the knownSkipped list/.test(problem)).length, 2);
});

test('a skipped test that is on the knownSkipped list is reported and passes', () => {
  const skippedOnPurpose = [{ project: 'chromium', file: 'a.spec.ts', line: 1, title: 'one', reason: 'needs a device' }];
  const result = summarize(report([spec('a.spec.ts', 1, 'one', 'skipped', []), ok('b.spec.ts', 2, 'two')]), options({ minTests: 2, knownSkipped: skippedOnPurpose }));
  assert.equal(result.failed, false, JSON.stringify(result.problems));
  assert.equal(result.knownSkipped.length, 1);
  assert.match(render(result), /Skipped \(listed in knownSkipped\)[\s\S]*needs a device/);
});

test('a partial report fails: fewer tests than its own stats count', () => {
  const partial = report(whole, { stats: { expected: 10, unexpected: 0, flaky: 0, skipped: 0 } });
  const result = summarize(partial, options());
  assert.equal(result.failed, true);
  assert.match(result.problems.join('\n'), /stats disagree with its tests[\s\S]*expected 10 in stats, 3 in tests/);
});

test('a report without stats fails: its tests cannot be checked', () => {
  const result = summarize({ ...report(whole), stats: undefined }, options());
  assert.equal(result.failed, true);
  assert.match(result.problems.join('\n'), /no usable stats/);
});

test('fewer tests than the minimum fails (a spec file that stopped loading)', () => {
  const result = summarize(report(whole), options({ minTests: 150 }));
  assert.equal(result.failed, true);
  assert.match(result.problems.join('\n'), /3 tests, fewer than the minimum of 150/);
});

test('a project with no tests fails, and so does a spec file with none', () => {
  const noWebkit = summarize(report([ok('a.spec.ts', 1, 'one'), ok('b.spec.ts', 2, 'two'), ok('d.spec.ts', 4, 'four')]), options({ projects: ['chromium', 'webkit'] }));
  assert.equal(noWebkit.failed, true);
  assert.match(noWebkit.problems.join('\n'), /project "webkit" has no tests/);
  const noFile = summarize(report(whole), options({ specFiles: ['a.spec.ts', 'lost.spec.ts'] }));
  assert.equal(noFile.failed, true);
  assert.match(noFile.problems.join('\n'), /spec file lost\.spec\.ts has no tests in the report/);
});

test('an unknown test status or result status fails: it is never read as a pass', () => {
  const unknownTest = summarize(report([...whole, spec('d.spec.ts', 4, 'four', 'fixme', passed)], { stats: { expected: 3, unexpected: 0, flaky: 0, skipped: 0 } }), options({ minTests: 4 }));
  assert.equal(unknownTest.failed, true);
  assert.match(unknownTest.problems.join('\n'), /unknown test status "fixme"/);
  const unknownResult = summarize(report([...whole.slice(0, 2), spec('c.spec.ts', 3, 'three', 'expected', [{ status: 'weird' }], 'webkit')]), options());
  assert.equal(unknownResult.failed, true);
  assert.match(unknownResult.problems.join('\n'), /unknown result status "weird"/);
});

test('an interrupted test, and an expected failure that is not a pass, fail', () => {
  const interrupted = summarize(report([...whole.slice(0, 2), spec('c.spec.ts', 3, 'three', 'unexpected', [{ status: 'interrupted' }], 'webkit')]), options({ exitCode: 1 }));
  assert.equal(interrupted.failed, true);
  assert.match(interrupted.problems.join('\n'), /interrupted/);
  const expectedFailure = summarize(report([...whole.slice(0, 2), spec('c.spec.ts', 3, 'three', 'expected', [{ status: 'failed' }], 'webkit')]), options());
  assert.equal(expectedFailure.failed, true);
  assert.match(expectedFailure.problems.join('\n'), /expected failure is not a pass/);
});

test('a spec file that fails to load is a run-level error and fails the run', () => {
  const result = summarize(report(whole, { errors: [{ message: 'Error: Cannot find module ../src/missing\n  at x' }] }), options());
  assert.equal(result.failed, true);
  assert.deepEqual(result.errors, ['Error: Cannot find module ../src/missing']);
});

test('a nonzero Playwright exit status with a clean report fails; an unrecorded one fails', () => {
  const clean = summarize(report(whole), options({ exitCode: 1 }));
  assert.equal(clean.failed, true);
  assert.match(clean.problems.join('\n'), /exited with status 1, and the report does not explain it/);
  const unrecorded = summarize(report(whole), options({ exitCode: undefined }));
  assert.equal(unrecorded.failed, true);
  assert.match(unrecorded.problems.join('\n'), /exit status was not recorded/);
});

test('a nonzero exit status is explained by known reds alone; exit 0 with a failing test is inconsistent', () => {
  const withKnownRed = report([...whole, spec('red.spec.ts', 80, 'a known red', 'unexpected', failedTwice)]);
  const explained = summarize(withKnownRed, options({ exitCode: 1, minTests: 4, knownReds: known }));
  assert.equal(explained.failed, false, JSON.stringify(explained.problems));
  assert.equal(explained.knownRed.length, 1);
  const inconsistent = summarize(withKnownRed, options({ exitCode: 0, minTests: 4, knownReds: known }));
  assert.equal(inconsistent.failed, true);
  assert.match(inconsistent.problems.join('\n'), /exited with status 0, but the report has failing tests/);
});

test('a failure that is not a known red is a new failure, and fails even beside a known red', () => {
  const result = summarize(report([...whole, spec('red.spec.ts', 80, 'a known red', 'unexpected', failedTwice), spec('b.spec.ts', 9, 'brand new break', 'unexpected', failedTwice)]), options({ exitCode: 1, minTests: 5, knownReds: known }));
  assert.equal(result.failed, true);
  assert.equal(result.newFailures.length, 1);
  assert.equal(result.newFailures[0].failure, 'Error: expect(locator).toBeVisible() failed');
  assert.equal(result.knownRed.length, 1);
});

test('a known red is matched by project, file and title, not by line', () => {
  const base = (s) => summarize(report([...whole, s]), options({ exitCode: 1, minTests: 4, knownReds: known }));
  assert.equal(base(spec('red.spec.ts', 200, 'a known red', 'unexpected', failedTwice)).knownRed.length, 1);
  assert.equal(base(spec('red.spec.ts', 73, 'a known red', 'unexpected', failedTwice, 'webkit')).newFailures.length, 1);
  assert.equal(base(spec('red.spec.ts', 73, 'a known red, reworded', 'unexpected', failedTwice)).newFailures.length, 1);
});

test('a test that failed and passed on its retry is a flake and does not fail the run; a persistent failure always does', () => {
  const flake = summarize(report([...whole, spec('login.spec.ts', 241, 'a flaky one', 'flaky', failedThenPassed)]), options({ minTests: 4 }));
  assert.equal(flake.failed, false, JSON.stringify(flake.problems));
  assert.equal(flake.flaky.length, 1);
  assert.equal(flake.flaky[0].failure, 'Expected: 1');
  assert.match(render(flake), /Flakes \(failed, then passed on retry/);
  const persistent = summarize(report([...whole, spec('login.spec.ts', 241, 'a flaky one', 'unexpected', failedTwice)]), options({ exitCode: 1, minTests: 4 }));
  assert.equal(persistent.failed, true);
  assert.equal(persistent.newFailures.length, 1);
});

test('a listed known red that passes is reported as one that now passes, and does not fail the run', () => {
  const result = summarize(report([...whole, spec('red.spec.ts', 73, 'a known red', 'expected', passed)]), options({ minTests: 4, knownReds: known }));
  assert.equal(result.failed, false, JSON.stringify(result.problems));
  assert.equal(result.knownNowPasses.length, 1);
  assert.match(render(result), /Known red now passes: delete it from the list/);
});

test('a listed entry that matches no test is reported and does not fail the run', () => {
  const result = summarize(report(whole), options({ knownReds: known }));
  assert.equal(result.failed, false, JSON.stringify(result.problems));
  assert.equal(result.unmatchedKnown.length, 1);
  assert.match(render(result), /match no test/);
});

test('the summary lists problems and new failures first, then known reds, flakes and the totals', () => {
  const text = render(summarize(report([
    ...whole,
    spec('b.spec.ts', 9, 'brand new break', 'unexpected', failedTwice),
    spec('red.spec.ts', 73, 'a known red', 'unexpected', failedTwice),
    spec('login.spec.ts', 241, 'a flake', 'flaky', failedThenPassed),
  ]), options({ exitCode: 0, minTests: 6, knownReds: known })));
  const order = ['### Problems with the report', '### New failures', '### Known reds', '### Flakes', '### Totals'].map((heading) => text.indexOf(heading));
  assert.ok(order.every((position) => position >= 0), text);
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.match(text, /\*\*FAIL\*\*: 1 problem\(s\) with the report, 1 new failure\(s\)/);
  assert.match(text, /\| webkit \| 1 \| 0 \| 0 \| 0 \|/);
});

test('the command: exit codes for a green run, a known red, a new failure, a broken report and missing files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'web-browser-summary-'));
  try {
    const specsDir = join(dir, 'specs');
    mkdirSync(specsDir);
    for (const name of ['a.spec.ts', 'b.spec.ts', 'c.spec.ts', 'helper.ts']) writeFileSync(join(specsDir, name), '');
    const listPath = join(dir, 'list.json');
    writeFileSync(listPath, JSON.stringify({ minTests: 3, projects: ['chromium', 'webkit'], knownReds: known, knownSkipped: [] }));
    const run = (reportObject, args = ['--exit-code', '0', '--specs-dir', specsDir], list = listPath) => {
      const reportPath = join(dir, 'report.json');
      writeFileSync(reportPath, JSON.stringify(reportObject));
      return spawnSync(process.execPath, [script, reportPath, list, ...args], { encoding: 'utf8' });
    };
    const green = run(report(whole));
    assert.equal(green.status, 0, green.stdout);
    assert.match(green.stdout, /\*\*PASS\*\*/);
    // Known red: exit status 1 from Playwright, explained by the list.
    const withRed = run(report([...whole, spec('red.spec.ts', 80, 'a known red', 'unexpected', failedTwice)]), ['--exit-code', '1', '--specs-dir', specsDir]);
    assert.equal(withRed.status, 0, withRed.stdout);
    // The same report without an exit status, or with the wrong one, fails.
    assert.equal(run(report(whole), ['--specs-dir', specsDir]).status, 1);
    assert.equal(run(report(whole), ['--exit-code', '1', '--specs-dir', specsDir]).status, 1);
    // A spec file in the directory with no tests in the report fails.
    writeFileSync(join(specsDir, 'lost.spec.ts'), '');
    const lost = run(report(whole));
    assert.equal(lost.status, 1);
    assert.match(lost.stdout, /spec file lost\.spec\.ts has no tests/);
    // A new failure fails; no list file means the known red is a new failure.
    assert.equal(run(report([...whole, spec('b.spec.ts', 9, 'brand new break', 'unexpected', failedTwice)]), ['--exit-code', '1']).status, 1);
    assert.equal(run(report([...whole, spec('red.spec.ts', 80, 'a known red', 'unexpected', failedTwice)]), ['--exit-code', '1'], join(dir, 'missing.json')).status, 1);
    // No report, an unreadable list, an unreadable spec directory.
    const none = spawnSync(process.execPath, [script, join(dir, 'absent.json'), listPath, '--exit-code', '0'], { encoding: 'utf8' });
    assert.equal(none.status, 1);
    assert.match(none.stdout, /no readable Playwright report/);
    writeFileSync(join(dir, 'broken.json'), '{ not json');
    assert.equal(run(report(whole), ['--exit-code', '0'], join(dir, 'broken.json')).status, 1);
    assert.equal(run(report(whole), ['--exit-code', '0', '--specs-dir', join(dir, 'nope')]).status, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
