#!/usr/bin/env node
// Reads a Playwright JSON report and the known-red list, prints a markdown summary and exits 1
// only when a failure is NOT on the known-red list (TC-2120).
//
//   node web-browser-summary.mjs <playwright-report.json> [known-reds.json]
//
// A test that fails and is not listed is a NEW failure (job fails). A listed test that fails is a
// known red. A test that failed and passed on its retry is a flake (reported, never fails). A listed
// test that passes is "known red now passes". A report that is missing, unreadable or carries
// run-level errors fails the job: no report means nothing was checked.

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const firstLine = (text) => String(text ?? '').replace(/\x1b\[[0-9;]*m/g, '').split('\n').find((line) => line.trim()) ?? '';
const testKey = (project, file, title) => `${project}\u0000${file}\u0000${title}`;

function* tests(suite) {
  for (const child of suite.suites ?? []) yield* tests(child);
  for (const spec of suite.specs ?? []) {
    for (const test of spec.tests ?? []) {
      yield { project: test.projectName ?? 'default', file: spec.file, line: spec.line, title: spec.title, status: test.status, results: test.results ?? [] };
    }
  }
}

/** The classification of every test in a report against the known reds. */
export function summarize(report, knownReds = []) {
  const known = new Map(knownReds.map((entry) => [testKey(entry.project, entry.file, entry.title), entry]));
  const seen = new Set();
  const out = { newFailures: [], knownRed: [], flaky: [], knownNowPasses: [], unmatchedKnown: [], skipped: 0, perProject: {}, errors: [], stats: report.stats ?? {} };
  for (const error of report.errors ?? []) out.errors.push(firstLine(error.message ?? error));
  for (const suite of report.suites ?? []) {
    for (const test of tests(suite)) {
      const key = testKey(test.project, test.file, test.title);
      const counts = (out.perProject[test.project] ??= { passed: 0, failed: 0, flaky: 0, skipped: 0 });
      const entry = known.get(key);
      if (entry) seen.add(key);
      const failure = firstLine(test.results.find((result) => result.error)?.error?.message);
      const row = { project: test.project, file: test.file, line: test.line, title: test.title, failure };
      if (test.status === 'unexpected') {
        counts.failed += 1;
        (entry ? out.knownRed : out.newFailures).push(entry ? { ...row, reason: entry.reason } : row);
      } else if (test.status === 'flaky') {
        counts.flaky += 1;
        out.flaky.push(row);
      } else if (test.status === 'skipped') {
        counts.skipped += 1;
        out.skipped += 1;
      } else {
        counts.passed += 1;
        if (entry) out.knownNowPasses.push(row);
      }
    }
  }
  for (const [key, entry] of known) if (!seen.has(key)) out.unmatchedKnown.push(entry);
  out.failed = out.newFailures.length > 0 || out.errors.length > 0;
  return out;
}

const where = (row) => `\`[${row.project}] ${row.file}:${row.line}\` ${row.title}`;

export function render(result) {
  const lines = [];
  const headline = result.failed
    ? `**FAIL**: ${result.newFailures.length} new failure(s)${result.errors.length ? `, ${result.errors.length} run-level error(s)` : ''}`
    : `**PASS**: no failure outside the known-red list (${result.knownRed.length} known red, ${result.flaky.length} flaky)`;
  lines.push('## Web browser specs', '', headline, '');
  if (result.errors.length) {
    lines.push('### Run-level errors (nothing may have run)', ...result.errors.map((error) => `- ${error}`), '');
  }
  if (result.newFailures.length) {
    lines.push('### New failures (not in the known-red list)', ...result.newFailures.map((row) => `- ${where(row)}${row.failure ? `: ${row.failure}` : ''}`), '');
  }
  if (result.knownRed.length) {
    lines.push('### Known reds (still failing; listed in .github/web-browser-known-reds.json)', ...result.knownRed.map((row) => `- ${where(row)}${row.reason ? `: ${row.reason}` : ''}`), '');
  }
  if (result.flaky.length) {
    lines.push('### Flakes (failed, then passed on retry; they do not fail the job)', ...result.flaky.map((row) => `- ${where(row)}${row.failure ? `: ${row.failure}` : ''}`), '');
  }
  if (result.knownNowPasses.length) {
    lines.push('### Known red now passes: delete it from the list', ...result.knownNowPasses.map((row) => `- ${where(row)}`), '');
  }
  if (result.unmatchedKnown.length) {
    lines.push('### Known-red entries that match no test: delete or update them', ...result.unmatchedKnown.map((entry) => `- \`[${entry.project}] ${entry.file}\` ${entry.title}`), '');
  }
  lines.push('### Totals', '', '| Project | Passed | Failed | Flaky | Skipped |', '| --- | --- | --- | --- | --- |');
  for (const [project, counts] of Object.entries(result.perProject)) {
    lines.push(`| ${project} | ${counts.passed} | ${counts.failed} | ${counts.flaky} | ${counts.skipped} |`);
  }
  if (typeof result.stats.duration === 'number') lines.push('', `Run time ${(result.stats.duration / 1000).toFixed(0)} s.`);
  return `${lines.join('\n')}\n`;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function main(argv) {
  const [reportPath, knownPath] = argv;
  if (!reportPath) {
    console.error('usage: web-browser-summary.mjs <playwright-report.json> [known-reds.json]');
    return 2;
  }
  let report;
  try {
    report = readJson(reportPath);
  } catch (error) {
    process.stdout.write(`## Web browser specs\n\n**FAIL**: no readable Playwright report (${error.code ?? error.name}), so nothing was checked.\n`);
    return 1;
  }
  let knownReds = [];
  if (knownPath) {
    try {
      knownReds = readJson(knownPath).knownReds ?? [];
    } catch (error) {
      // A missing list is an empty list; an unreadable one must not hide a failure.
      if (error.code !== 'ENOENT') {
        process.stdout.write(`## Web browser specs\n\n**FAIL**: the known-red list cannot be read (${error.name}).\n`);
        return 1;
      }
    }
  }
  const result = summarize(report, knownReds);
  process.stdout.write(render(result));
  return result.failed ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exit(main(process.argv.slice(2)));
