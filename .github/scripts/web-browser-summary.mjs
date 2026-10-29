#!/usr/bin/env node
// Reads a Playwright JSON report, Playwright's exit status and the known-red list, prints a markdown
// summary, and exits 1 unless the report is complete and every failure is a known red (TC-2120).
//
//   node web-browser-summary.mjs <playwright-report.json> <known-reds.json> [--exit-code N] [--specs-dir DIR]
//
// The list file is REQUIRED: it carries the completeness floor (`minTests`, `projects`) as well as
// the known reds, so a missing, unreadable or invalid list fails the job, never loosens the checks.
//
// The job FAILS when:
//   - the list file is missing, unreadable or invalid (`minTests` not a positive integer, `projects`
//     not a non-empty array of names, or a known entry without its project, file, title and reason);
//   - the report is missing, unreadable, or has run-level errors (a spec file that fails to load is one);
//   - Playwright's exit status was not recorded, or is anything but 0 or 1 (1 is Playwright's
//     test-failure status; 2, 130, 137 and the rest are crashes, signals and CLI errors), or is 1 and
//     the report does not fully explain it (every failing test must be a listed known red, and at
//     least one must fail);
//   - the report has no tests, fewer than `minTests`, a configured project with no tests, or a spec
//     file anywhere under --specs-dir (nested ones included, compared by relative path) with no tests;
//   - the counts in `stats` disagree with the tests in the report (a partial report);
//   - a test has a status or result status this script does not know, was interrupted, or is an
//     expected failure;
//   - a test is skipped and not on the `knownSkipped` list;
//   - a test fails and is not a listed known red.
// A test that failed and then passed on its retry is a flake: reported, never a failure. Its results
// must show it (an earlier failed or timed-out attempt, and a final passed one), or the report fails.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const TEST_STATUSES = new Set(['expected', 'unexpected', 'flaky', 'skipped']);
const RESULT_STATUSES = new Set(['passed', 'failed', 'timedOut', 'skipped', 'interrupted']);

const firstLine = (text) => String(text ?? '').replace(/\x1b\[[0-9;]*m/g, '').split('\n').find((line) => line.trim()) ?? '';
const testKey = (project, file, title) => `${project}\u0000${file}\u0000${title}`;
const normalizePath = (path) => String(path).replace(/\\/g, '/').replace(/^\.\//, '');
const keyed = (entries) => new Map(entries.map((entry) => [testKey(entry.project, entry.file, entry.title), entry]));

function* tests(suite) {
  for (const child of suite.suites ?? []) yield* tests(child);
  for (const spec of suite.specs ?? []) {
    for (const test of spec.tests ?? []) {
      yield { project: test.projectName ?? 'default', file: spec.file, line: spec.line, title: spec.title, status: test.status, results: test.results ?? [] };
    }
  }
}

/**
 * The classification of every test in a report.
 * options: knownReds, knownSkipped (entries { project, file, title, reason }), minTests, projects
 * (names that must each have a test), specFiles (file names that must each have a test), exitCode.
 */
export function summarize(report, options = {}) {
  const { knownReds = [], knownSkipped = [], minTests = 1, projects = [], specFiles = [], exitCode } = options;
  const known = keyed(knownReds);
  const skippable = keyed(knownSkipped);
  const seen = new Set();
  const out = {
    newFailures: [], knownRed: [], flaky: [], knownNowPasses: [], unmatchedKnown: [], knownSkipped: [],
    problems: [], errors: [], skipped: 0, total: 0, perProject: {}, stats: report.stats ?? {},
  };
  for (const error of report.errors ?? []) out.errors.push(firstLine(error.message ?? error));

  const walked = { expected: 0, unexpected: 0, flaky: 0, skipped: 0 };
  const files = new Set();
  const seenProjects = new Set();
  for (const suite of report.suites ?? []) {
    for (const test of tests(suite)) {
      out.total += 1;
      files.add(normalizePath(test.file));
      seenProjects.add(test.project);
      const key = testKey(test.project, test.file, test.title);
      const counts = (out.perProject[test.project] ??= { passed: 0, failed: 0, flaky: 0, skipped: 0 });
      const entry = known.get(key);
      if (entry) seen.add(key);
      const failure = firstLine(test.results.find((result) => result.error)?.error?.message);
      const row = { project: test.project, file: test.file, line: test.line, title: test.title, failure };
      const label = `\`[${test.project}] ${test.file}:${test.line}\` ${test.title}`;

      for (const result of test.results) {
        if (!RESULT_STATUSES.has(result.status)) out.problems.push(`${label}: unknown result status "${result.status}"`);
        else if (result.status === 'interrupted') out.problems.push(`${label}: the run was interrupted`);
      }
      if (!TEST_STATUSES.has(test.status)) {
        out.problems.push(`${label}: unknown test status "${test.status}"`);
        continue;
      }
      walked[test.status] += 1;
      if (test.status === 'unexpected') {
        counts.failed += 1;
        (entry ? out.knownRed : out.newFailures).push(entry ? { ...row, reason: entry.reason } : row);
      } else if (test.status === 'flaky') {
        const attempts = test.results.map((result) => result.status);
        const eventualPass = attempts.length >= 2 && attempts[attempts.length - 1] === 'passed'
          && attempts.slice(0, -1).some((status) => status === 'failed' || status === 'timedOut');
        if (!eventualPass) {
          out.problems.push(`${label}: reported as flaky, but its attempts are [${attempts.join(', ')}], not a failure followed by a pass`);
        } else {
          counts.flaky += 1;
          out.flaky.push(row);
        }
      } else if (test.status === 'skipped') {
        counts.skipped += 1;
        out.skipped += 1;
        const allowed = skippable.get(key);
        if (allowed) out.knownSkipped.push({ ...row, reason: allowed.reason });
        else out.problems.push(`${label}: skipped, and not on the knownSkipped list`);
      } else {
        const last = test.results[test.results.length - 1];
        if (last?.status !== 'passed') {
          out.problems.push(`${label}: counted as expected but its last result is "${last?.status ?? 'missing'}" (an expected failure is not a pass)`);
        } else {
          counts.passed += 1;
          if (entry) out.knownNowPasses.push(row);
        }
      }
    }
  }
  for (const [key, entry] of known) if (!seen.has(key)) out.unmatchedKnown.push(entry);

  // The report must be whole: tests present, as many as expected, and as many as its own stats say.
  if (out.total === 0) out.problems.push('the report has no tests');
  else if (out.total < minTests) out.problems.push(`the report has ${out.total} tests, fewer than the minimum of ${minTests} (a spec file may not have loaded)`);
  const stats = report.stats;
  if (!stats || ['expected', 'unexpected', 'flaky', 'skipped'].some((name) => !Number.isInteger(stats[name]))) {
    out.problems.push('the report has no usable stats to check its tests against');
  } else {
    const mismatched = Object.keys(walked).filter((name) => walked[name] !== stats[name]);
    if (mismatched.length > 0) {
      out.problems.push(`the report's stats disagree with its tests (a partial report?): ${mismatched.map((name) => `${name} ${stats[name]} in stats, ${walked[name]} in tests`).join('; ')}`);
    }
  }
  for (const project of projects) {
    if (!seenProjects.has(project)) out.problems.push(`project "${project}" has no tests in the report`);
  }
  for (const file of specFiles.map(normalizePath)) {
    if (!files.has(file)) out.problems.push(`spec file ${file} has no tests in the report (did it fail to load?)`);
  }

  // Playwright's exit status must be recorded. 0 is a pass and 1 is its documented test-failure
  // status; anything else (2, 130, 137, ...) is a crash, a signal or a CLI error that no test explains.
  if (!Number.isInteger(exitCode)) {
    out.problems.push("Playwright's exit status was not recorded");
  } else if (exitCode !== 0 && exitCode !== 1) {
    out.problems.push(`Playwright exited with status ${exitCode}, which is not a test-failure status (0 or 1)`);
  } else if (exitCode === 1) {
    const failing = out.newFailures.length + out.knownRed.length;
    if (failing === 0 || out.newFailures.length > 0 || out.errors.length > 0) {
      out.problems.push(`Playwright exited with status 1, and the report does not explain it by known reds alone`);
    }
  } else if (out.newFailures.length + out.knownRed.length > 0) {
    out.problems.push('Playwright exited with status 0, but the report has failing tests');
  }

  out.failed = out.problems.length > 0 || out.newFailures.length > 0 || out.errors.length > 0;
  return out;
}

const where = (row) => `\`[${row.project}] ${row.file}:${row.line}\` ${row.title}`;

export function render(result) {
  const lines = [];
  const reasons = [];
  if (result.problems.length) reasons.push(`${result.problems.length} problem(s) with the report`);
  if (result.errors.length) reasons.push(`${result.errors.length} run-level error(s)`);
  if (result.newFailures.length) reasons.push(`${result.newFailures.length} new failure(s)`);
  lines.push('## Web browser specs', '', result.failed
    ? `**FAIL**: ${reasons.join(', ')}`
    : `**PASS**: ${result.total} tests, no failure outside the known-red list (${result.knownRed.length} known red, ${result.flaky.length} flaky)`, '');
  if (result.problems.length) {
    lines.push('### Problems with the report (the run cannot be trusted)', ...result.problems.map((problem) => `- ${problem}`), '');
  }
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
  if (result.knownSkipped.length) {
    lines.push('### Skipped (listed in knownSkipped)', ...result.knownSkipped.map((row) => `- ${where(row)}${row.reason ? `: ${row.reason}` : ''}`), '');
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
  if (typeof result.stats?.duration === 'number') lines.push('', `Run time ${(result.stats.duration / 1000).toFixed(0)} s.`);
  return `${lines.join('\n')}\n`;
}

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

const isText = (value) => typeof value === 'string' && value.trim() !== '';

/**
 * The reason a list file is not usable as policy, or null. An entry in knownReds or knownSkipped
 * must name its test (project, file, title) and carry its diagnosis (`reason`): an entry without
 * one would excuse a failing or skipped test with no explanation.
 */
export function policyProblem(list) {
  if (list === null || typeof list !== 'object' || Array.isArray(list)) return 'it is not a JSON object';
  if (!Number.isInteger(list.minTests) || list.minTests < 1) return '`minTests` must be a positive integer';
  if (!Array.isArray(list.projects) || list.projects.length === 0 || !list.projects.every(isText)) {
    return '`projects` must be a non-empty array of project names';
  }
  for (const name of ['knownReds', 'knownSkipped']) {
    const entries = list[name];
    if (entries === undefined) continue;
    if (!Array.isArray(entries)) return `\`${name}\` must be an array`;
    for (const [index, entry] of entries.entries()) {
      const at = `\`${name}[${index}]\``;
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return `${at} must be an object`;
      for (const field of ['project', 'file', 'title', 'reason']) {
        if (!isText(entry[field])) return `${at} needs a non-empty \`${field}\` (an entry names its test and carries its diagnosis)`;
      }
      if (entry.line !== undefined && !(Number.isInteger(entry.line) && entry.line >= 1)) return `${at}.line must be a positive integer when present`;
    }
  }
  return null;
}

/** Every *.spec.ts under a directory, as paths relative to it with forward slashes. */
export function specFilesUnder(directory, prefix = '') {
  return readdirSync(join(directory, prefix)).sort().flatMap((name) => {
    if (name === 'node_modules' || name === 'test-results') return [];
    const relative = prefix ? `${prefix}/${name}` : name;
    return statSync(join(directory, relative)).isDirectory() ? specFilesUnder(directory, relative) : name.endsWith('.spec.ts') ? [relative] : [];
  });
}

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--exit-code' || argv[i] === '--specs-dir') flags[argv[i]] = argv[++i];
    else positional.push(argv[i]);
  }
  return { positional, flags };
}

const fail = (message) => {
  process.stdout.write(`## Web browser specs\n\n**FAIL**: ${message}\n`);
  return 1;
};

function main(argv) {
  const { positional: [reportPath, listPath], flags } = parseArgs(argv);
  if (!reportPath || !listPath) {
    console.error('usage: web-browser-summary.mjs <playwright-report.json> <known-reds.json> [--exit-code N] [--specs-dir DIR]');
    return 2;
  }
  // The list carries the completeness floor, so any problem with it, a missing file included, fails.
  let list;
  try {
    list = readJson(listPath);
  } catch (error) {
    return fail(`the known-red list cannot be read (${error.code ?? error.name}), so the completeness checks cannot run.`);
  }
  const problem = policyProblem(list);
  if (problem) return fail(`the known-red list is invalid: ${problem}.`);

  let report;
  try {
    report = readJson(reportPath);
  } catch (error) {
    return fail(`no readable Playwright report (${error.code ?? error.name}), so nothing was checked.`);
  }
  let specFiles = [];
  if (flags['--specs-dir']) {
    try {
      specFiles = specFilesUnder(flags['--specs-dir']);
    } catch (error) {
      return fail(`the spec directory cannot be read (${error.code ?? error.name}).`);
    }
  }
  // The status is parsed strictly: canonical non-negative decimal digits only. An empty or absent
  // value is an unrecorded status (a problem in the report); anything else that is not a status
  // (`1.0`, `01`, `0x1`, ` `, `+1`, `1e0`, `-1`) is refused here, by name.
  const rawExit = flags['--exit-code'];
  if (rawExit !== undefined && rawExit !== '' && !/^(0|[1-9][0-9]*)$/.test(rawExit)) {
    return fail(`--exit-code must be a non-negative integer in plain decimal digits, got ${JSON.stringify(rawExit)}.`);
  }
  const exitCode = rawExit === undefined || rawExit === '' ? undefined : Number(rawExit);
  const result = summarize(report, {
    knownReds: list.knownReds ?? [],
    knownSkipped: list.knownSkipped ?? [],
    minTests: list.minTests,
    projects: list.projects,
    specFiles,
    exitCode,
  });
  process.stdout.write(render(result));
  return result.failed ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exit(main(process.argv.slice(2)));
