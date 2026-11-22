#!/usr/bin/env node
// Fails a deploy or publish unless every check in .github/required-checks.json
// passed on the exact commit it ships. Waits while any of them is queued, running
// or not yet created, up to REQUIRE_GREEN_WAIT_SECONDS (default 2400), then fails
// closed. The newest attempt of each check (highest check-run id) decides, so a
// successful re-run supersedes a failure. Only GitHub Actions' check runs count:
// another app can't satisfy a required name.
//
//   GH_TOKEN=… GH_REPO=owner/repo node .github/scripts/require-green.mjs <sha>
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const GITHUB_ACTIONS_APP_ID = 15368;

// pages: output of `gh api --paginate --slurp .../check-runs?filter=all&per_page=100`.
export function decide(pages, sha, names) {
  if (!Array.isArray(pages) || pages.length === 0 || pages.some((page) =>
    !Array.isArray(page?.check_runs) || !Number.isInteger(page.total_count) || page.total_count < 0
  )) {
    throw new Error('incomplete check-run response');
  }
  const checks = pages.flatMap((page) => page.check_runs);
  if (pages.some((page) => checks.length < page.total_count)) throw new Error('incomplete check-run response');

  const rows = names.map((name) => {
    let newest;
    for (const check of checks) {
      if (check.name !== name || check.head_sha !== sha || check.app?.id !== GITHUB_ACTIONS_APP_ID) continue;
      if (!Number.isSafeInteger(check.id) || check.id <= 0) throw new Error(`invalid check-run id for ${name}`);
      if (!newest || check.id > newest.id) newest = check;
    }
    if (!newest) return { name, state: 'pending', detail: 'not started' };
    if (newest.status !== 'completed') return { name, state: 'pending', detail: newest.status, url: newest.html_url };
    return {
      name,
      state: newest.conclusion === 'success' ? 'success' : 'failure',
      detail: newest.conclusion,
      url: newest.html_url,
    };
  });
  const state = rows.some((row) => row.state === 'failure') ? 'failure'
    : rows.some((row) => row.state === 'pending') ? 'pending' : 'success';
  return { state, rows };
}

function fetchPages(repo, sha) {
  const out = execFileSync('gh', ['api', '--paginate', '--slurp', `repos/${repo}/commits/${sha}/check-runs?filter=all&per_page=100`], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out);
}

async function main() {
  const [sha] = process.argv.slice(2);
  const repo = process.env.GH_REPO || process.env.GITHUB_REPOSITORY;
  const { checks: names } = JSON.parse(readFileSync(new URL('../required-checks.json', import.meta.url), 'utf8'));
  if (!/^[0-9a-f]{40}$/.test(sha ?? '') || !repo) throw new Error('usage: GH_REPO=owner/repo require-green.mjs <40-hex sha>');
  if (!Array.isArray(names) || names.length === 0 || names.some((name) => typeof name !== 'string' || !name)) {
    throw new Error('.github/required-checks.json has no check names');
  }
  const waitSeconds = Number(process.env.REQUIRE_GREEN_WAIT_SECONDS ?? 2400);
  const pollSeconds = Number(process.env.REQUIRE_GREEN_POLL_SECONDS ?? 30);
  const deadline = Date.now() + waitSeconds * 1000;
  for (;;) {
    const { state, rows } = decide(fetchPages(repo, sha), sha, names);
    const summary = rows.map((row) => `  ${row.state.padEnd(7)} ${row.name} (${row.detail})${row.url ? ` ${row.url}` : ''}`).join('\n');
    if (state === 'success') {
      console.log(`require-green: every required check passed on ${sha}\n${summary}`);
      return;
    }
    if (state === 'failure') throw new Error(`a required check did not pass on ${sha}\n${summary}`);
    if (Date.now() >= deadline) throw new Error(`required checks still pending on ${sha} after ${waitSeconds}s\n${summary}`);
    console.log(`require-green: waiting ${pollSeconds}s\n${summary}`);
    await new Promise((done) => setTimeout(done, pollSeconds * 1000));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`::error::require-green: ${error.message}`);
    process.exit(1);
  });
}
