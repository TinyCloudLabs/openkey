#!/usr/bin/env node
// Two decisions for the "Review path" workflow, both read from a git diff and both failing OPEN:
//
//   relevance   Does the change touch what the Review path exercises (the API, the web app, the packages
//               they build from, the image build)? Prints `relevant=true|false` and `reason=...` for
//               $GITHUB_OUTPUT. Only a clean diff that lists files, none of them on a relevant path, skips
//               the heavy steps; a non-pull-request event, a git failure and an empty list all run them.
//   note        The one-line release note for a publish: `touches sign-in/approval: yes|no (PRs ...)`,
//               generated from the diff BASE..HEAD. It says "yes" when the diff cannot be computed or lists
//               no files: a reviewer must never read "no" off a guess.
//
// Environment: EVENT (github.event_name), BASE, HEAD (commits to diff).
// `--stdin` reads NUL-delimited file names from stdin instead of git; the tests use it.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// What a Review path run exercises: the API and web app, everything they build from, the image build, the
// root configuration, and this workflow's own files.
const RELEVANT = [
  /^apps\/(api|web)\//,
  /^packages\//,
  /^scripts\/(review-path\/|generate-prisma\.ts$)/,
  /^Dockerfile$/,
  /^(bun\.lock|bunfig\.toml|package\.json|tsconfig\.json|turbo\.json|prisma\.config\.ts)$/,
  /^\.github\/workflows\/review-path\.yml$/,
  /^\.github\/scripts\/review-path-/,
];

// Code that decides who signs in, what they approve, and what a session or a delegation may do.
// Deliberately wide: a file here that turns out harmless costs a "yes" note, a file missing costs a wrong "no".
const SIGN_IN_APPROVAL = [
  /^apps\/api\/src\/(auth|auth-options|oauth-config|origin-policy|social-providers)\.ts$/,
  /^apps\/api\/src\/middleware\//,
  /^apps\/api\/src\/routes\/(delegate|delegation-codes|approval-requests|native-delegation-consent|device-|oauth-|passkey-proxy|prepared-handoffs|owner-revocation|reviewer-admin|keys)/,
  /^apps\/api\/src\/services\/[^/]*(auth|session|passkey|otp|mcp|reviewer|approval|delegat|consent|oauth|signin|siwe|capabilit)/,
  /^apps\/web\/src\/routes\/(auth|delegate|device|oauth|widget|a)\//,
  /^apps\/web\/src\/lib\/[^/]*(auth|delegate|approval|consent|oauth|device|passkey|sign|capabilit|prepared)/,
  /^packages\/capability-review\//,
  /^packages\/db\/prisma\//,
];

// Tests and prose change no shipped behavior.
const NOT_SHIPPED = [/\.(test|spec)\.[cm]?[jt]s$/, /(^|\/)(__tests__|tests|test)\//, /\.md$/];

export function isRelevantPath(path) {
  return RELEVANT.some((pattern) => pattern.test(path));
}

export function touchesSignInApproval(path) {
  return !NOT_SHIPPED.some((pattern) => pattern.test(path)) && SIGN_IN_APPROVAL.some((pattern) => pattern.test(path));
}

export function decideRelevance(files) {
  if (files.length === 0) return { relevant: true, reason: 'the list of changed files is empty, so the check runs' };
  const first = files.find(isRelevantPath);
  if (first) return { relevant: true, reason: `a relevant path changed: ${first.replaceAll('\n', ' ')}` };
  return { relevant: false, reason: 'no API, web app, package, image build or Review path file changed in this pull request' };
}

/**
 * `commits` is [{ sha, subject, files }] for the commits in BASE..HEAD. The line says "yes" with the PRs
 * (`Merge pull request #123 ...` or a squash subject ending in `(#123)`) of the commits that touch sign-in/approval code, and names a
 * commit with no PR number by its short sha.
 */
export function releaseNote(files, commits) {
  if (files === null || files.length === 0) return 'touches sign-in/approval: yes (the diff could not be read, so assume it does)';
  if (!files.some(touchesSignInApproval)) return 'touches sign-in/approval: no';
  const refs = commits
    .filter((commit) => commit.files.some(touchesSignInApproval))
    .map((commit) => {
      const pr = commit.subject.match(/^Merge pull request #(\d+) /)?.[1] ?? commit.subject.match(/\(#(\d+)\)\s*$/)?.[1];
      return pr ? `#${pr}` : commit.sha.slice(0, 7);
    });
  return `touches sign-in/approval: yes${refs.length ? ` (${[...new Set(refs)].join(', ')})` : ''}`;
}

const git = (...args) => {
  const result = spawnSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 28 });
  return result.status === 0 ? result.stdout : null;
};
const names = (output) => output.split('\0').filter(Boolean);

function changedFiles(base, head) {
  const output = base && head ? git('diff', '--no-renames', '--name-only', '-z', base, head) : null;
  return output === null ? null : names(output);
}

function commitsBetween(base, head) {
  const shas = git('log', '--first-parent', '--format=%H', `${base}..${head}`)?.split('\n').filter(Boolean);
  if (!shas) return [];
  return shas.map((sha) => ({
    sha,
    subject: git('log', '-1', '--format=%s', sha)?.trim() ?? '',
    files: names(git('diff-tree', '-m', '--first-parent', '--no-commit-id', '--no-renames', '--name-only', '-r', '-z', sha) ?? ''),
  }));
}

async function readStdinFiles() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return names(Buffer.concat(chunks).toString('utf8'));
}

async function main() {
  const [command, flag] = process.argv.slice(2);
  const { EVENT, BASE, HEAD } = process.env;
  const stdin = flag === '--stdin';
  if (command === 'relevance') {
    const files = stdin ? await readStdinFiles() : EVENT === 'pull_request' ? changedFiles(BASE, HEAD) : null;
    const decision = files === null
      ? { relevant: true, reason: `event ${EVENT || 'unknown'} or an unreadable diff always runs the check` }
      : decideRelevance(files);
    console.log(`relevant=${decision.relevant}\nreason=${decision.reason}`);
  } else if (command === 'note') {
    const files = stdin ? await readStdinFiles() : changedFiles(BASE, HEAD);
    console.log(releaseNote(files, stdin || !files ? [] : commitsBetween(BASE, HEAD)));
  } else {
    console.error('usage: review-path-scope.mjs relevance|note [--stdin]');
    process.exit(2);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
