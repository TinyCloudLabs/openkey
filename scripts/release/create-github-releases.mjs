#!/usr/bin/env node
// Create GitHub Releases for the given package tags (idempotent).
//
//   node scripts/release/create-github-releases.mjs [--dry-run] <tag>...
//   node scripts/release/create-github-releases.mjs [--dry-run] --points-at-head
//
// `--points-at-head` selects every tag on HEAD: the tags `changeset publish`
// just created. Re-running on the same commit retries any Release that failed.
// Needs `gh` authenticated (GH_TOKEN) and the tags present on the remote.
import { execFileSync } from 'node:child_process';
import { createReleases, formatResults } from './github-releases.mjs';

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
let tags = args.filter((a) => !a.startsWith('--'));
if (args.includes('--points-at-head')) {
  tags = execFileSync('git', ['tag', '--points-at', 'HEAD'], { encoding: 'utf8' }).split('\n').filter(Boolean);
}
if (tags.length === 0) {
  console.log('No tags to release.');
} else {
  console.log(formatResults(createReleases(tags, { dryRun }), dryRun));
}
