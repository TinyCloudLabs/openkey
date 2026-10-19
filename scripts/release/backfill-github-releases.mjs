#!/usr/bin/env node
// One-off backfill: create GitHub Releases for every package tag created after
// @openkey/sdk@0.7.2 (the last tag that has a Release). Idempotent; tags that
// already have a Release are skipped.
//
//   node scripts/release/backfill-github-releases.mjs --dry-run   # list only
//   node scripts/release/backfill-github-releases.mjs             # create
//
// Run from a full clone with tags (`git fetch --tags`) and `gh` authenticated.
// Only the highest stable @openkey/sdk is marked "latest"; betas are prereleases.
import { createReleases, formatResults, listTagsWithDates, parseTag, pickLatestTag } from './github-releases.mjs';

const SINCE_TAG = '@openkey/sdk@0.7.2';
const dryRun = process.argv.includes('--dry-run');

const all = listTagsWithDates();
const since = all.find((t) => t.tag === SINCE_TAG);
if (!since) throw new Error(`Tag ${SINCE_TAG} not found; run \`git fetch --tags\`.`);

const tags = all.filter((t) => t.time > since.time && parseTag(t.tag)).map((t) => t.tag);
const results = createReleases(tags, { dryRun, latestTag: pickLatestTag(tags) });
console.log(formatResults(results, dryRun));
