import { readFileSync } from 'node:fs';

const sha = process.argv[2];
if (!sha) throw new Error('Usage: share-web-publication.mjs <requested-sha>');

// Input: gh api --paginate --slurp .../check-runs?filter=all&per_page=100.
const pages = JSON.parse(readFileSync(0, 'utf8'));
if (!Array.isArray(pages) || pages.length === 0 || pages.some((page) =>
  !Array.isArray(page.check_runs) || !Number.isInteger(page.total_count) || page.total_count < 0
)) {
  throw new Error('Incomplete check-run response');
}
const checks = pages.flatMap((page) => page.check_runs);
if (pages.some((page) => checks.length < page.total_count)) {
  throw new Error('Incomplete check-run response');
}

// A completed production attempt decides; previews cannot authorize production.
const attempts = checks.filter((check) =>
  check.app?.id === 85455 && check.name === 'Cloudflare Pages: openkey' &&
  check.head_sha === sha && check.conclusion !== 'cancelled' &&
  !(check.status === 'completed' && /Branch Preview URL/.test(check.output?.summary ?? ''))
);
const ids = new Set();
let newestCompleted;
for (const check of attempts) {
  if (!Number.isSafeInteger(check.id) || check.id <= 0) {
    throw new Error(`Invalid check-run id: ${check.id}`);
  }
  if (ids.has(check.id)) throw new Error(`Duplicate check-run id: ${check.id}`);
  ids.add(check.id);
  // GitHub IDs order creation; a late-finishing older attempt cannot win.
  if (check.status === 'completed') {
    if (!newestCompleted || check.id > newestCompleted.id) newestCompleted = check;
  }
}

const newestId = newestCompleted?.id ?? 0;
for (const check of attempts) {
  if (check.status === 'completed' && check.conclusion !== 'success' && check.id < newestId) {
    console.error(`Superseded check-run id=${check.id} conclusion=${check.conclusion}`);
  }
}

let state = 'unpublished';
if (newestCompleted?.conclusion === 'success') {
  state = 'published';
} else if (newestCompleted && !['skipped', 'neutral'].includes(newestCompleted.conclusion)) {
  state = 'failure';
}
console.log(state);
