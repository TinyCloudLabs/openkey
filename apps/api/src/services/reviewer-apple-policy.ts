import { isDeepStrictEqual } from 'node:util';

export const APPLE_REVIEW_CLIENT_ID = 'ok_e1d13d0b220379f37a553aa0391d28a4';
export const REVIEWER_SEED_REVISION = 1;
export const REVIEWER_SEED_COMMIT = 'faad27f73b8408e6bdc14027e4897579460416fc';
const app = 'xyz.tinycloud.tinychat';

// Pinned Home request (TC-2720); this narrows reviewer users only.
export const REVIEWER_HOME_PERMISSIONS = [
  { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/threads/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/threads`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/home_feed`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/feed/`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.hooks', space: 'applications', path: `sql/${app}/feed/`, actions: ['tinycloud.hooks/subscribe'] },
  { service: 'tinycloud.hooks', space: 'applications', path: `sql/${app}/home_feed`, actions: ['tinycloud.hooks/subscribe'] },
  { service: 'tinycloud.hooks', space: 'applications', path: `sql/${app}/threads`, actions: ['tinycloud.hooks/subscribe'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/canvas`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/connectors`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/connectors/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/details`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/summaries`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/transcripts`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.kv', space: 'applications', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/exo/v1/requests/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/del'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/exo/v1/jobs/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'xyz.tinycloud.sample.healthlog/healthlog', actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'xyz.tinycloud.sample.recipes/recipes', actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
] as const;

export function appleReviewEnabled(): boolean {
  return process.env.APPLE_REVIEW_ENABLED === 'true';
}

export function reviewerHomePermissions(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  const order = (value: unknown) => {
    if (!value || typeof value !== 'object') return JSON.stringify(value) ?? '';
    const entry = value as Record<string, unknown>;
    return JSON.stringify([entry.service, entry.path]);
  };
  const canonical = (entries: unknown[]) => entries.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
    const entry = item as Record<string, unknown>;
    return { ...entry, actions: Array.isArray(entry.actions) ? [...entry.actions].sort() : entry.actions };
  }).sort((a, b) => order(a).localeCompare(order(b)));
  return isDeepStrictEqual(canonical(value), canonical([...REVIEWER_HOME_PERMISSIONS]));
}

export function reviewerSeedPermissions(dryRun: boolean) {
  const databases = ['threads', 'home_feed', 'feed/feed_output_home_tour', 'feed/feed_responses_home_tour', 'connectors'];
  const sql = databases.map(path => ({
    service: 'tinycloud.sql', space: 'applications', path: `${app}/${path}`,
    actions: dryRun ? ['tinycloud.sql/read'] : ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'],
  }));
  if (dryRun) return sql;
  return [...sql,
    { service: 'tinycloud.kv', space: 'applications', path: `${app}/connectors/exo-voice-note/transcript/tinychat-reviewer-seed-r1-voice-note`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
    { service: 'tinycloud.kv', space: 'applications', path: `${app}/connectors/exo-voice-note/transcript-rev/tinychat-reviewer-seed-r1-voice-note/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
  ];
}
