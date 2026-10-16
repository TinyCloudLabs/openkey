import readChangesets from '@changesets/read';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const changesetDir = join(process.cwd(), '.changeset');
const ignored = new Set(JSON.parse(readFileSync(join(changesetDir, 'config.json'), 'utf8')).ignore);
const preFile = join(changesetDir, 'pre.json');
const consumed = new Set(existsSync(preFile) ? JSON.parse(readFileSync(preFile, 'utf8')).changesets : []);

for (const { id, releases } of await readChangesets(process.cwd())) {
  if (consumed.has(id)) continue;
  const ignoredPackages = releases.filter(({ name }) => ignored.has(name)).map(({ name }) => name);
  if (ignoredPackages.length > 0 && ignoredPackages.length < releases.length) {
    throw new Error(`Found mixed changeset ${id}: ${ignoredPackages.join(', ')}. Mixed changesets that contain both ignored and not ignored packages are not allowed`);
  }
}
