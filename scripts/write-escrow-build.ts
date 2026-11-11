import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const generated = 'apps/api/src/services/escrow-build.json';
const records: [string, string][] = [];
async function collect(directory: string) {
  for (const entry of await readdir(join(root, directory), { withFileTypes: true })) {
    const name = join(directory, entry.name);
    if (entry.isDirectory()) await collect(name);
    else if (entry.isFile() && name !== generated) records.push([name, createHash('sha256').update(await readFile(join(root, name))).digest('hex')]);
  }
}
await collect('apps/api/src'); await collect('packages/tee/src');
for (const name of ['package.json', 'bun.lock', 'Dockerfile', 'packages/tee/package.json', 'apps/api/package.json', 'packages/tee/tsup.config.ts', 'scripts/write-escrow-build.ts']) {
  records.push([name, createHash('sha256').update(await readFile(join(root, name))).digest('hex')]);
}
records.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
const codeHash = createHash('sha256').update(JSON.stringify(['tinycloud/escrow/source-code', 1, records])).digest('hex');
await writeFile(join(root, generated), JSON.stringify({ codeHash }) + '\n');
