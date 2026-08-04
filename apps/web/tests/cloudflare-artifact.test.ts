// @ts-nocheck -- this production-artifact check runs in Bun, outside the web client tsconfig.
import { describe, expect, test } from 'bun:test';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';

const artifact = join(import.meta.dir, '../.svelte-kit/cloudflare');
const manifest = join(import.meta.dir, '../.svelte-kit/cloudflare-tmp/manifest.js');

async function filesIn(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesIn(path) : [path];
  }));
  return files.flat();
}

describe('Cloudflare Pages artifact', () => {
  test('keeps every page request in the worker host boundary', async () => {
    const routes = JSON.parse(await Bun.file(join(artifact, '_routes.json')).text()) as {
      include: string[];
      exclude: string[];
    };
    const html = await filesIn(artifact);
    const workerManifest = await Bun.file(manifest).text();

    expect(routes.include).toEqual(['/*']);
    expect(routes.exclude).toEqual(['/_app/version.json', '/_app/immutable/*']);
    expect(html.filter((path) => path.endsWith('.html')).map((path) => path.slice(artifact.length)))
      .toEqual(['/404.html']);
    expect(workerManifest).toContain('prerendered_routes: new Set([])');
    expect(workerManifest).not.toContain('managed-accounts-architecture/index.html');
    expect(workerManifest).not.toContain('managed-accounts-project/index.html');
  });
});
