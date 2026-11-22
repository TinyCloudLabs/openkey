#!/usr/bin/env bun
// TC-3837: every service in a production compose must name its image by digest. The measured
// compose (compose_hash) covers the compose text, so a tag or a `${VAR}` there lets a registry push
// or an environment value change the code that runs without changing the measurement.
//
//   bun scripts/compose-image-digests.ts <compose.yml>

import { readFile } from 'node:fs/promises';

// [registry/]path[:tag]@sha256:<64 hex>. No `$`, so an unsubstituted variable never passes.
const PINNED_IMAGE = /^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$/;

/** Returns one line per service that does not run an image pinned by digest; empty when all do. */
export function unpinnedImages(composeText: string): string[] {
  const compose: unknown = Bun.YAML.parse(composeText);
  const services = compose && typeof compose === 'object' && 'services' in compose ? compose.services : undefined;
  if (!services || typeof services !== 'object' || Array.isArray(services) || Object.keys(services).length === 0) {
    return ['compose has no services'];
  }
  const problems: string[] = [];
  for (const [name, service] of Object.entries(services)) {
    if (!service || typeof service !== 'object' || Array.isArray(service)) {
      problems.push(`${name}: not a service mapping`);
      continue;
    }
    const image = 'image' in service ? service.image : undefined;
    if ('build' in service) problems.push(`${name}: builds its image in the CVM`);
    if (typeof image !== 'string' || !PINNED_IMAGE.test(image)) {
      problems.push(`${name}: image ${JSON.stringify(image ?? null)} is not pinned by @sha256 digest`);
    }
  }
  return problems;
}

if (import.meta.main) {
  const [path] = process.argv.slice(2);
  if (!path) throw new Error('usage: bun scripts/compose-image-digests.ts <compose.yml>');
  const problems = unpinnedImages(await readFile(path, 'utf8'));
  if (problems.length > 0) {
    for (const problem of problems) console.error(`::error::${path}: ${problem}`);
    process.exit(1);
  }
  console.log(`${path}: every image is pinned by digest`);
}
