#!/usr/bin/env bun

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPrismaClient } from '../packages/db/src/index';
import {
  partitionPreTc488Migrations,
  selectProductionMigrationMode,
  type MigrationRow,
} from './deploy-production-migrations';

const repoRoot = resolve(import.meta.dir, '..');

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Expected an object in production metadata');
  }
  return value as Record<string, unknown>;
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Expected a string in production metadata');
  return value;
}

function command(binary: string, args: string[]): string {
  const result = spawnSync(binary, args, { encoding: 'utf8', timeout: 60_000 });
  // Provider errors can include credentials or compose contents. Never echo them.
  if (result.status !== 0) throw new Error(`${binary} read-only inspection failed`);
  return result.stdout;
}

function phala(path: string): unknown {
  return JSON.parse(command('phala', ['api', path, '--api-version', '2026-05-22', '--json']));
}

function apiService(compose: unknown): Record<string, unknown> {
  return record(record(record(compose).services).api);
}

function environment(service: Record<string, unknown>): Map<string, string> {
  if (!Array.isArray(service.environment)) throw new Error('Expected compose environment list');
  return new Map(service.environment.map((entry: unknown) => {
    const value = text(entry);
    const separator = value.indexOf('=');
    const key = value.slice(0, separator);
    if (separator < 1 || !/^[A-Z][A-Z0-9_]*$/.test(key)) throw new Error('Invalid environment key');
    return [key, value.slice(separator + 1)];
  }));
}

function publicAudience(expression: string | undefined): string | null {
  if (expression === undefined) return null;
  const literal = expression.replace(/^\$\{OAUTH_VALID_AUDIENCES(?::-([^{}]*))?\}/, '$1');
  for (const audience of literal.split(',').filter(Boolean)) {
    const url = new URL(audience);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new Error('Refusing to print a non-public audience expression');
    }
  }
  return expression;
}

async function main() {
  if (!process.env.PHALA_CLOUD_API_KEY || !/^postgres(ql)?:\/\//.test(process.env.DATABASE_URL ?? '')) {
    throw new Error('PHALA_CLOUD_API_KEY and PostgreSQL DATABASE_URL are required');
  }
  const info = record(phala('/cvms/openkey-api'));
  const appId = text(info.app_id);
  const fleet = phala(`/apps/${encodeURIComponent(appId)}/cvms`);
  if (!Array.isArray(fleet)) throw new Error('Expected the complete app CVM array');
  const instances = fleet.map((value: unknown) => {
    const cvm = record(value);
    return { name: cvm.name, vm_uuid: cvm.vm_uuid, app_id: cvm.app_id, status: cvm.status, os: cvm.os };
  });
  console.log(JSON.stringify({ instances }, null, 2));
  if (instances.length !== 1 || instances[0]?.vm_uuid !== info.vm_uuid || info.status !== 'running' || info.in_progress) {
    throw new Error('The single-CVM deployment requires exactly one stable running app instance');
  }
  const os = record(info.os);
  if (os.is_dev !== false || os.name !== process.env.PHALA_OS_IMAGE || os.os_image_hash !== process.env.PHALA_OS_IMAGE_HASH) {
    throw new Error('The serving CVM is not on the pinned production OS');
  }

  const manifest = record(phala(`/cvms/${encodeURIComponent(text(info.vm_uuid))}/compose_file`));
  const composeText = text(manifest.docker_compose_file);
  const live = apiService(Bun.YAML.parse(composeText));
  const candidate = apiService(Bun.YAML.parse(await readFile(resolve(repoRoot, 'docker-compose.prod.yml'), 'utf8')));
  const image = text(live.image);
  // Accept both registries while production moves from Docker Hub to GHCR.
  const repository = /^(skgbafa\/openkey-api|ghcr\.io\/tinycloudlabs\/openkey-api)(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})$/.exec(image)?.[1];
  if (!repository) {
    throw new Error('Unexpected production API image repository');
  }
  const inspection = command('docker', ['buildx', 'imagetools', 'inspect', image]);
  const digest = /^Digest:\s+(sha256:[a-f0-9]{64})\s*$/m.exec(inspection)?.[1];
  if (!digest) throw new Error('Could not resolve the immutable rollback image digest');
  const liveEnvironment = environment(live);
  const candidateEnvironment = environment(candidate);
  const changedEnvironmentKeys = [...new Set([...liveEnvironment.keys(), ...candidateEnvironment.keys()])]
    .filter((key) => liveEnvironment.get(key) !== candidateEnvironment.get(key)).sort();
  const after = record(phala('/cvms/openkey-api'));
  for (const key of ['vm_uuid', 'app_id', 'status', 'compose_hash', 'encrypted_env_hash']) {
    if (info[key] !== after[key]) throw new Error('Production changed during the read-only inventory');
  }
  if (after.in_progress) throw new Error('Production is changing during the read-only inventory');
  console.log(JSON.stringify({
    observed_at: new Date().toISOString(),
    image,
    rollback_image: `${repository}@${digest}`,
    compose_sha256: createHash('sha256').update(composeText).digest('hex'),
    changed_environment_keys: changedEnvironmentKeys,
    live_audience_expression: publicAudience(liveEnvironment.get('OAUTH_VALID_AUDIENCES')),
    candidate_audience_expression: publicAudience(candidateEnvironment.get('OAUTH_VALID_AUDIENCES')),
  }, null, 2));

  const database = createPrismaClient({ connectionString: process.env.DATABASE_URL, log: [] });
  try {
    const metadata = await database.$transaction(async (transaction) => {
      await transaction.$executeRawUnsafe('SET TRANSACTION READ ONLY');
      const migrations = await transaction.$queryRawUnsafe<MigrationRow[]>(
        'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" ORDER BY migration_name',
      );
      const custody = await transaction.$queryRawUnsafe<Array<{ exists: boolean }>>(
        "SELECT to_regclass('public.managed_account') IS NOT NULL AS \"exists\"",
      );
      const migrationDirectories = (await readdir(resolve(repoRoot, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      const mode = selectProductionMigrationMode({ migrations, migrationDirectories, managedAccountTableExists: custody[0]?.exists === true });
      const applied = new Set(migrations.filter((row) => row.finished_at && !row.rolled_back_at).map((row) => row.migration_name));
      const pending = migrationDirectories.filter((name) => !applied.has(name));
      const passkeyProvenanceApplied = applied.has('20261110_0002_passkey_enrolment_provenance');
      const unclassified = passkeyProvenanceApplied
        ? await transaction.$queryRawUnsafe<Array<{ count: number }>>('SELECT count(*)::int AS count FROM "passkey" WHERE "enrolledVia" IS NULL')
        : null;
      return {
        migration_mode: mode,
        pending: mode === 'pre-tc488-additive' ? partitionPreTc488Migrations(pending) : { apply: pending, park: [] },
        passkey_provenance_applied: passkeyProvenanceApplied,
        unclassified_passkeys: unclassified?.[0]?.count ?? null,
      };
    });
    console.log(JSON.stringify(metadata, null, 2));
  } finally {
    await database.$disconnect();
  }
}

if (import.meta.main) {
  main().catch(() => {
    // Do not print database/provider exceptions: they may contain secret values.
    console.error('Read-only production preflight failed; no migrations or deployment were performed.');
    process.exitCode = 1;
  });
}
