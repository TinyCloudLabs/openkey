import { describe, expect, test } from 'bun:test';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { KeyResealCursor } from '../services/key-reseal-cursor';

const fixturePath = new URL('./fixtures/key-reseal-runner-config.ts', import.meta.url).pathname;
const cliPath = new URL('../../../../scripts/reseal-keys.ts', import.meta.url).pathname;
const numericCounts = {
  scanned: 0, alreadyCurrent: 0, resealed: 0, raced: 0, failed: 0, remainingOldGeneration: 0,
};
const dryRunResult = { ...numericCounts, scanned: 1, remainingOldGeneration: 1, dryRun: true };
const applyResult = { ...numericCounts, scanned: 1, resealed: 1, dryRun: false };
const failureResult = { ...numericCounts, failed: 1, dryRun: true };

interface ScenarioReport {
  result: unknown;
  logs: string[];
  cas: number;
  seals: number;
  unchanged: boolean;
  current: boolean;
  verified: boolean;
}

async function runProcess(args: string[]) {
  // Subprocess isolation is the module-loading boundary: runner imports must
  // not inherit dependency replacements installed by other API test files.
  const child = Bun.spawn([process.execPath, ...args], { stdout: 'pipe', stderr: 'pipe' });
  const [stdout, stderr, exit] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  return { stdout, stderr, exit };
}

async function scenario(operation: string, path: string): Promise<ScenarioReport> {
  const output = await runProcess([fixturePath, operation, path]);
  // Avoid echoing captured output on an unexpected failure: it may be material.
  expect(output.exit === 0).toBe(true);
  expect(output.stderr.length === 0).toBe(true);
  try {
    return JSON.parse(output.stdout);
  } catch {
    throw new Error('TEST runner did not produce a safe scenario report');
  }
}

async function configModule(directory: string, fail = false) {
  const path = join(directory, fail ? 'failure-config.ts' : 'config.ts');
  const cursorPath = join(directory, 'cursor.json');
  await writeFile(path, [
    `import { createRunnerFixture } from ${JSON.stringify(pathToFileURL(fixturePath).href)};`,
    `export const runnerFixture = await createRunnerFixture(${JSON.stringify(cursorPath)}, ${fail});`,
    'export const resealConfig = runnerFixture.config;',
  ].join('\n'));
  return { path, cursorPath };
}

function expectReadOnly(report: ScenarioReport) {
  expect(report.cas).toBe(0);
  expect(report.seals).toBe(0);
  expect(report.unchanged).toBe(true);
  expect(report.current).toBe(false);
  expect(report.verified).toBe(true);
}

async function expectCheckpoint(path: string) {
  const cursor: KeyResealCursor = JSON.parse(await readFile(path, 'utf8'));
  expect(cursor.completed).toBe(true);
  expect(cursor.writeKid).toBe(1);
  expect(cursor.counts).toEqual({ ...numericCounts, scanned: 1, resealed: 1 });
  expect(Object.keys(cursor.counts).sort()).toEqual(Object.keys(numericCounts).sort());
}

describe('re-seal runner explicit apply boundary', () => {
  for (const existingCursor of [false, true]) {
    test(`callable default ignores raw config dryRun:false and leaves ${existingCursor ? 'existing' : 'absent'} cursor untouched`, async () => {
      const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-runner-'));
      try {
        const cursorPath = join(directory, 'cursor.json');
        const sentinel: KeyResealCursor = {
          version: 1, writeKid: 1, kind: 'nostr', afterId: 'TEST-sentinel-after', completed: false,
          counts: { ...numericCounts, scanned: 71, alreadyCurrent: 71 },
        };
        const before = `${JSON.stringify(sentinel, null, 2)}\n`;
        if (existingCursor) await writeFile(cursorPath, before);
        const report = await scenario('library-default', cursorPath);
        expect(report.result).toEqual(dryRunResult);
        expect(report.logs).toEqual([]);
        expectReadOnly(report);
        if (existingCursor) expect(await readFile(cursorPath, 'utf8')).toBe(before);
        expect(await readdir(directory)).toEqual(existingCursor ? ['cursor.json'] : []);
      } finally { await rm(directory, { recursive: true, force: true }); }
    });
  }

  test('callable explicit apply performs a verified record CAS and creates numeric checkpoint counts', async () => {
    const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-runner-'));
    try {
      const cursorPath = join(directory, 'cursor.json');
      const report = await scenario('library-apply', cursorPath);
      expect(report.result).toEqual(applyResult);
      expect(report.logs).toEqual([]);
      expect(report.cas).toBe(1);
      expect(report.seals).toBe(1);
      expect(report.unchanged).toBe(false);
      expect(report.current).toBe(true);
      expect(report.verified).toBe(true);
      await expectCheckpoint(cursorPath);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  test('repository errors containing fixture material return only seven safe fields without console output', async () => {
    const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-runner-'));
    try {
      const report = await scenario('library-failure', join(directory, 'cursor.json'));
      expect(report.result).toEqual(failureResult);
      expect(report.logs).toEqual([]);
      expectReadOnly(report);
      expect(await readdir(directory)).toEqual([]);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  for (const mode of ['default', 'apply', 'failure', 'unknown']) {
    test(`CLI function ${mode} prints exactly safe JSON and returns the expected exit status`, async () => {
      const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-runner-'));
      try {
        const { path, cursorPath } = await configModule(directory, mode === 'failure');
        const report = await scenario(`main-${mode}`, path);
        const failed = mode === 'failure' || mode === 'unknown';
        expect(report.result).toBe(failed ? 1 : 0);
        expect(report.logs).toEqual([JSON.stringify(failed ? failureResult : mode === 'apply' ? applyResult : dryRunResult)]);
        if (mode === 'apply') {
          expect(report.cas).toBe(1);
          expect(report.seals).toBe(1);
          expect(report.current).toBe(true);
          expect(report.unchanged).toBe(false);
          expect(report.verified).toBe(true);
          await expectCheckpoint(cursorPath);
        } else {
          expectReadOnly(report);
          expect(await Bun.file(cursorPath).exists()).toBe(false);
        }
      } finally { await rm(directory, { recursive: true, force: true }); }
    });
  }

  for (const fail of [false, true]) {
    test(`actual CLI process ${fail ? 'fails safely' : 'defaults to read-only with an explicit TEST config'}`, async () => {
      const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-runner-'));
      try {
        const { path, cursorPath } = await configModule(directory, fail);
        const output = await runProcess([cliPath, path]);
        const expected = JSON.stringify(fail ? failureResult : dryRunResult) + '\n';
        expect(output.exit).toBe(fail ? 1 : 0);
        // Boolean comparisons prevent failed assertions from printing material.
        expect(output.stdout === expected).toBe(true);
        expect(output.stderr.length === 0).toBe(true);
        expect(await Bun.file(cursorPath).exists()).toBe(false);
      } finally { await rm(directory, { recursive: true, force: true }); }
    });
  }
});
