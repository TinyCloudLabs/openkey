import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { privateKeyToAddress } from 'viem/accounts';
import { SealingKeyring, sealingKid } from '@openkey/tee';
import type { ResealKeysConfig } from '../../../../../scripts/reseal-keys';
import type { KeyResealRepository, KeyResealRow } from '../../services/key-reseal';

const TEST_PRIVATE_KEY = `0x${'31'.repeat(32)}` as const;
const TEST_ERROR_CANARY = 'TEST-runner-error-canary';
const TEST_CONTEXT = Buffer.alloc(32, 23).toString('base64url');

export interface RunnerFixture {
  config: ResealKeysConfig & { dryRun: false };
  material: string[];
  recording: { cas: number; seals: number };
  unchanged(): boolean;
  current(): boolean;
  verified(): Promise<boolean>;
}

/** Explicit TEST-only providers and a recording repository; no environment defaults. */
export async function createRunnerFixture(cursorPath: string, fail = false): Promise<RunnerFixture> {
  const material = [TEST_PRIVATE_KEY, TEST_PRIVATE_KEY.slice(2),
    Buffer.from(TEST_PRIVATE_KEY.slice(2), 'hex').toString('base64'),
    TEST_ERROR_CANARY, TEST_CONTEXT, 'TEST-runner-record', 'TEST-runner-user'];
  const providers = new Map([0, 1].map((kid) => [kid, async (path: string) => {
    const bytes = createHash('sha256').update(`TEST ONLY runner/${kid}/${path}`).digest();
    material.push(bytes.toString('hex'), bytes.toString('base64'));
    return bytes;
  }]));
  const keyring = new SealingKeyring({ providers, writeKid: 1 });
  const binding = { recordId: 'TEST-runner-record', sealingContext: `openkey/key/${TEST_CONTEXT}` };
  const row: KeyResealRow = {
    kind: 'ethereum', id: binding.recordId, userId: 'TEST-runner-user', sealingContext: TEST_CONTEXT,
    identity: privateKeyToAddress(TEST_PRIVATE_KEY),
    blob: await new SealingKeyring({ providers }).seal(TEST_PRIVATE_KEY, binding),
  };
  material.push(row.identity, row.blob);
  const original = structuredClone(row);
  const recording = { cas: 0, seals: 0 };
  const seal = keyring.seal.bind(keyring);
  keyring.seal = async (...args: Parameters<typeof seal>) => {
    recording.seals++;
    const blob = await seal(...args);
    material.push(blob);
    return blob;
  };
  const repository: KeyResealRepository = {
    async page(kind, afterId, take) {
      if (fail) throw new Error(material.join('|'));
      return kind === row.kind && (afterId === null || row.id > afterId) && take > 0
        ? [structuredClone(row)] : [];
    },
    async get(kind, id) {
      return kind === row.kind && id === row.id ? structuredClone(row) : null;
    },
    async compareAndSwap(previous, blob) {
      recording.cas++;
      if (JSON.stringify(previous) !== JSON.stringify(row)) return 0;
      row.blob = blob;
      return 1;
    },
    async remaining(kid) { return sealingKid(row.blob) === kid ? 1 : 0; },
  };
  // An untyped operator module must not be able to opt into writes via config.
  const config: ResealKeysConfig & { dryRun: false } = {
    repository, keyring, cursorPath, dryRun: false, pageSize: 1,
  };
  return {
    config, material, recording,
    unchanged: () => JSON.stringify(row) === JSON.stringify(original),
    current: () => sealingKid(row.blob) === 1,
    verified: async () => await keyring.unseal(row.blob, binding) === TEST_PRIVATE_KEY,
  };
}

function assertSafe(value: unknown, fixture: RunnerFixture): void {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (fixture.material.some((item) => text.includes(item))) {
    throw new Error('TEST runner exposed fixture material');
  }
}

if (import.meta.main) {
  const [operation, path] = process.argv.slice(2);
  if (!path) throw new Error('TEST runner requires an explicit path');
  // Module-loading-boundary exception: real runner/config imports stay inside
  // this subprocess, isolated from API suite-wide module replacements.
  const { runResealKeys, resealKeysMain } = await import('../../../../../scripts/reseal-keys');
  const isMain = operation?.startsWith('main-');
  const fixture: RunnerFixture = isMain
    ? (await import(pathToFileURL(path).href)).runnerFixture
    : await createRunnerFixture(path, operation === 'library-failure');
  const logs: string[] = [];
  const methods = ['log', 'error', 'warn', 'debug', 'info', 'trace'] as const;
  const originals = methods.map((method) => console[method]);
  for (const method of methods) {
    console[method] = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); };
  }
  let result: unknown;
  try {
    if (isMain) {
      const args = operation === 'main-apply' ? [path, '--apply']
        : operation === 'main-unknown' ? [path, '--unknown'] : [path];
      result = await resealKeysMain(args);
    } else {
      result = operation === 'library-apply'
        ? await runResealKeys(fixture.config, { apply: true })
        : await runResealKeys(fixture.config);
    }
  } finally {
    for (const [index, method] of methods.entries()) console[method] = originals[index]!;
  }
  assertSafe(result, fixture);
  assertSafe(logs, fixture);
  console.log(JSON.stringify({
    result, logs, cas: fixture.recording.cas, seals: fixture.recording.seals,
    unchanged: fixture.unchanged(), current: fixture.current(), verified: await fixture.verified(),
  }));
}
