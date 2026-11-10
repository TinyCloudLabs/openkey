import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { FileKeyResealCursorStore } from '../apps/api/src/services/key-reseal-cursor';
import { emptyKeyResealCounts, runKeyReseal, type KeyResealCounts, type KeyResealOptions } from '../apps/api/src/services/key-reseal';

export interface ResealKeysConfig extends Omit<KeyResealOptions, 'cursorStore'> {
  /** Absolute path on a durable volume; never a temporary deployment directory. */
  cursorPath: string;
}

/** An explicit keyring and repository are required; no provider or DB defaults. */
export async function runResealKeys(config: ResealKeysConfig): Promise<KeyResealCounts> {
  try {
    const cursorStore = new FileKeyResealCursorStore(config.cursorPath);
    return await runKeyReseal({ ...config, cursorStore });
  } catch {
    return { ...emptyKeyResealCounts(), failed: 1 };
  }
}

/**
 * Usage: bun run scripts/reseal-keys.ts /absolute/path/to/config.ts
 * The operator-selected module exports `resealConfig: ResealKeysConfig`, with
 * its explicitly constructed keyring, repository, and durable cursorPath.
 * No HTTP endpoint, scheduler, environment lookup, or implicit client exists.
 */
export async function resealKeysMain(
  args: readonly string[],
  log: (text: string) => void = console.log,
): Promise<number> {
  let result: KeyResealCounts;
  try {
    if (args.length !== 1 || !args[0]) throw new Error('Maintenance configuration required');
    const module = await import(pathToFileURL(resolve(args[0])).href);
    result = await runResealKeys(module.resealConfig);
  } catch {
    result = { ...emptyKeyResealCounts(), failed: 1 };
  }
  log(JSON.stringify(result));
  return result.failed === 0 ? 0 : 1;
}

if (import.meta.main) process.exitCode = await resealKeysMain(process.argv.slice(2));
