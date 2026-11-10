import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { FileKeyResealCursorStore } from '../apps/api/src/services/key-reseal-cursor';
import { emptyKeyResealCounts, runKeyReseal, type KeyResealResult, type KeyResealOptions } from '../apps/api/src/services/key-reseal';

export interface ResealKeysConfig extends Omit<KeyResealOptions, 'cursorStore' | 'dryRun'> {
  /** Absolute path on a durable volume; never a temporary deployment directory. */
  cursorPath: string;
}

/** An explicit keyring and repository are required; writes require explicit opt-in. */
export async function runResealKeys(config: ResealKeysConfig, options: { apply?: boolean } = {}): Promise<KeyResealResult> {
  const dryRun = options.apply !== true;
  try {
    const cursorStore = new FileKeyResealCursorStore(config.cursorPath);
    return await runKeyReseal({ ...config, cursorStore, dryRun });
  } catch {
    return { ...emptyKeyResealCounts(), failed: 1, dryRun };
  }
}

/**
 * Usage: bun run scripts/reseal-keys.ts /absolute/path/to/config.ts [--apply]
 * The operator-selected module exports `resealConfig: ResealKeysConfig`, with
 * its explicitly constructed keyring, repository, and durable cursorPath.
 * No HTTP endpoint, scheduler, environment lookup, or implicit client exists.
 */
export async function resealKeysMain(
  args: readonly string[],
  log: (text: string) => void = console.log,
): Promise<number> {
  const apply = args.length === 2 && args[1] === '--apply';
  let result: KeyResealResult;
  try {
    if ((args.length !== 1 && !apply) || !args[0] || args[0].startsWith('--')) {
      throw new Error('Maintenance configuration required');
    }
    const module = await import(pathToFileURL(resolve(args[0])).href);
    result = await runResealKeys(module.resealConfig, { apply });
  } catch {
    result = { ...emptyKeyResealCounts(), failed: 1, dryRun: !apply };
  }
  log(JSON.stringify(result));
  return result.failed === 0 ? 0 : 1;
}

if (import.meta.main) process.exitCode = await resealKeysMain(process.argv.slice(2));
