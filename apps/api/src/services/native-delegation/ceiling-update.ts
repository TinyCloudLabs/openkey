import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import {
  NativeDelegationPolicyError,
  nativeDelegationJson,
  validateNativeDelegationConfig,
  type NativeDelegationConfig,
} from './policy';

/**
 * Applies a full native delegation ceiling to an existing client row. Used by
 * scripts/ci-register-oauth-client.ts. The ceiling is validated by the same
 * `validateNativeDelegationConfig` the admin API uses and written as the same
 * whole-value replacement. Entries may be added freely; removing an entry, or
 * reducing a limit, needs `allowNarrow`. Only validated ceiling values are
 * printed.
 */

// The production registration path: never accept loopback TinyCloud hosts,
// whatever NODE_ENV the CI runner has.
const POLICY_OPTIONS = { allowLocalHosts: false } as const;
// Signing domain used when a ceiling carries no siweDomain.
const DEFAULT_SIWE_DOMAIN = 'openkey.so';

export class NativeCeilingRefusedError extends Error {}

export interface CeilingDiff {
  /** List entries present only in the new ceiling, e.g. `kv.paths: <appId>/jobs/`. */
  added: string[];
  /** List entries and limits the new ceiling no longer carries; these need `allowNarrow`. */
  removed: string[];
  /** Limits that are larger in the new ceiling. */
  changed: string[];
}

export interface CeilingUpdateOptions {
  clientId: string;
  /** The ceiling as the JSON text the operator supplied. */
  rawCeiling: string;
  dryRun: boolean;
  allowNarrow: boolean;
  log: (line: string) => void;
}

export type CeilingUpdateOutcome = 'written' | 'dry-run' | 'unchanged';

export interface CeilingUpdateResult {
  outcome: CeilingUpdateOutcome;
  before: NativeDelegationConfig | null;
  after: NativeDelegationConfig;
  diff: CeilingDiff;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, entry]) => [key, sortKeys(entry)]),
    );
  }
  return value;
}

/** Pretty-printed JSON with object keys in sorted order, so printed ceilings diff cleanly. */
export function sortedJson(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 2);
}

function listFields(config: NativeDelegationConfig | null): Record<string, string[]> {
  return {
    'kv.paths': config?.kv.paths ?? [],
    'kv.actions': config?.kv.actions ?? [],
    'sql.databases': config?.sql?.databases ?? [],
    'sql.actions': config?.sql?.actions ?? [],
  };
}

/** What moving from `before` to `after` adds, removes and changes. Lines are sorted. */
export function diffNativeCeilings(before: NativeDelegationConfig | null, after: NativeDelegationConfig): CeilingDiff {
  const diff: CeilingDiff = { added: [], removed: [], changed: [] };
  const previous = listFields(before);
  const next = listFields(after);
  for (const field of Object.keys(next)) {
    for (const entry of next[field]!) {
      if (!previous[field]!.includes(entry)) diff.added.push(`${field}: ${entry}`);
    }
    for (const entry of previous[field]!) {
      if (!next[field]!.includes(entry)) diff.removed.push(`${field}: ${entry}`);
    }
  }
  if (before) {
    const identity: Array<[string, string, string]> = [
      ['appId', before.appId, after.appId],
      ['tinycloudHost', before.tinycloudHost, after.tinycloudHost],
      ['siweDomain', before.siweDomain ?? DEFAULT_SIWE_DOMAIN, after.siweDomain ?? DEFAULT_SIWE_DOMAIN],
    ];
    for (const [field, from, to] of identity) {
      if (from !== to) diff.removed.push(`${field}: ${from} -> ${to}`);
    }
    const limits: Array<[string, number, number]> = [
      ['maxDelegationTtlSeconds', before.maxDelegationTtlSeconds, after.maxDelegationTtlSeconds],
      ['grantLifetimeSeconds', before.grantLifetimeSeconds, after.grantLifetimeSeconds],
    ];
    for (const [field, from, to] of limits) {
      if (to < from) diff.removed.push(`${field}: ${from} -> ${to}`);
      else if (to > from) diff.changed.push(`${field}: ${from} -> ${to}`);
    }
  }
  diff.added.sort();
  diff.removed.sort();
  diff.changed.sort();
  return diff;
}

function parseCeiling(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    throw new NativeCeilingRefusedError('The native delegation ceiling is not valid JSON');
  }
}

export async function updateNativeCeiling(
  db: Pick<PrismaClient, 'oauthClient'>,
  options: CeilingUpdateOptions,
): Promise<CeilingUpdateResult> {
  const { clientId, log } = options;
  const client = await db.oauthClient.findUnique({ where: { clientId } });
  if (!client || client.disabled) throw new Error(`Enabled OAuth client not found: ${clientId}`);
  const gate = {
    type: client.type,
    public: client.public,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    disabled: client.disabled,
  };

  // The same validator as the admin API PATCH; a malformed value never reaches the write.
  const after = validateNativeDelegationConfig(parseCeiling(options.rawCeiling), gate, POLICY_OPTIONS);

  let before: NativeDelegationConfig | null = null;
  let beforeNote = 'none (the client has no ceiling)';
  if (client.tinycloudNativeDelegation != null) {
    try {
      before = validateNativeDelegationConfig(client.tinycloudNativeDelegation, gate, POLICY_OPTIONS);
      beforeNote = sortedJson(before);
    } catch (error) {
      if (!(error instanceof NativeDelegationPolicyError)) throw error;
      beforeNote = `not valid under the current policy (${error.message}); treated as empty`;
    }
  }

  log(`Client: ${clientId}`);
  log(`BEFORE: ${beforeNote}`);
  log(`AFTER: ${sortedJson(after)}`);

  const diff = diffNativeCeilings(before, after);
  for (const line of diff.added) log(`  + ${line}`);
  for (const line of diff.removed) log(`  - ${line}`);
  for (const line of diff.changed) log(`  ~ ${line}`);

  if (diff.removed.length > 0 && !options.allowNarrow) {
    throw new NativeCeilingRefusedError(
      `The new ceiling removes or reduces ${diff.removed.length} existing entr${diff.removed.length === 1 ? 'y' : 'ies'}; ` +
      `nothing was written. Pass --allow-narrow to apply it. Removed:\n${diff.removed.map((line) => `  - ${line}`).join('\n')}`,
    );
  }

  if (before && diff.added.length + diff.removed.length + diff.changed.length === 0) {
    log('No change: the stored ceiling already grants exactly this. Nothing written.');
    return { outcome: 'unchanged', before, after, diff };
  }

  if (options.dryRun) {
    log('DRY RUN: nothing written. Pass --apply (workflow dry_run=false) to write.');
    return { outcome: 'dry-run', before, after, diff };
  }

  // Same write as the admin API PATCH: replace the whole value and keep the delegation scope.
  await db.oauthClient.update({
    where: { clientId },
    data: {
      tinycloudNativeDelegation: nativeDelegationJson(after),
      scopes: [...new Set([...client.scopes, TINYCLOUD_DELEGATION_SCOPE])],
    },
  });

  const stored = await db.oauthClient.findUnique({ where: { clientId } });
  const storedConfig = stored ? validateNativeDelegationConfig(stored.tinycloudNativeDelegation, gate, POLICY_OPTIONS) : null;
  if (!storedConfig || sortedJson(storedConfig) !== sortedJson(after)) {
    throw new Error('The stored ceiling does not match the value that was written');
  }
  log('Written. The stored ceiling matches AFTER.');
  return { outcome: 'written', before, after, diff };
}
