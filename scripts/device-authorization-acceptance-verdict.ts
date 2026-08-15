#!/usr/bin/env bun

import { readFile } from 'node:fs/promises';

type Evidence = Record<string, unknown>;
const required = [
  'publicCliProcess', 'apiTransactionStart', 'renderedDescriptor',
  'authenticatedApproval', 'descriptorBoundConsumption', 'shareAuthorityVerified',
  'oneShotUpload', 'finalShareUrl',
] as const;

/**
 * A deliberately fail-closed release verdict. Unit/in-memory smoke evidence is
 * useful, but cannot claim the public authorization ceremony completed.
 */
export function acceptanceVerdict(evidence: Evidence): { passed: boolean; missing: string[] } {
  const missing = required.filter((key) => evidence[key] !== true);
  if (evidence.mockedApproval === true || evidence.healthOnly === true || evidence.lookupOnly === true) {
    missing.push('real authenticated approval (mocked/partial evidence is ineligible)');
  }
  return { passed: missing.length === 0, missing };
}

if (import.meta.main) {
  const path = process.argv[2];
  if (!path) throw new Error('Usage: bun scripts/device-authorization-acceptance-verdict.ts evidence.json');
  const evidence = JSON.parse(await readFile(path, 'utf8')) as Evidence;
  const verdict = acceptanceVerdict(evidence);
  process.stdout.write(`${JSON.stringify(verdict)}\n`);
  if (!verdict.passed) process.exit(1);
}
