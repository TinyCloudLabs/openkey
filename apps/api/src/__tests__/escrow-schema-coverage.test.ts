import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const mapped = new Map([
  ['EthereumKey', new Set(['sealedBlob'])],
  ['NostrKey', new Set(['sealedSecret'])],
  ['UserEncryptionKey', new Set(['sealedPrivateKey'])],
]);

test('every sealed or blob Prisma field has an escrow inventory and fence mapping', () => {
  const schema = readFileSync(new URL('../../../../packages/db/prisma/schema.prisma', import.meta.url), 'utf8');
  const discovered: string[] = [];
  for (const [, model, body] of schema.matchAll(/model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
    for (const line of body!.split('\n')) {
      const field = line.trim().match(/^(\w+)\s+\S+/)?.[1];
      if (!field || !(/sealed/i.test(field) || /blob/i.test(field))) continue;
      discovered.push(`${model}.${field}`);
      expect(mapped.get(model!)?.has(field), `Missing escrow mapping: ${model}.${field}`).toBe(true);
    }
  }
  expect(discovered.sort()).toEqual(['EthereumKey.sealedBlob', 'NostrKey.sealedSecret', 'UserEncryptionKey.sealedPrivateKey']);
});

import { openKeySnapshotColumnNames } from '../services/escrow-db-encoding';
test('snapshot encoding covers every scalar column of all three complete Prisma models', () => {
  const schema = readFileSync(new URL('../../../../packages/db/prisma/schema.prisma', import.meta.url), 'utf8');
  const scalarTypes = new Set(['String', 'Boolean', 'Int', 'BigInt', 'Float', 'Decimal', 'DateTime', 'Json', 'Bytes', ...[...schema.matchAll(/^enum\s+(\w+)\s*\{/gm)].map(match => match[1]!) ]);
  const models = new Map([...schema.matchAll(/^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)].map(match => [match[1]!, match[2]!]));
  const columns = openKeySnapshotColumnNames();
  for (const [model, table] of [['EthereumKey', 'ethereum_keys'], ['NostrKey', 'nostr_keys'], ['UserEncryptionKey', 'user_encryption_key']] as const) {
    const body = models.get(model)!;
    const expected = [...body.matchAll(/^\s*(\w+)\s+(\w+)(?:\?|\[\])?(?:\s|$)/gm)]
      .filter(match => scalarTypes.has(match[2]!)).map(match => match[1]!).sort();
    expect([...columns[table]!].sort(), `Full snapshot coverage for ${model}`).toEqual(expected);
    expect(new Set(columns[table]).size).toBe(columns[table]!.length);
  }
});
