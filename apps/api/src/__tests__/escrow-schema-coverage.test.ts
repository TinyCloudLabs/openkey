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
