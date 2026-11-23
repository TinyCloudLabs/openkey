import { describe, expect, test } from 'bun:test';
import { BOT_HISTORY_KEY_PATH } from '../services/reserved-secret-scopes';
import { mockModules } from './mock-module';

// TinyChat's bot-history key sits under a scope the SDK reserves. The API's secret list, write and delete each
// leave it alone, in the exact spelling and in any spelling the SDK reads as the same scope.
const vaultCalls: string[] = [];
const ordinary = ['secrets/ANTHROPIC_API_KEY', 'secrets/OPENAI_API_KEY'];
const stored = [...ordinary];

class FakeTinyCloudNode {
  vault = {
    unlock: async () => ({ ok: true, data: undefined }),
    list: async () => {
      vaultCalls.push('list');
      return { ok: true, data: [...stored] };
    },
    put: async () => {
      vaultCalls.push('put');
      return { ok: true, data: undefined };
    },
    delete: async () => {
      vaultCalls.push('delete');
      return { ok: true, data: undefined };
    },
  };
  spaceId = 'tinycloud:pkh:eip155:1:0x0:fake';
  async signIn() {}
  async ensureEncryptionNetwork() {}
}

await mockModules({ '@tinycloud/node-sdk': () => ({ TinyCloudNode: FakeTinyCloudNode }) });
const { tinyCloudService } = await import('../services/tinycloud-service?reserved-secret-scopes' as string);

const userId = 'user_reserved_scopes';
const keyName = BOT_HISTORY_KEY_PATH.slice('secrets/'.length);
const spellings = [
  keyName,
  `${keyName}/item-1`,
  keyName.replace('tinychat-bot-history', 'Tinychat-Bot-History'),
  keyName.replace('tinychat-bot-history', 'TINYCHAT_BOT HISTORY'),
];
const names = (secrets: Array<{ name: string }>) => secrets.map((secret) => secret.name);

describe('the reserved bot-history scope', () => {
  test('is not listed or counted, in any spelling', async () => {
    await tinyCloudService.enableForUser(userId, '55'.repeat(32));
    stored.push(...spellings.map((name) => `secrets/${name}`));
    try {
      expect(names(await tinyCloudService.listSecrets(userId))).toEqual(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']);
    } finally {
      stored.length = ordinary.length;
    }
  });

  test('cannot be written, in any spelling', async () => {
    vaultCalls.length = 0;
    for (const name of spellings) await expect(tinyCloudService.putSecret(userId, name, 'x')).rejects.toThrow('reserved');
    expect(vaultCalls).toEqual([]);
  });

  test('cannot be deleted, in any spelling', async () => {
    vaultCalls.length = 0;
    for (const name of spellings) await expect(tinyCloudService.deleteSecret(userId, name)).rejects.toThrow('reserved');
    expect(vaultCalls).toEqual([]);
  });

  test('leaves a scope with a similar name listed, writable and deletable', async () => {
    vaultCalls.length = 0;
    const similar = 'scoped/tinychat-bot-history-copy/bot-history';
    stored.push(`secrets/${similar}`);
    try {
      expect(names(await tinyCloudService.listSecrets(userId))).toContain(similar);
    } finally {
      stored.length = ordinary.length;
    }
    await tinyCloudService.putSecret(userId, similar, 'x');
    await tinyCloudService.deleteSecret(userId, similar);
    expect(vaultCalls).toEqual(['list', 'put', 'delete']);
  });
});
