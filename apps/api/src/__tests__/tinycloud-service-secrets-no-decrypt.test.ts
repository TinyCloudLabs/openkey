import { describe, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

// The secrets session lists, writes and deletes sealed values and never opens one: it holds no decrypt grant,
// so a list that read a value back would be refused.
type VaultCall = { method: string; args: unknown[] };
const vaultCalls: VaultCall[] = [];
const stored = ['secrets/ANTHROPIC_API_KEY', 'secrets/OPENAI_API_KEY'];

function fakeVault() {
  const record = (method: string, result: unknown) => async (...args: unknown[]) => {
    vaultCalls.push({ method, args });
    return result;
  };
  return {
    unlock: record('unlock', { ok: true, data: undefined }),
    list: record('list', { ok: true, data: stored }),
    put: record('put', { ok: true, data: undefined }),
    delete: record('delete', { ok: true, data: undefined }),
    get: async (...args: unknown[]) => {
      vaultCalls.push({ method: 'get', args });
      throw new Error('this session holds no decrypt grant');
    },
  };
}

class FakeTinyCloudNode {
  vault = fakeVault();
  spaceId = 'tinycloud:pkh:eip155:1:0x0:fake';
  async signIn() {}
  async ensureEncryptionNetwork() {
    vaultCalls.push({ method: 'ensureEncryptionNetwork', args: [] });
  }
}

await mockModules({ '@tinycloud/node-sdk': () => ({ TinyCloudNode: FakeTinyCloudNode }) });
const { tinyCloudService } = await import('../services/tinycloud-service?secrets-no-decrypt' as string);

const privateKey = '33'.repeat(32);
const userId = 'user_no_decrypt';

describe('the secrets session of the API', () => {
  test('makes the default encryption network before it unlocks the vault', async () => {
    await tinyCloudService.enableForUser(userId, privateKey);
    const methods = vaultCalls.map((call) => call.method);
    expect(methods.indexOf('ensureEncryptionNetwork')).toBeGreaterThanOrEqual(0);
    expect(methods.indexOf('ensureEncryptionNetwork')).toBeLessThan(methods.indexOf('unlock'));
  });

  test('lists the names without reading any value', async () => {
    vaultCalls.length = 0;

    const secrets = await tinyCloudService.listSecrets(userId);

    expect(secrets.map((secret: { name: string }) => secret.name)).toEqual(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']);
    expect(vaultCalls.map((call) => call.method)).toEqual(['list']);
    expect(vaultCalls[0]!.args).toEqual([{ prefix: 'secrets/' }]);
  });

  test('keeps the shape the web client parses, with a time string per secret', async () => {
    const secrets = await tinyCloudService.listSecrets(userId);
    for (const secret of secrets) expect(typeof secret.createdAt).toBe('string');
  });

  test('writes and deletes a secret without reading a value', async () => {
    vaultCalls.length = 0;
    await tinyCloudService.putSecret(userId, 'ANTHROPIC_API_KEY', 'sk-test');
    await tinyCloudService.deleteSecret(userId, 'ANTHROPIC_API_KEY');
    expect(vaultCalls.map((call) => call.method)).toEqual(['put', 'delete']);
    expect(vaultCalls[0]!.args[0]).toBe('secrets/ANTHROPIC_API_KEY');
  });
});
