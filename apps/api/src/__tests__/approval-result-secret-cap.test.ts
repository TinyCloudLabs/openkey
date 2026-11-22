import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { ApprovalResultService, type ApprovalRequestRecord, type ApprovalRequestStore } from '../services/approval-results';
import { strictSessionDid } from '../services/device-authorization';

// TC-3800: an approval request that decrypts secrets (a secret's own key, a prefix under `secrets/`, or a whole
// network) lasts 7 days at most, whatever its requester signed. The server refuses a longer one.

const DAY_MS = 86_400_000;
const NOW = new Date('2026-11-27T12:00:00Z');
const OWNER = '0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:1:${OWNER}:default`;
const HOST = 'https://node.tinycloud.test';
const DECRYPT = 'tinycloud.encryption/decrypt';

function fixture(permissions: unknown[], grantLifetimeSeconds = 30 * 86_400) {
  const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const record = {
    id: 'abcdefghijklmnopqrstuvwxyz', bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester',
    request: { targetDid: 'synthetic-requester', targetPublicJwk: jwk, nodeOrigin: HOST, permissions, grantLifetimeSeconds },
    expiresAt: new Date(NOW.getTime() + 600_000), createdAt: NOW,
  } as unknown as ApprovalRequestRecord;
  const unused = async () => { throw new Error('not used'); };
  const store: ApprovalRequestStore = {
    register: unused, findById: async (id) => (id === record.id ? record : null), findByResultRef: unused,
    admit: unused, release: unused, approve: unused, saveRenewal: unused, acknowledge: unused, deny: unused,
  };
  const service = new ApprovalResultService(store, { apiOrigin: 'http://localhost:3001', retentionSeconds: 600, now: () => NOW });
  const body = { jwk, host: HOST, permissions };
  const siwe = (lifetimeMs: number) => new SiweMessage({
    domain: 'app.example.test', address: Wallet.createRandom().address, uri: strictSessionDid(jwk as JsonWebKey),
    version: '1', chainId: 1, nonce: 'abcdef123456', issuedAt: NOW.toISOString(),
    expirationTime: new Date(NOW.getTime() + lifetimeMs).toISOString(),
  }).prepareMessage();
  return {
    window: (input: { expiryMs?: number; signedSiwe?: string }) => service.assertDelegationWindow(record.id, { ...body, ...input }),
    siwe,
  };
}

const secretKey = { service: 'tinycloud.encryption', space: 'encryption', path: `${NETWORK}/secrets/openai_api_key`, actions: [DECRYPT] };
const secretRead = { service: 'tinycloud.kv', space: `tinycloud:pkh:eip155:1:${OWNER}:secrets`, path: 'vault/secrets/OPENAI_API_KEY', actions: ['tinycloud.kv/get'] };

describe('approval request lifetime for secrets (TC-3800)', () => {
  for (const [name, decrypt] of [
    ['a secret\'s own key', secretKey],
    ['every secret', { ...secretKey, path: `${NETWORK}/secrets/` }],
    ['a whole network', { ...secretKey, path: NETWORK }],
  ] as const) {
    test(`a request that signed 30 days and decrypts ${name} is refused past 7 days`, async () => {
      const f = fixture([secretRead, decrypt]);
      await expect(f.window({ expiryMs: 7 * DAY_MS })).resolves.toBeDefined();
      await expect(f.window({ signedSiwe: f.siwe(7 * DAY_MS) })).resolves.toBeDefined();
      await expect(f.window({ expiryMs: 7 * DAY_MS + 1000 })).rejects.toMatchObject({ code: 'request_binding' });
      await expect(f.window({ signedSiwe: f.siwe(8 * DAY_MS) })).rejects.toMatchObject({ code: 'request_binding' });
    });
  }

  test('a request that decrypts nothing keeps the lifetime it signed', async () => {
    const f = fixture([secretRead]);
    await expect(f.window({ expiryMs: 30 * DAY_MS })).resolves.toBeDefined();
    await expect(f.window({ signedSiwe: f.siwe(30 * DAY_MS) })).resolves.toBeDefined();
    await expect(f.window({ expiryMs: 31 * DAY_MS })).rejects.toMatchObject({ code: 'request_binding' });
  });

  test('a shorter signed lifetime stays the limit', async () => {
    const f = fixture([secretRead, secretKey], 3_600);
    await expect(f.window({ expiryMs: 3_600_000 })).resolves.toBeDefined();
    await expect(f.window({ expiryMs: 2 * 3_600_000 })).rejects.toMatchObject({ code: 'request_binding' });
  });
});
