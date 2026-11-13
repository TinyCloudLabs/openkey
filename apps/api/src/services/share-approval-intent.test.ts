import { expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { parseShareApprovalIntent } from './share-approval-intent';
const intent = {
  origin: 'https://thirdparty.example', keyId: 'key', expiresAt: '2026-11-14T00:00:00.000Z',
  session: { siwe: 'verified separately', signature: 'verified separately',
    publicJwk: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) },
  permissions: [{ service: 'tinycloud.kv', space: 'applications', path: 'app/shares/file.json', actions: ['tinycloud.kv/get', 'tinycloud.kv/metadata'] }],
};
test('a share intent cannot select an existing id or add encryption grants', () => {
  expect(parseShareApprovalIntent(intent).permissions).toEqual(intent.permissions);
  for (const field of ['shareId', 'resource', 'siwe', 'action', 'purpose', 'intentDigest']) {
    expect(() => parseShareApprovalIntent({ ...intent, [field]: 'caller-chosen' })).toThrow();
  }
  expect(() => parseShareApprovalIntent({ ...intent, permissions: [{ service: 'tinycloud.encryption', path: 'share/known-existing', actions: ['tinycloud.encryption/decrypt'] }] })).toThrow();
  expect(() => parseShareApprovalIntent({ ...intent, session: { ...intent.session, publicJwk: { ...intent.session.publicJwk, d: 'private' } } })).toThrow();
});
