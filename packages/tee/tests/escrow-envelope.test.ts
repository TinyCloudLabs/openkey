import { expect, test } from 'bun:test';
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { wrapEscrowShare, unwrapEscrowShare } from '../src/escrow-envelope';

test('HPKE share round trip binds escrow, holder, index and header', async () => {
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
  const keys = await suite.kem.generateKeyPair();
  const share = crypto.getRandomValues(new Uint8Array(33)); share[32] = 7;
  const binding = { escrowId: 'test-escrow', holderId: 'test-holder', x: 7, headerHash: 'a'.repeat(64) };
  const envelope = await wrapEscrowShare(share, keys.publicKey, { ...binding, secret: 'LEAK' } as typeof binding);
  expect(await unwrapEscrowShare(envelope, keys.privateKey, binding)).toEqual(share);
  for (const changed of [{ escrowId: 'other' }, { holderId: 'other' }, { x: 8 }, { headerHash: 'b'.repeat(64) }]) {
    await expect(unwrapEscrowShare(envelope, keys.privateKey, { ...binding, ...changed })).rejects.toThrow();
    await expect(unwrapEscrowShare({ ...envelope, ...changed }, keys.privateKey, { ...binding, ...changed })).rejects.toThrow();
  }
  expect(JSON.stringify(envelope)).not.toContain('LEAK');
  await expect(unwrapEscrowShare({ ...envelope, version: 2 } as unknown as typeof envelope, keys.privateKey, binding)).rejects.toThrow();
  await expect(unwrapEscrowShare({ ...envelope, enc: envelope.enc + '=' }, keys.privateKey, binding)).rejects.toThrow();
  await expect(unwrapEscrowShare({ ...envelope, ciphertext: envelope.ciphertext + '=' }, keys.privateKey, binding)).rejects.toThrow();
  const enc = Buffer.from(envelope.enc, 'base64url'); enc[1] = enc[1]! ^ 1;
  await expect(unwrapEscrowShare({ ...envelope, enc: enc.toString('base64url') }, keys.privateKey, binding)).rejects.toThrow();
  const other = await suite.kem.generateKeyPair();
  await expect(unwrapEscrowShare(envelope, other.privateKey, binding)).rejects.toThrow();
  const ct = Buffer.from(envelope.ciphertext, 'base64url'); ct[0] = ct[0]! ^ 1;
  await expect(unwrapEscrowShare({ ...envelope, ciphertext: ct.toString('base64url') }, keys.privateKey, binding)).rejects.toThrow();
  expect(Object.keys(envelope).sort()).toEqual(['ciphertext', 'enc', 'escrowId', 'headerHash', 'holderId', 'version', 'x']);
});
