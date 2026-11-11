import { expect, test } from 'bun:test';
import { DhkemP256HkdfSha256 } from '@hpke/core';
import { encodeEscrowHeader, freezeEscrowHeader, type EscrowHeader } from '../src/escrow-header';

test('canonical header fixes ordering, copies policy and curve-checks recipients', async () => {
  const kem = new DhkemP256HkdfSha256();
  const holders = await Promise.all(['c', 'a', 'b'].map(async (id, index) => {
    const pair = await kem.generateKeyPair();
    return { id, x: index + 1, publicKey: Buffer.from(await kem.serializePublicKey(pair.publicKey)).toString('base64url') };
  }));
  const h: EscrowHeader = {
    version: 1, contentKeyCommitment: 'd'.repeat(64), createdAt: '2026-11-11T00:00:00.000Z', expiresAt: '2026-11-12T00:00:00.000Z', escrowId: 'escrow', appId: 'openkey', imageDigest: 'sha256:' + 'a'.repeat(64),
    composeHash: 'b'.repeat(64), codeHash: 'c'.repeat(64), osVersion: 'test-os', agentVersion: 'test-agent',
    bootReference: 'test-boot', snapshotId: 'test-snapshot', nonce: 'test-nonce', approvalReference: 'test-approval',
    operatorId: 'operator', approverId: 'approver', holders,
    paths: [{ path: 'test/path', purpose: 'wallet', version: 0, transform: 'sha256-getkey', sourcePublicKey: 'synthetic-source', signatureChain: ['synthetic-chain'], expectedCount: 1 }],
  };
  const frozen = await freezeEscrowHeader(h);
  expect(frozen.recipients.size).toBe(3);
  expect(encodeEscrowHeader({ ...h, holders: [...holders].reverse() })).toEqual(frozen.bytes);
  const extra = await freezeEscrowHeader({ ...h, threshold: 1, holders: h.holders.map(holder => ({ ...holder, secret: 'LEAK' })) } as EscrowHeader);
  expect(JSON.stringify(extra.header)).not.toContain('LEAK');
  expect('threshold' in extra.header).toBe(false);
  expect(extra.hash).toBe(frozen.hash);
  for (const patch of [
    { imageDigest: ['sha256:' + 'a'.repeat(64)] }, { imageDigest: 'bad' },
    { appId: '\ud800' }, { holders: h.holders.slice(0, 2) },
    { holders: h.holders.map(holder => ({ ...holder, x: 1 })) },
    { paths: [...h.paths, h.paths[0]!] },
    ...[NaN, 0.5, -0, 0].map(expectedCount => ({ paths: [{ ...h.paths[0]!, expectedCount }] })),
    { holders: h.holders.map(holder => ({ ...holder, publicKey: holder.publicKey + '=' })) },
    { holders: h.holders.map(holder => ({ ...holder, publicKey: Buffer.alloc(33, 2).toString('base64url') })) },
  ]) await expect(freezeEscrowHeader({ ...h, ...patch } as EscrowHeader)).rejects.toThrow();
  h.operatorId = 'changed'; holders[0]!.id = 'changed';
  expect(frozen.header.operatorId).toBe('operator');
  expect(frozen.header.holders[0]!.id).toBe('a');
  expect(Object.isFrozen(frozen.header.paths[0])).toBe(true);
  await expect(freezeEscrowHeader({ ...frozen.header, approverId: 'operator' })).rejects.toThrow();
  await expect(freezeEscrowHeader({ ...frozen.header, holders: [holders[1]!, holders[1]!, holders[2]!] })).rejects.toThrow();
  const bad = Buffer.alloc(65); bad[0] = 4;
  await expect(freezeEscrowHeader({ ...frozen.header, holders: [...frozen.header.holders.slice(0, 2), { id: 'bad', x: 99, publicKey: bad.toString('base64url') }] })).rejects.toThrow();
});

import fixed from './fixtures/escrow-header-v1.json';
test('fixed public P-256 scalar 1/2/3 header vector matches exact bytes and hash', async () => {
  const header = fixed.header as EscrowHeader;
  expect(new TextDecoder().decode(encodeEscrowHeader(header))).toBe(fixed.canonicalUtf8);
  expect((await freezeEscrowHeader(header)).hash).toBe(fixed.sha256);
});
