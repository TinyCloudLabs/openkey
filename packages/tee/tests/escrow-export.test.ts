import { expect, test } from 'bun:test';
import { DhkemP256HkdfSha256 } from '@hpke/core';
import { prepareEscrowExport, type ExportPolicy, type EscrowExportOptions } from '../src/escrow-export';
import { unwrapEscrowShare } from '../src/escrow-envelope';
import { recoverEscrowKey } from '../src/escrow-shares';
import { recoverEscrowPaths } from '../src/escrow-recovery';
import { createDecipheriv } from 'node:crypto';

test('synthetic enclave ceremony exports encrypted path key with actual split coordinates', async () => {
  const kem = new DhkemP256HkdfSha256();
  const pairs = await Promise.all([1, 2, 3].map(() => kem.generateKeyPair()));
  const holders = await Promise.all(pairs.map(async (pair, i) => ({ id: `holder-${i}`, publicKey: Buffer.from(await kem.serializePublicKey(pair.publicKey)).toString('base64url') })));
  const now = Date.now();
  const policy: ExportPolicy = {
    version: 1, escrowId: 'synthetic', appId: 'test', imageDigest: 'sha256:' + 'a'.repeat(64),
    composeHash: 'b'.repeat(64), codeHash: 'c'.repeat(64), osVersion: 'synthetic', agentVersion: 'synthetic',
    bootReference: 'synthetic', snapshotId: 'synthetic', nonce: 'synthetic', approvalReference: 'synthetic',
    operatorId: 'operator', approverId: 'approver', createdAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60000).toISOString(), holders,
    paths: [{ path: 'test/path', purpose: 'test', version: 0, transform: 'sha256-getkey', derivedPublicKey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', sourcePublicKey: 'synthetic', signatureChain: ['synthetic'], expectedCount: 1 }],
  };
  const key = crypto.getRandomValues(new Uint8Array(32));
  const events: string[] = [];
  const options: EscrowExportOptions = {
    getExportQuote: async headerHash => ({ quote: 'synthetic-quote', eventLog: '[]', reportDataSha256: headerHash }),
    enabled: true, dryRun: false, isInTee: () => true, policy,
    authorize: async () => { events.push('authorize'); return true; },
    snapshot: async operation => { events.push('snapshot'); return operation([{ ...policy.paths[0]!, key: key.slice() }]); },
    validateSnapshot: async (_policy, keys) => { events.push('validate'); return keys.map(k => ({ path: k.path, purpose: k.purpose, version: k.version, validatedCount: 1 })); },
  };
  await expect(prepareEscrowExport({ ...options, enabled: false })).rejects.toThrow();
  await expect(prepareEscrowExport({ ...options, isInTee: () => false })).rejects.toThrow();
  await expect(prepareEscrowExport({ ...options, isInTee: async () => false })).rejects.toThrow();
  await expect(prepareEscrowExport({ ...options, authorize: async () => false as unknown as true, snapshot: async () => { throw new Error('must not run'); } })).rejects.toThrow('authorization denied');
  await expect(prepareEscrowExport({ ...options, policy: { ...policy, holders: holders.slice(0, 2) } })).rejects.toThrow();
  await expect(prepareEscrowExport({ ...options, policy: { ...policy, expiresAt: new Date(now - 1).toISOString() } })).rejects.toThrow();
  const dry = await prepareEscrowExport({ ...options, dryRun: undefined });
  expect(dry).toEqual({ dryRun: true, paths: 1, expectedRecords: 1 });
  const result = await prepareEscrowExport(options);
  if (result.dryRun) throw new Error('Expected encrypted bundle');
  expect(result.quote.quote).toBe('synthetic-quote');
  expect(events).toEqual(['authorize', 'snapshot', 'validate', 'authorize', 'snapshot', 'validate']);
  for (const inventory of [[], [{ ...policy.paths[0]!, key: key.slice() }, { ...policy.paths[0]!, key: key.slice() }], [{ ...policy.paths[0]!, path: 'extra', key: key.slice() }], [{ ...policy.paths[0]!, key: new Uint8Array(31) }]]) {
    await expect(prepareEscrowExport({ ...options, snapshot: operation => operation(inventory) })).rejects.toThrow();
    for (const item of inventory) expect(item.key.every(byte => byte === 0)).toBe(true);
  }
  await expect(prepareEscrowExport({ ...options, validateSnapshot: async () => [{ ...policy.paths[0]!, validatedCount: 5 }] })).rejects.toThrow();
  const clearedKey = key.slice();
  await prepareEscrowExport({ ...options, dryRun: true, snapshot: operation => operation([{ ...policy.paths[0]!, key: clearedKey }]) });
  expect(clearedKey.every(byte => byte === 0)).toBe(true);
  await expect(prepareEscrowExport({ ...options, getExportQuote: async () => { throw new Error('Quote unavailable'); } })).rejects.toThrow();
  const shares = [];
  for (const wrapper of result.wrappers.slice(0, 2)) {
    const holder = result.header.holders.find(h => h.id === wrapper.holderId)!;
    expect(wrapper.x).toBe(holder.x);
    const index = Number(holder.id.split('-')[1]);
    shares.push(await unwrapEscrowShare(wrapper, pairs[index]!.privateKey, { escrowId: result.header.escrowId, holderId: holder.id, x: holder.x, headerHash: result.headerHash }));
  }
  const recovered = await recoverEscrowKey(shares, result.header.contentKeyCommitment, policy.escrowId);
  const p = result.header.paths[0]!;
  const aad = Buffer.from(JSON.stringify(['tinycloud/escrow/path-key', 1, result.headerHash, policy.escrowId, policy.appId, p.path, p.purpose, p.version, p.transform, p.sourcePublicKey, p.signatureChain]));
  const blob = Buffer.from(result.items[0]!.ciphertext, 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', recovered, blob.subarray(0, 12));
  decipher.setAAD(aad); decipher.setAuthTag(blob.subarray(-16));
  expect(Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()])).toEqual(Buffer.from(key));
  let imports = 0;
  let keyReference: Uint8Array | undefined;
  const recovery = {
    enabled: true, isInTee: async () => true, header: result.header, expectedHeaderHash: result.headerHash,
    shares, items: result.items,
    validate: async (keys: readonly { key: Uint8Array }[]) => { expect(Buffer.from(keys[0]!.key)).toEqual(Buffer.from(key)); keyReference = keys[0]!.key; return policy.paths.map(p => ({ ...p, validatedCount: p.expectedCount })); },
    importAndReseal: async () => { imports++; return true as const; },
  };
  expect(await recoverEscrowPaths(recovery)).toEqual({ completed: 1, headerHash: result.headerHash });
  expect(keyReference!.every(byte => byte === 0)).toBe(true);
  expect(imports).toBe(1);
  for (const items of [[], [result.items[0]!, result.items[0]!], [{ ...result.items[0]!, path: 'extra' }]]) {
    await expect(recoverEscrowPaths({ ...recovery, items })).rejects.toThrow();
  }
  const damaged = Buffer.from(result.items[0]!.ciphertext, 'base64url'); damaged[15] = damaged[15]! ^ 1;
  await expect(recoverEscrowPaths({ ...recovery, items: [{ ...result.items[0]!, ciphertext: damaged.toString('base64url'), checksum: (await import('node:crypto')).createHash('sha256').update(damaged).digest('hex') }] })).rejects.toThrow();
  await expect(recoverEscrowPaths({ ...recovery, validate: async () => [] })).rejects.toThrow();
  await expect(recoverEscrowPaths({ ...recovery, expectedHeaderHash: '0'.repeat(64) })).rejects.toThrow();
  await expect(recoverEscrowPaths({ ...recovery, isInTee: async () => false })).rejects.toThrow();
  expect(imports).toBe(1);
  expect(JSON.stringify(result)).not.toContain(Buffer.from(key).toString('hex'));
  await expect(prepareEscrowExport({ ...options, authorize: async () => { throw new Error('Denied'); } })).rejects.toThrow();
  await expect(prepareEscrowExport({ ...options, validateSnapshot: async () => { throw new Error('Invalid identity'); } })).rejects.toThrow();
  const sentinel = { ...policy.paths[0]!, path: 'openkey/user/{userId}/encryption', purpose: 'legacy-user-encryption-empty', expectedCount: 0 };
  const legacyPolicy = { ...policy, paths: [...policy.paths, sentinel] };
  const legacyOptions = { ...options, policy: legacyPolicy,
    validateSnapshot: async () => legacyPolicy.paths.map(p => ({ ...p, validatedCount: p.expectedCount })),
  };
  const withEmpty = await prepareEscrowExport(legacyOptions);
  expect(withEmpty.dryRun).toBe(false);
  if (!withEmpty.dryRun) expect(withEmpty.items.length).toBe(1);
  await expect(prepareEscrowExport({ ...legacyOptions, validateSnapshot: async () => legacyPolicy.paths.map(p => ({ ...p, validatedCount: 1 })) })).rejects.toThrow();

});
