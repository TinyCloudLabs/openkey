import { expect, test } from 'bun:test';
import { webcrypto, randomBytes } from 'node:crypto';
import approvalVector from '../../../../packages/tee/tests/fixtures/escrow-approval-v1.json';
import { mockModules } from './mock-module';

  const pairs = await Promise.all([1, 2].map(() => webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])));
  const admins = await Promise.all(pairs.map(async (pair, i) => ({ id: `admin-${i}`, publicKey: Buffer.from(await webcrypto.subtle.exportKey('raw', pair.publicKey)).toString('base64url') })));
  await mockModules({ '../services/escrow-admins.json': () => ({ default: [...admins, ...approvalVector.admins] }) });
  const { authorizeEscrow, escrowApprovalMessage } = await import('../services/escrow-approval?escrow-approval-test' as string);
test('two distinct measured admin keys must sign the exact policy and consume one nonce', async () => {
  const expected = { policyHash: 'a'.repeat(64), nonce: randomBytes(32).toString('base64url'), expiresAt: new Date(Date.now() + 60000).toISOString(), dryRun: true, operatorId: 'admin-0', approverId: 'admin-1' };
  const message = escrowApprovalMessage(expected);
  const signatures = await Promise.all(pairs.map(async (pair, i) => ({ id: admins[i]!.id, signature: Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, message)).toString('base64url') })));
  const request = { ...expected, signatures };
  let consumed = 0;
  const store = { consume: async () => { consumed++; return true as const; } };
  expect(await authorizeEscrow(request, expected, store)).toBe(true);
  expect(consumed).toBe(1);
  for (const patch of [{ policyHash: 'b'.repeat(64) }, { dryRun: false }, { nonce: randomBytes(32).toString('base64url') }, { approverId: 'admin-0' }, { signatures: [signatures[0], signatures[0]] }, { signatures: signatures.slice(0, 1) }]) {
    await expect(authorizeEscrow({ ...request, ...patch }, expected, store)).rejects.toThrow();
  }
  expect(consumed).toBe(1);
  await expect(authorizeEscrow({ ...request, signatures: [{ ...signatures[0], signature: Buffer.alloc(64).toString('base64url') }, signatures[1]] }, expected, store)).rejects.toThrow();
  await expect(authorizeEscrow(request, expected, { consume: async () => false as unknown as true })).rejects.toThrow();
  const script = `import { authorizeEscrow } from ${JSON.stringify(new URL('../services/escrow-approval.ts', import.meta.url).pathname)};
try { await authorizeEscrow(${JSON.stringify(request)}, ${JSON.stringify(expected)}, { consume: async () => true }); process.exit(2); } catch(e) { if(e.message !== 'Escrow approval not configured') process.exit(3); }`;
  const child = Bun.spawn([process.execPath, '-e', script], { env: {}, stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited).toBe(0);

  expect(new TextDecoder().decode(escrowApprovalMessage(approvalVector.expected))).toBe(approvalVector.approveMessageUtf8);
  expect(await authorizeEscrow({ ...approvalVector.expected, signatures: approvalVector.signatures }, approvalVector.expected, store)).toBe(true);

});
