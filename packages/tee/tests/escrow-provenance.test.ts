import { expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, toBytes } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createEscrowProvenanceClient, type EscrowGuestAgent } from '../src/escrow-provenance';

test('escrow provenance preserves derivation, chain and header quote binding without env gates', async () => {
  const raw = new Uint8Array(32); raw[31] = 9;
  const source = privateKeyToAccount(('0x' + '01'.padStart(64, '0')) as `0x${string}`);
  const pub = Buffer.from(secp256k1.getPublicKey(raw, true)).toString('hex');
  const signature = Buffer.from((await source.sign({ hash: keccak256(toBytes(`:${pub}`)) })).slice(2), 'hex');
  let returned: Uint8Array | undefined;
  const agent: EscrowGuestAgent = {
    getKey: async (path, purpose) => { expect(path).toBe('synthetic/path'); expect(purpose).toBe(''); returned = raw.slice(); return { key: returned, signature_chain: [signature, new Uint8Array(65)] }; },
    getQuote: async digest => {
      const quote = Buffer.alloc(48 + 584 + 4); quote.writeUInt16LE(4); quote.writeUInt32LE(0x81, 4);
      Buffer.from(digest).copy(quote, 48 + 520);
      return { quote: quote.toString('hex'), event_log: '[]', report_data: Buffer.concat([digest, Buffer.alloc(32)]).toString('hex') };
    },
  };
  const client = createEscrowProvenanceClient(agent);
  expect(await client.isInTee()).toBe(true);
  const result = await client.derivePath('synthetic/path');
  expect(Buffer.from(result.key).toString('hex')).toBe(createHash('sha256').update(raw).digest('hex'));
  expect(result.sourcePublicKey).toBe(source.publicKey);
  expect(result.signatureChain[0]).toBe(signature.toString('hex'));
  expect(returned!.every(byte => byte === 0)).toBe(true);
  const hash = 'a'.repeat(64);
  const quote = await client.getExportQuote(hash);
  expect(quote.reportDataSha256).toBe(createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(hash).digest('hex'));
  const broken = createEscrowProvenanceClient({ ...agent, getQuote: async () => { throw new Error('Unavailable'); } });
  expect(await broken.isInTee()).toBe(false);
  await expect(broken.getExportQuote(hash)).rejects.toThrow();
  await expect(createEscrowProvenanceClient({ ...agent, getQuote: async () => ({ quote: '00', event_log: '[]', report_data: '00' }) }).getExportQuote(hash)).rejects.toThrow();
});
