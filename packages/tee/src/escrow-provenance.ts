import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256, recoverPublicKey, toBytes } from 'viem';

export interface EscrowGuestAgent {
  getKey(path: string, purpose?: string): Promise<{ key: Uint8Array; signature_chain: Uint8Array[] }>;
  getQuote(data: Uint8Array): Promise<{ quote: string; event_log: string; report_data?: string }>;
}
export interface EscrowQuote { quote: string; eventLog: string; reportDataSha256: string }

async function quoteWithBinding(agent: EscrowGuestAgent, digest: Uint8Array): Promise<EscrowQuote> {
  const response = await agent.getQuote(digest);
  const hex = response.quote.replace(/^0x/, '');
  if (!/^(?:[a-fA-F0-9]{2})+$/.test(hex) || typeof response.event_log !== 'string') throw new Error('Invalid escrow quote');
  const quote = Buffer.from(hex, 'hex');
  const signatureAt = 48 + 584;
  const expected = Buffer.concat([digest, Buffer.alloc(32)]);
  if (quote.length < signatureAt + 4 || quote.readUInt16LE(0) !== 4 || quote.readUInt32LE(4) !== 0x81
    || quote.length !== signatureAt + 4 + quote.readUInt32LE(signatureAt)
    || !quote.subarray(48 + 520, 48 + 584).equals(expected)
    || response.report_data?.replace(/^0x/, '').toLowerCase() !== expected.toString('hex')) throw new Error('Escrow quote binding mismatch');
  return { quote: hex, eventLog: response.event_log, reportDataSha256: Buffer.from(digest).toString('hex') };
}

/** Guest reachability/output binding only; holders/recovery verify TDX chains and measurements. */
export function createEscrowProvenanceClient(agent: EscrowGuestAgent) {
  return {
    async isInTee(): Promise<boolean> {
      try { await quoteWithBinding(agent, randomBytes(32)); return true; } catch { return false; }
    },
    async derivePath(path: string) {
      if (typeof path !== 'string' || !path || Buffer.byteLength(path) > 4096) throw new Error('Invalid escrow path');
      const result = await agent.getKey(path, '');
      try {
        if (result.key.length !== 32 || result.signature_chain.length !== 2
          || result.signature_chain.some(signature => signature.length !== 65)) throw new Error('Invalid escrow source evidence');
        // v0 signs Keccak256(UTF8(purpose + ':' + lowercase compressed derived pubkey)).
        const derivedPublicKey = Buffer.from(secp256k1.getPublicKey(result.key, true)).toString('hex');
        const sourcePublicKey = await recoverPublicKey({ hash: keccak256(toBytes(`:${derivedPublicKey}`)), signature: `0x${Buffer.from(result.signature_chain[0]!).toString('hex')}` });
        const digest = createHash('sha256').update(result.key).digest();
        try {
          return { key: new Uint8Array(digest), derivedPublicKey, sourcePublicKey,
            signatureChain: result.signature_chain.map(signature => Buffer.from(signature).toString('hex')) };
        } finally { digest.fill(0); }
      } finally { result.key.fill(0); }
    },
    async getExportQuote(headerHash: string): Promise<EscrowQuote> {
      if (!/^[a-f0-9]{64}$/.test(headerHash)) throw new Error('Invalid escrow header hash');
      const digest = createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(headerHash, 'utf8').digest();
      return quoteWithBinding(agent, digest);
    },
  };
}

/** Explicit Unix socket prevents the SDK's simulator env override on this path. */
export async function createProductionEscrowProvenanceClient() {
  const { DstackClient } = await import('@phala/dstack-sdk');
  return createEscrowProvenanceClient(new DstackClient('/var/run/dstack.sock'));
}
