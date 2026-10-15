// OpenKey TEE - dstack wrapper with Viem integration
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// Types
export interface TeeClient {
  deriveKey(path: string): Promise<Uint8Array>;
  /**
   * Quote SHA-256 of `binding` (UTF-8). TDX REPORTDATA holds 64 bytes, so the
   * quote carries the 32-byte digest followed by 32 zero bytes.
   */
  getQuote(binding: string): Promise<TeeQuote>;
  isInTee(): boolean;
}

export interface TeeQuote {
  /** Hex TDX quote. */
  quote: string;
  /** dstack event log (JSON), for RTMR replay. */
  eventLog: string;
  /** Hex SHA-256 of the binding: the first 32 bytes of the quote's REPORTDATA. */
  reportDataSha256: string;
}

/**
 * A dstack answer that is not a quote over the binding's digest. `code` (an
 * allowlisted log field) separates a quote we can't parse from one over
 * other report data.
 */
class QuoteBindingError extends Error {
  constructor(
    message: string,
    readonly code: 'quote_report_data_mismatch' | 'quote_format_invalid' = 'quote_report_data_mismatch',
  ) {
    super(message);
  }
}

// TDX quote layout, Intel TDX DCAP Quoting Library API, Appendix A ("Version
// 4 Quote Format"): a 48-byte header (version u16 LE at 0, TEE type u32 LE at
// 4, 0x81 for TDX), the 584-byte TD Quote Body, then a u32 LE signature-data
// length and that many bytes. REPORTDATA is the last 64 bytes of the body
// (body offset 520). dstack emits version 4 quotes.
const QUOTE_HEADER_LENGTH = 48;
const TD_QUOTE_BODY_LENGTH = 584;
const TD_REPORT_DATA_OFFSET = QUOTE_HEADER_LENGTH + 520;

/**
 * The REPORTDATA of a structurally complete TDX v4 quote. Checks layout only;
 * it does not verify the quote's signature or certificates.
 */
function quoteReportData(quote: Buffer): Buffer {
  const signatureLengthAt = QUOTE_HEADER_LENGTH + TD_QUOTE_BODY_LENGTH;
  if (quote.length < signatureLengthAt + 4) {
    throw new QuoteBindingError(`dstack quote is truncated (${quote.length} bytes)`, 'quote_format_invalid');
  }
  if (quote.readUInt16LE(0) !== 4 || quote.readUInt32LE(4) !== 0x81) {
    throw new QuoteBindingError('dstack quote is not a TDX version 4 quote', 'quote_format_invalid');
  }
  if (quote.length - (signatureLengthAt + 4) < quote.readUInt32LE(signatureLengthAt)) {
    throw new QuoteBindingError('dstack quote signature data is truncated', 'quote_format_invalid');
  }
  return quote.subarray(TD_REPORT_DATA_OFFSET, TD_REPORT_DATA_OFFSET + 64);
}

export interface DeriveKeyResult {
  key: Uint8Array;
  certificateChain: string[];
}

export type TeeMode = 'production' | 'development';

/** NODE_ENV values under which the mock may run. Unset is local `bun run`. */
const MOCK_NODE_ENVS: Record<string, true> = { development: true, test: true };

/**
 * Resolves the TEE mode from the environment, failing closed (TC-966).
 *
 * Only `TEE_MODE=production` uses dstack. The mock client seals under
 * deterministic dev keys, so it needs an explicit `TEE_MODE=development`, and
 * only for local development: NODE_ENV unset, `development` or `test`. Any
 * other NODE_ENV (production, staging, preview, …) is a deployment and is
 * refused. A missing or misspelled TEE_MODE throws instead of silently
 * selecting the mock.
 */
export function resolveTeeMode(env: Record<string, string | undefined> = process.env): TeeMode {
  const mode = env.TEE_MODE;
  if (mode === 'production') return 'production';
  if (mode === 'development') {
    const nodeEnv = env.NODE_ENV;
    if (nodeEnv !== undefined && nodeEnv !== '' && !Object.hasOwn(MOCK_NODE_ENVS, nodeEnv)) {
      throw new Error(
        `TEE_MODE=development is only allowed for local development (NODE_ENV unset, development or test), not NODE_ENV=${JSON.stringify(nodeEnv)}; set TEE_MODE=production`,
      );
    }
    return 'development';
  }
  const got = mode === undefined ? 'unset' : JSON.stringify(mode);
  throw new Error(
    `TEE_MODE must be "production" or "development" (got ${got}); refusing to fall back to mock sealing keys`,
  );
}

/**
 * Create a TEE client: dstack for TEE_MODE=production, the mock for an explicit
 * TEE_MODE=development. Throws otherwise (see resolveTeeMode). API modules call
 * this at import, so a bad TEE_MODE stops the API at startup.
 */
export function createTeeClient(): TeeClient {
  return resolveTeeMode() === 'production' ? createProductionClient() : createMockClient();
}

/**
 * Production client using @phala/dstack-sdk (DstackClient for dstack OS 0.5.x)
 *
 * Every sealed key depends on this derivation: sha256(v0 GetKey(path).key).
 * The SDK is pinned exactly; in SDK 0.6 `DstackClient` is the v1 client, which
 * derives different keys. tests/dstack-key-derivation.kat.test.ts freezes the
 * output; read it before touching this function or the SDK version (TC-964).
 */
function createProductionClient(): TeeClient {
  const getDstackClient = async () => {
    const { DstackClient } = await import('@phala/dstack-sdk');
    return new DstackClient();
  };

  return {
    async deriveKey(path: string): Promise<Uint8Array> {
      const client = await getDstackClient();
      const result = await client.getKey(path);
      // getKey returns raw key bytes; hash to 32 bytes for AES-256-GCM
      const hash = createHash('sha256').update(result.key).digest();
      return new Uint8Array(hash);
    },

    async getQuote(binding: string): Promise<TeeQuote> {
      const digest = createHash('sha256').update(binding, 'utf8').digest();
      const client = await getDstackClient();
      const result = await client.getQuote(digest);
      const expected = Buffer.concat([digest, Buffer.alloc(32)]);
      // The guest agent's echo is a cheap sanity check; the binding that
      // matters is the REPORTDATA inside the quote. Verifiers still verify the
      // quote itself.
      if (result.report_data?.replace(/^0x/, '').toLowerCase() !== expected.toString('hex')) {
        throw new QuoteBindingError('dstack echoed report data does not match the binding');
      }
      const quote = result.quote.replace(/^0x/, '');
      if (!/^(?:[0-9a-fA-F]{2})+$/.test(quote)) {
        throw new QuoteBindingError('dstack quote is not hex', 'quote_format_invalid');
      }
      if (!quoteReportData(Buffer.from(quote, 'hex')).equals(expected)) {
        throw new QuoteBindingError('dstack quote REPORTDATA does not match the binding');
      }
      return { quote, eventLog: result.event_log, reportDataSha256: digest.toString('hex') };
    },

    isInTee: () => true,
  };
}

/**
 * Mock client for local development (TEE_MODE=development only)
 * Uses deterministic key derivation from DEV_SEALING_KEY env var
 */
function createMockClient(): TeeClient {
  const devKey = process.env.DEV_SEALING_KEY || 'openkey-dev-sealing-key-32b!';

  return {
    async deriveKey(path: string): Promise<Uint8Array> {
      // Derive a deterministic key from the path + dev key
      const hash = createHash('sha256')
        .update(devKey)
        .update(path)
        .digest();
      return new Uint8Array(hash);
    },

    async getQuote(binding: string): Promise<TeeQuote> {
      return {
        quote: 'mock-tdx-quote-for-development',
        eventLog: '[]',
        reportDataSha256: createHash('sha256').update(binding, 'utf8').digest('hex'),
      };
    },

    isInTee: () => false,
  };
}

/**
 * Seal data using AES-256-GCM
 * @param data - Plain text data to seal
 * @param sealingKey - 32-byte key from TEE
 * @returns Base64 encoded sealed blob (iv:authTag:ciphertext)
 */
export async function seal(data: string, sealingKey: Uint8Array): Promise<string> {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', sealingKey, iv);

  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  // Combine: iv (12) + authTag (16) + ciphertext
  const sealed = Buffer.concat([iv, authTag, encrypted]);
  return sealed.toString('base64');
}

/**
 * Unseal data using AES-256-GCM
 * @param sealedData - Base64 encoded sealed blob
 * @param sealingKey - 32-byte key from TEE
 * @returns Plain text data
 */
export async function unseal(sealedData: string, sealingKey: Uint8Array): Promise<string> {
  const blob = Buffer.from(sealedData, 'base64');

  // Extract: iv (12) + authTag (16) + ciphertext
  const iv = blob.subarray(0, 12);
  const authTag = blob.subarray(12, 28);
  const encrypted = blob.subarray(28);

  const decipher = createDecipheriv('aes-256-gcm', sealingKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

// Re-export wallet utilities
export { createWalletFromPrivateKey, generatePrivateKey, getAddressFromPrivateKey } from './wallet';

// Re-export Nostr identity utilities (secp256k1 Schnorr / BIP-340, NOT ECDSA)
export {
  generateNostrKeypair,
  canonicalizeNip01,
  computeEventId,
  signNostrEvent,
  SUPPORTED_NOSTR_KINDS,
} from './nostr';
export type { UnsignedNostrEvent, SignedNostrEvent, NostrKeypair, SealedNostrSecret } from './nostr';
