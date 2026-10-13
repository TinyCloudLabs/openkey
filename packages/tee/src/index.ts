// OpenKey TEE - dstack wrapper with Viem integration
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// Types
export interface TeeClient {
  deriveKey(path: string): Promise<Uint8Array>;
  getQuote(data: string): Promise<string>;
  isInTee(): boolean;
}

export interface DeriveKeyResult {
  key: Uint8Array;
  certificateChain: string[];
}

export type TeeMode = 'production' | 'development';

/**
 * Resolves the TEE mode from the environment, failing closed (TC-966).
 *
 * Only `TEE_MODE=production` uses dstack. The mock client seals under
 * deterministic dev keys, so it needs an explicit `TEE_MODE=development`, and
 * it is refused when `NODE_ENV=production`. A missing or misspelled TEE_MODE
 * throws instead of silently selecting the mock.
 */
export function resolveTeeMode(env: Record<string, string | undefined> = process.env): TeeMode {
  const mode = env.TEE_MODE;
  if (mode === 'production') return 'production';
  if (mode === 'development') {
    if (env.NODE_ENV === 'production') {
      throw new Error('TEE_MODE=development is not allowed with NODE_ENV=production; set TEE_MODE=production');
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

    async getQuote(data: string): Promise<string> {
      const client = await getDstackClient();
      const result = await client.getQuote(data);
      return result.quote;
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

    async getQuote(_data: string): Promise<string> {
      return 'mock-tdx-quote-for-development';
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
