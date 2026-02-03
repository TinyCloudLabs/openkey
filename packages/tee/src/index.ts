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

// Check if we're running in TEE
const isProduction = process.env.TEE_MODE === 'production';

/**
 * Create a TEE client - uses dstack SDK in production, mock in development
 */
export function createTeeClient(): TeeClient {
  if (isProduction) {
    return createProductionClient();
  }
  return createMockClient();
}

/**
 * Production client using @phala/dstack-sdk (DstackClient for dstack OS 0.5.x)
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
 * Mock client for local development
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

// Re-export for convenience
export { isProduction as isProductionTee };

// Re-export wallet utilities
export { createWalletFromPrivateKey, generatePrivateKey, getAddressFromPrivateKey } from './wallet';
