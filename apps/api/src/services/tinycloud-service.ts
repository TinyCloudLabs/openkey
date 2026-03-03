// TinyCloud service - manages TinyCloud sessions and operations on behalf of users
import { TinyCloudNode } from '@tinycloud/node-sdk';
import { Wallet } from 'ethers';
import { PrismaClient } from '@prisma/client';
import { createTeeClient, seal, unseal } from '@openkey/tee';
import { generateKeyPairSync, privateDecrypt, constants } from 'crypto';

const TINYCLOUD_URL = process.env.TINYCLOUD_URL || 'https://node.tinycloud.xyz';
const prisma = new PrismaClient();
const tee = createTeeClient();

interface TinyCloudSession {
  tc: TinyCloudNode;
  wallet: Wallet;
}

// In-memory cache of TinyCloud sessions per userId
const sessions = new Map<string, TinyCloudSession>();

async function getSession(userId: string, privateKey: string): Promise<TinyCloudSession> {
  const existing = sessions.get(userId);
  if (existing) {
    return existing;
  }

  // Initialize new TinyCloudNode for this user
  const wallet = new Wallet(`0x${privateKey}`);
  const tc = new TinyCloudNode({
    host: TINYCLOUD_URL,
    privateKey: privateKey,
    prefix: 'openkey',
    autoCreateSpace: true,
  });

  await tc.signIn();
  await tc.vault.unlock(wallet);

  const session: TinyCloudSession = { tc, wallet };
  sessions.set(userId, session);
  return session;
}

export class TinyCloudService {
  async enableForUser(userId: string, privateKey: string): Promise<{ spaceId: string }> {
    const session = await getSession(userId, privateKey);
    return { spaceId: session.tc.spaceId! };
  }

  async isEnabledForUser(userId: string): Promise<boolean> {
    return sessions.has(userId);
  }

  // =========================================================================
  // Per-user encryption keypair
  // =========================================================================

  async getOrCreateEncryptionKey(userId: string): Promise<{ publicKey: string }> {
    const existing = await prisma.userEncryptionKey.findUnique({
      where: { userId },
    });

    if (existing) {
      return { publicKey: existing.publicKey };
    }

    // Generate RSA-OAEP 2048-bit keypair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // Seal private key with TEE
    const sealingKey = await tee.deriveKey(`openkey/user/${userId}/encryption`);
    const sealedPrivateKey = await seal(privateKey as string, sealingKey);

    await prisma.userEncryptionKey.create({
      data: {
        userId,
        publicKey: publicKey as string,
        sealedPrivateKey,
      },
    });

    return { publicKey: publicKey as string };
  }

  async decryptValue(userId: string, encrypted: EncryptedPayload): Promise<string> {
    const encKey = await prisma.userEncryptionKey.findUnique({
      where: { userId },
    });

    if (!encKey) {
      throw new Error('No encryption key found for user');
    }

    // Unseal private key
    const sealingKey = await tee.deriveKey(`openkey/user/${userId}/encryption`);
    const privateKeyPem = await unseal(encKey.sealedPrivateKey, sealingKey);

    if ('encryptedKey' in encrypted) {
      // Hybrid encryption: RSA-decrypt the AES key, then AES-decrypt the value
      const aesKeyBuf = privateDecrypt(
        { key: privateKeyPem, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(encrypted.encryptedKey, 'base64'),
      );

      const iv = Buffer.from(encrypted.iv, 'base64');
      const ciphertext = Buffer.from(encrypted.encryptedValue, 'base64');

      // AES-256-GCM: last 16 bytes are auth tag
      const authTag = ciphertext.subarray(ciphertext.length - 16);
      const data = ciphertext.subarray(0, ciphertext.length - 16);

      const { createDecipheriv } = await import('crypto');
      const decipher = createDecipheriv('aes-256-gcm', aesKeyBuf, iv);
      decipher.setAuthTag(authTag);

      const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
      return decrypted.toString('utf8');
    } else {
      // Direct RSA encryption (small payloads)
      const decrypted = privateDecrypt(
        { key: privateKeyPem, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
        Buffer.from(encrypted.encryptedValue, 'base64'),
      );
      return decrypted.toString('utf8');
    }
  }

  // =========================================================================
  // Secrets (vault - encrypted)
  // =========================================================================

  async putSecret(userId: string, name: string, value: string): Promise<{ createdAt: string }> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const createdAt = new Date().toISOString();
    const result = await session.tc.vault.put(`secrets/${name}`, { value, createdAt });
    if (!result.ok) {
      throw new Error(`Failed to store secret: ${(result as any).error?.message}`);
    }
    return { createdAt };
  }

  async listSecrets(userId: string): Promise<Array<{ name: string; createdAt: string }>> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const listResult = await session.tc.vault.list({ prefix: 'secrets/' });
    if (!listResult.ok) {
      throw new Error(`Failed to list secrets: ${(listResult as any).error?.message}`);
    }

    const secrets: Array<{ name: string; createdAt: string }> = [];
    for (const key of listResult.data) {
      const name = key.replace('secrets/', '');
      let createdAt = '';
      // Read the stored payload to get createdAt
      const getResult = await session.tc.vault.get<{ value: string; createdAt: string }>(key);
      if (getResult.ok && getResult.data?.createdAt) {
        createdAt = getResult.data.createdAt;
      }
      secrets.push({ name, createdAt });
    }

    return secrets;
  }

  async deleteSecret(userId: string, name: string): Promise<void> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const result = await session.tc.vault.delete(`secrets/${name}`);
    if (!result.ok) {
      throw new Error(`Failed to delete secret: ${(result as any).error?.message}`);
    }
  }

  // =========================================================================
  // Variables (KV - plaintext)
  // =========================================================================

  async putVariable(userId: string, name: string, value: string): Promise<{ createdAt: string }> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const createdAt = new Date().toISOString();
    const kv = session.tc.kv.withPrefix('variables/');
    const result = await kv.put(name, { value, createdAt });
    if (!result.ok) {
      throw new Error(`Failed to store variable: ${(result as any).error?.message}`);
    }
    return { createdAt };
  }

  async getVariable(userId: string, name: string): Promise<{ value: string; createdAt: string }> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const kv = session.tc.kv.withPrefix('variables/');
    const result = await kv.get<{ value: string; createdAt: string }>(name);
    if (!result.ok) {
      throw new Error(`Failed to get variable: ${(result as any).error?.message}`);
    }
    return result.data.data as { value: string; createdAt: string };
  }

  async listVariables(userId: string): Promise<Array<{ name: string; value: string; createdAt: string }>> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const kv = session.tc.kv.withPrefix('variables/');
    const listResult = await kv.list();
    if (!listResult.ok) {
      throw new Error(`Failed to list variables: ${(listResult as any).error?.message}`);
    }

    const variables: Array<{ name: string; value: string; createdAt: string }> = [];
    for (const key of listResult.data.keys) {
      const getResult = await kv.get<{ value: string; createdAt: string }>(key);
      if (getResult.ok && getResult.data.data) {
        const data = getResult.data.data as { value: string; createdAt: string };
        variables.push({ name: key, value: data.value, createdAt: data.createdAt });
      }
    }

    return variables;
  }

  async deleteVariable(userId: string, name: string): Promise<void> {
    const session = sessions.get(userId);
    if (!session) {
      throw new Error('TinyCloud not enabled for user');
    }

    const kv = session.tc.kv.withPrefix('variables/');
    const result = await kv.delete(name);
    if (!result.ok) {
      throw new Error(`Failed to delete variable: ${(result as any).error?.message}`);
    }
  }
}

// Encrypted payload types
export interface EncryptedPayloadDirect {
  encryptedValue: string; // base64 RSA-OAEP ciphertext
}

export interface EncryptedPayloadHybrid {
  encryptedKey: string;   // base64 RSA-OAEP encrypted AES key
  encryptedValue: string; // base64 AES-256-GCM ciphertext + auth tag
  iv: string;             // base64 AES-GCM IV
}

export type EncryptedPayload = EncryptedPayloadDirect | EncryptedPayloadHybrid;

export const tinyCloudService = new TinyCloudService();
