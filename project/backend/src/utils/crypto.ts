import crypto from 'crypto';
import { ethers } from 'ethers';

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const ALGORITHM = 'aes-256-gcm';

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 32) {
  throw new Error('ENCRYPTION_KEY must be exactly 32 characters long');
}

export class CryptoUtils {
  /**
   * Encrypt a private key using AES-256-GCM
   */
  static encryptPrivateKey(privateKey: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(ALGORITHM, ENCRYPTION_KEY);
    cipher.setIV(iv);
    
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Combine IV, auth tag, and encrypted data
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  }

  /**
   * Decrypt a private key using AES-256-GCM
   */
  static decryptPrivateKey(encryptedData: string): string {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const decipher = crypto.createDecipher(ALGORITHM, ENCRYPTION_KEY);
    decipher.setIV(iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Generate a new Ethereum private key and address
   */
  static generateEthereumKey(): { privateKey: string; address: string } {
    const wallet = ethers.Wallet.createRandom();
    return {
      privateKey: wallet.privateKey,
      address: wallet.address,
    };
  }

  /**
   * Sign a message with an Ethereum private key
   */
  static async signMessage(privateKey: string, message: string): Promise<string> {
    const wallet = new ethers.Wallet(privateKey);
    return await wallet.signMessage(message);
  }

  /**
   * Sign a transaction with an Ethereum private key
   */
  static async signTransaction(
    privateKey: string, 
    transaction: ethers.TransactionRequest
  ): Promise<string> {
    const wallet = new ethers.Wallet(privateKey);
    return await wallet.signTransaction(transaction);
  }

  /**
   * Generate a random token for recovery
   */
  static generateRecoveryToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Hash a password using bcrypt
   */
  static hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  /**
   * Verify a password against a hash
   */
  static verifyPassword(password: string, hash: string): boolean {
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    return hashedPassword === hash;
  }
}