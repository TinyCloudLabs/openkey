import { Router, Response, NextFunction } from 'express';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { CryptoUtils } from '../utils/crypto';
import { ValidationError, NotFoundError } from '../middleware/errorHandler';
import { prisma } from '../index';
import { logger } from '../utils/logger';
import { ethers } from 'ethers';

const router = Router();

// All routes require authentication
router.use(authenticateToken);

/**
 * POST /api/keys/generate
 * Generate a new Ethereum key for the user
 */
router.post('/generate', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;

    // Check if user already has an active key
    const existingKey = await prisma.ethereumKey.findFirst({
      where: {
        userId,
        isActive: true
      }
    });

    if (existingKey) {
      return res.json({
        success: true,
        address: existingKey.address,
        keyId: existingKey.id,
        message: 'Using existing active key'
      });
    }

    // Generate new Ethereum key pair
    const { privateKey, address } = CryptoUtils.generateEthereumKey();
    
    // Encrypt the private key
    const encryptedKey = CryptoUtils.encryptPrivateKey(privateKey);

    // Store in database
    const ethereumKey = await prisma.ethereumKey.create({
      data: {
        userId,
        address,
        encryptedKey,
        keyIndex: 0, // Could be used for HD wallet derivation in the future
        isActive: true
      }
    });

    logger.info('Generated new Ethereum key', {
      userId,
      address,
      keyId: ethereumKey.id
    });

    res.json({
      success: true,
      address: ethereumKey.address,
      keyId: ethereumKey.id
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/keys/sign
 * Sign a message with user's Ethereum key
 */
router.post('/sign', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;
    const { message, keyId } = req.body;

    if (!message || typeof message !== 'string') {
      throw new ValidationError('Message is required and must be a string');
    }

    // Find the key
    let ethereumKey;
    if (keyId) {
      ethereumKey = await prisma.ethereumKey.findFirst({
        where: {
          id: keyId,
          userId,
          isActive: true
        }
      });
    } else {
      // Use the user's active key if no keyId specified
      ethereumKey = await prisma.ethereumKey.findFirst({
        where: {
          userId,
          isActive: true
        }
      });
    }

    if (!ethereumKey) {
      throw new NotFoundError('No active Ethereum key found');
    }

    // Decrypt the private key
    const privateKey = CryptoUtils.decryptPrivateKey(ethereumKey.encryptedKey);

    // Sign the message
    const signature = await CryptoUtils.signMessage(privateKey, message);

    logger.info('Message signed successfully', {
      userId,
      address: ethereumKey.address,
      keyId: ethereumKey.id,
      messageLength: message.length
    });

    res.json({
      success: true,
      signature,
      address: ethereumKey.address,
      message: 'Message signed successfully'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/keys/sign-transaction
 * Sign an Ethereum transaction with user's key
 */
router.post('/sign-transaction', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;
    const { transaction, keyId } = req.body;

    if (!transaction || typeof transaction !== 'object') {
      throw new ValidationError('Transaction object is required');
    }

    // Validate transaction structure
    if (!transaction.to || !transaction.value) {
      throw new ValidationError('Transaction must include "to" and "value" fields');
    }

    // Find the key
    const ethereumKey = await prisma.ethereumKey.findFirst({
      where: {
        id: keyId || undefined,
        userId,
        isActive: true
      }
    });

    if (!ethereumKey) {
      throw new NotFoundError('No active Ethereum key found');
    }

    // Decrypt the private key
    const privateKey = CryptoUtils.decryptPrivateKey(ethereumKey.encryptedKey);

    // Prepare transaction object
    const txRequest: ethers.TransactionRequest = {
      to: transaction.to,
      value: ethers.parseEther(transaction.value.toString()),
      data: transaction.data || '0x',
      gasLimit: transaction.gasLimit ? BigInt(transaction.gasLimit) : undefined,
      gasPrice: transaction.gasPrice ? BigInt(transaction.gasPrice) : undefined,
    };

    // Sign the transaction
    const signedTransaction = await CryptoUtils.signTransaction(privateKey, txRequest);
    
    // Calculate transaction hash
    const hash = ethers.keccak256(signedTransaction);

    logger.info('Transaction signed successfully', {
      userId,
      address: ethereumKey.address,
      keyId: ethereumKey.id,
      to: transaction.to,
      value: transaction.value,
      hash
    });

    res.json({
      success: true,
      signedTransaction,
      hash,
      address: ethereumKey.address
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/keys/list
 * List all Ethereum keys for the user
 */
router.get('/list', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;

    const keys = await prisma.ethereumKey.findMany({
      where: { userId },
      select: {
        id: true,
        address: true,
        keyIndex: true,
        isActive: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      success: true,
      keys
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/keys/:keyId/activate
 * Activate a specific Ethereum key
 */
router.put('/:keyId/activate', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;
    const { keyId } = req.params;

    // Verify the key belongs to the user
    const key = await prisma.ethereumKey.findFirst({
      where: {
        id: keyId,
        userId
      }
    });

    if (!key) {
      throw new NotFoundError('Key not found');
    }

    // Deactivate all other keys and activate this one
    await prisma.$transaction([
      prisma.ethereumKey.updateMany({
        where: { userId },
        data: { isActive: false }
      }),
      prisma.ethereumKey.update({
        where: { id: keyId },
        data: { isActive: true }
      })
    ]);

    logger.info('Ethereum key activated', {
      userId,
      keyId,
      address: key.address
    });

    res.json({
      success: true,
      message: 'Key activated successfully'
    });
  } catch (error) {
    next(error);
  }
});

export default router;