import { Router, Response, NextFunction } from 'express';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { prisma } from '../index';

const router = Router();

// All routes require authentication
router.use(authenticateToken);

/**
 * GET /api/user/profile
 * Get user profile information
 */
router.get('/profile', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true
      }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.json({
      success: true,
      user
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/user/devices
 * Get user's registered devices (WebAuthn credentials)
 */
router.get('/devices', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;

    const credentials = await prisma.credential.findMany({
      where: { userId },
      select: {
        id: true,
        credentialId: true,
        transports: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { createdAt: 'desc' }
    });

    // Transform credentials for frontend display
    const devices = credentials.map((cred, index) => ({
      id: cred.id,
      name: `Device ${index + 1}`, // In a real app, you might let users name their devices
      type: cred.transports.includes('internal') ? 'Platform Authenticator' : 'Cross-Platform Authenticator',
      transports: cred.transports,
      registeredAt: cred.createdAt,
      lastUsed: cred.updatedAt
    }));

    res.json({
      success: true,
      devices
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/user/keys
 * Get user's Ethereum keys
 */
router.get('/keys', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
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
 * GET /api/user/stats
 * Get user statistics
 */
router.get('/stats', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;

    const [credentialCount, keyCount, recoveryTokenCount] = await Promise.all([
      prisma.credential.count({ where: { userId } }),
      prisma.ethereumKey.count({ where: { userId } }),
      prisma.recoveryToken.count({ where: { userId, used: false } })
    ]);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { createdAt: true }
    });

    res.json({
      success: true,
      stats: {
        devicesRegistered: credentialCount,
        ethereumKeys: keyCount,
        activeRecoveryTokens: recoveryTokenCount,
        accountAge: user ? Math.floor((Date.now() - user.createdAt.getTime()) / (1000 * 60 * 60 * 24)) : 0 // days
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/user/devices/:credentialId
 * Remove a WebAuthn credential
 */
router.delete('/devices/:credentialId', async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;
    const { credentialId } = req.params;

    // Check if credential belongs to user
    const credential = await prisma.credential.findFirst({
      where: {
        id: credentialId,
        userId
      }
    });

    if (!credential) {
      return res.status(404).json({
        success: false,
        error: 'Device not found'
      });
    }

    // Don't allow deleting the last credential
    const credentialCount = await prisma.credential.count({
      where: { userId }
    });

    if (credentialCount <= 1) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete the last authentication device'
      });
    }

    // Delete the credential
    await prisma.credential.delete({
      where: { id: credentialId }
    });

    res.json({
      success: true,
      message: 'Device removed successfully'
    });
  } catch (error) {
    next(error);
  }
});

export default router;