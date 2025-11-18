import { Router, Request, Response, NextFunction } from 'express';
import { ValidationError, NotFoundError } from '../middleware/errorHandler';
import { CryptoUtils } from '../utils/crypto';
import { prisma } from '../index';
import { logger } from '../utils/logger';
import nodemailer from 'nodemailer';

const router = Router();

// Email transporter configuration
const createEmailTransporter = () => {
  return nodemailer.createTransporter({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  });
};

/**
 * POST /api/recovery/initiate
 * Initiate email-based account recovery
 */
router.post('/initiate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;

    if (!email || typeof email !== 'string') {
      throw new ValidationError('Email is required');
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new ValidationError('Invalid email format');
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      // Don't reveal if user exists or not for security
      return res.json({
        success: true,
        message: 'If an account with this email exists, a recovery link has been sent.'
      });
    }

    // Generate recovery token
    const token = CryptoUtils.generateRecoveryToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store recovery token
    await prisma.recoveryToken.create({
      data: {
        userId: user.id,
        token,
        type: 'email',
        expiresAt,
      }
    });

    // Send recovery email (only if email is configured)
    if (process.env.ENABLE_EMAIL_RECOVERY === 'true' && process.env.SMTP_HOST) {
      try {
        const transporter = createEmailTransporter();
        const recoveryUrl = `${process.env.FRONTEND_URL}/recovery?token=${token}`;

        await transporter.sendMail({
          from: process.env.EMAIL_FROM || 'noreply@openkey.local',
          to: email,
          subject: 'OpenKey Account Recovery',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2>Account Recovery Request</h2>
              <p>You have requested to recover your OpenKey account. Click the link below to proceed:</p>
              <p style="margin: 20px 0;">
                <a href="${recoveryUrl}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                  Recover Account
                </a>
              </p>
              <p><strong>This link will expire in 24 hours.</strong></p>
              <p>If you didn't request this recovery, please ignore this email.</p>
              <hr>
              <p style="color: #666; font-size: 12px;">
                This is an automated message from OpenKey. Please do not reply to this email.
              </p>
            </div>
          `
        });

        logger.info('Recovery email sent', { 
          userId: user.id, 
          email,
          tokenId: token.slice(0, 8) + '...'
        });
      } catch (emailError) {
        logger.error('Failed to send recovery email', { 
          error: emailError,
          userId: user.id,
          email 
        });
        // Don't fail the entire request if email fails
      }
    }

    res.json({
      success: true,
      message: 'If an account with this email exists, a recovery link has been sent.',
      ...(process.env.NODE_ENV === 'development' && { 
        recoveryToken: token // Only include in development
      })
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/recovery/verify
 * Verify recovery token and get user info
 */
router.post('/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.body;

    if (!token || typeof token !== 'string') {
      throw new ValidationError('Recovery token is required');
    }

    // Find valid recovery token
    const recoveryToken = await prisma.recoveryToken.findFirst({
      where: {
        token,
        used: false,
        expiresAt: {
          gte: new Date()
        }
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            createdAt: true
          }
        }
      }
    });

    if (!recoveryToken) {
      throw new NotFoundError('Invalid or expired recovery token');
    }

    res.json({
      success: true,
      user: recoveryToken.user,
      message: 'Recovery token is valid'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/recovery/complete
 * Complete account recovery process
 */
router.post('/complete', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token, newCredential } = req.body;

    if (!token || !newCredential) {
      throw new ValidationError('Recovery token and new credential are required');
    }

    // Find and validate recovery token
    const recoveryToken = await prisma.recoveryToken.findFirst({
      where: {
        token,
        used: false,
        expiresAt: {
          gte: new Date()
        }
      },
      include: {
        user: true
      }
    });

    if (!recoveryToken) {
      throw new NotFoundError('Invalid or expired recovery token');
    }

    // In a real implementation, you would:
    // 1. Verify the new WebAuthn credential
    // 2. Replace or add the new credential
    // 3. Optionally deactivate old credentials
    
    // For this demo, we'll just mark the token as used
    await prisma.recoveryToken.update({
      where: { id: recoveryToken.id },
      data: { used: true }
    });

    logger.info('Account recovery completed', {
      userId: recoveryToken.user.id,
      email: recoveryToken.user.email,
      tokenId: token.slice(0, 8) + '...'
    });

    res.json({
      success: true,
      message: 'Account recovery completed successfully',
      user: {
        id: recoveryToken.user.id,
        email: recoveryToken.user.email,
        createdAt: recoveryToken.user.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/recovery/status/:token
 * Check recovery token status
 */
router.get('/status/:token', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.params;

    const recoveryToken = await prisma.recoveryToken.findFirst({
      where: { token },
      select: {
        id: true,
        used: true,
        expiresAt: true,
        createdAt: true
      }
    });

    if (!recoveryToken) {
      throw new NotFoundError('Recovery token not found');
    }

    const isExpired = recoveryToken.expiresAt < new Date();
    const isValid = !recoveryToken.used && !isExpired;

    res.json({
      success: true,
      status: {
        valid: isValid,
        used: recoveryToken.used,
        expired: isExpired,
        expiresAt: recoveryToken.expiresAt,
        createdAt: recoveryToken.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
});

export default router;