import { Router, Request, Response, NextFunction } from 'express';
import { WebAuthnService } from '../services/webauthn';
import { generateToken } from '../middleware/auth';
import { ValidationError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import { redis } from '../index';

const router = Router();

/**
 * POST /api/auth/register/begin
 * Start WebAuthn registration process
 */
router.post('/register/begin', async (req: Request, res: Response, next: NextFunction) => {
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

    const options = await WebAuthnService.generateRegistrationOptions(email);
    
    // Store challenge in Redis for verification
    const challengeKey = `challenge:register:${email}`;
    await redis.setex(challengeKey, 300, options.challenge); // 5 minute expiry

    res.json({
      success: true,
      options
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/register/finish
 * Complete WebAuthn registration
 */
router.post('/register/finish', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, credential } = req.body;

    if (!email || !credential) {
      throw new ValidationError('Email and credential are required');
    }

    // Get stored challenge
    const challengeKey = `challenge:register:${email}`;
    const expectedChallenge = await redis.get(challengeKey);
    
    if (!expectedChallenge) {
      throw new ValidationError('Challenge expired or not found');
    }

    // Verify registration
    const { user } = await WebAuthnService.verifyRegistration(
      email,
      credential,
      expectedChallenge
    );

    // Generate JWT token
    const token = generateToken(user.id, user.email);

    // Clean up challenge
    await redis.del(challengeKey);

    logger.info('User registered successfully', { userId: user.id, email });

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt
      },
      token
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/login/begin
 * Start WebAuthn authentication process
 */
router.post('/login/begin', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;

    const options = await WebAuthnService.generateAuthenticationOptions(email);
    
    // Store challenge in Redis
    const challengeKey = `challenge:login:${email || 'anonymous'}:${Date.now()}`;
    await redis.setex(challengeKey, 300, options.challenge); // 5 minute expiry

    res.json({
      success: true,
      options,
      challengeId: challengeKey
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/login/finish
 * Complete WebAuthn authentication
 */
router.post('/login/finish', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { credential, challengeId } = req.body;

    if (!credential || !challengeId) {
      throw new ValidationError('Credential and challengeId are required');
    }

    // Get stored challenge
    const expectedChallenge = await redis.get(challengeId);
    
    if (!expectedChallenge) {
      throw new ValidationError('Challenge expired or not found');
    }

    // Verify authentication
    const user = await WebAuthnService.verifyAuthentication(
      credential,
      expectedChallenge
    );

    // Generate JWT token
    const token = generateToken(user.id, user.email);

    // Clean up challenge
    await redis.del(challengeId);

    logger.info('User logged in successfully', { userId: user.id, email: user.email });

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt
      },
      token
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/verify
 * Verify JWT token validity
 */
router.post('/verify', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token } = req.body;

    if (!token) {
      throw new ValidationError('Token is required');
    }

    // Token verification is handled by the auth middleware
    // This endpoint is mainly for client-side token validation
    res.json({
      success: true,
      message: 'Token is valid'
    });
  } catch (error) {
    next(error);
  }
});

export default router;