import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import { prisma } from '../index';
import { logger } from '../utils/logger';

const rpName = process.env.WEBAUTHN_RP_NAME || 'OpenKey';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
const origin = process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000';

export class WebAuthnService {
  /**
   * Generate registration options for a new user
   */
  static async generateRegistrationOptions(email: string) {
    const user = await prisma.user.findUnique({
      where: { email },
      include: { credentials: true }
    });

    // Get existing credentials for this user (if any)
    const existingCredentials = user?.credentials.map(cred => ({
      id: cred.credentialId,
      type: 'public-key' as const,
      transports: cred.transports as any,
    })) || [];

    const options: GenerateRegistrationOptionsOpts = {
      rpName,
      rpID,
      userID: user?.id || email, // Use existing user ID or email for new users
      userName: email,
      userDisplayName: email,
      timeout: parseInt(process.env.WEBAUTHN_CHALLENGE_TIMEOUT || '60000'),
      attestationType: 'none',
      excludeCredentials: existingCredentials,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform',
      },
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
    };

    const registrationOptions = await generateRegistrationOptions(options);

    logger.info('Generated registration options', {
      email,
      challenge: registrationOptions.challenge.slice(0, 10) + '...',
    });

    return registrationOptions;
  }

  /**
   * Verify registration response and create credential
   */
  static async verifyRegistration(
    email: string,
    credential: any,
    expectedChallenge: string
  ) {
    const verification: VerifyRegistrationResponseOpts = {
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };

    const verificationResult = await verifyRegistrationResponse(verification);

    if (!verificationResult.verified || !verificationResult.registrationInfo) {
      throw new Error('Registration verification failed');
    }

    const { credentialID, credentialPublicKey, counter } = verificationResult.registrationInfo;

    // Find or create user
    let user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      user = await prisma.user.create({
        data: { email }
      });
      logger.info('Created new user', { userId: user.id, email });
    }

    // Store the credential
    const newCredential = await prisma.credential.create({
      data: {
        userId: user.id,
        credentialId: Buffer.from(credentialID).toString('base64'),
        publicKey: Buffer.from(credentialPublicKey),
        counter: BigInt(counter),
        transports: credential.response.transports || [],
      }
    });

    logger.info('Stored new credential', {
      userId: user.id,
      credentialId: newCredential.id,
    });

    return { user, credential: newCredential };
  }

  /**
   * Generate authentication options for existing user
   */
  static async generateAuthenticationOptions(email?: string) {
    let allowCredentials: any[] = [];

    if (email) {
      const user = await prisma.user.findUnique({
        where: { email },
        include: { credentials: true }
      });

      if (user) {
        allowCredentials = user.credentials.map(cred => ({
          id: Buffer.from(cred.credentialId, 'base64'),
          type: 'public-key' as const,
          transports: cred.transports as any,
        }));
      }
    }

    const options: GenerateAuthenticationOptionsOpts = {
      rpID,
      timeout: parseInt(process.env.WEBAUTHN_CHALLENGE_TIMEOUT || '60000'),
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
      userVerification: 'preferred',
    };

    const authenticationOptions = await generateAuthenticationOptions(options);

    logger.info('Generated authentication options', {
      email,
      credentialCount: allowCredentials.length,
      challenge: authenticationOptions.challenge.slice(0, 10) + '...',
    });

    return authenticationOptions;
  }

  /**
   * Verify authentication response
   */
  static async verifyAuthentication(
    credential: any,
    expectedChallenge: string
  ) {
    const credentialId = Buffer.from(credential.id, 'base64').toString('base64');
    
    // Find the credential in database
    const dbCredential = await prisma.credential.findUnique({
      where: { credentialId },
      include: { user: true }
    });

    if (!dbCredential) {
      throw new Error('Credential not found');
    }

    const verification: VerifyAuthenticationResponseOpts = {
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(dbCredential.credentialId, 'base64'),
        credentialPublicKey: dbCredential.publicKey,
        counter: Number(dbCredential.counter),
        transports: dbCredential.transports as any,
      },
      requireUserVerification: true,
    };

    const verificationResult = await verifyAuthenticationResponse(verification);

    if (!verificationResult.verified) {
      throw new Error('Authentication verification failed');
    }

    // Update counter
    await prisma.credential.update({
      where: { id: dbCredential.id },
      data: { counter: BigInt(verificationResult.authenticationInfo.newCounter) }
    });

    logger.info('Authentication successful', {
      userId: dbCredential.user.id,
      credentialId: dbCredential.id,
    });

    return dbCredential.user;
  }
}