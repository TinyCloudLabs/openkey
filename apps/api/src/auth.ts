// OpenKey API - better-auth configuration
// Auth Flow: Email OTP OR Google → Passkey creation (required) → Passkey login
import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { passkey } from '@better-auth/passkey';
import { emailOTP, jwt } from 'better-auth/plugins';
import { oauthProvider } from '@better-auth/oauth-provider';
import { Resend } from 'resend';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Initialize Resend for email OTP
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

// Environment-based configuration
const isDev = process.env.NODE_ENV !== 'production';
const rpID = process.env.WEBAUTHN_RP_ID || (isDev ? 'localhost' : 'openkey.so');
const origin = process.env.WEBAUTHN_ORIGIN || (isDev ? 'http://localhost:5173' : 'https://openkey.so');

// Base URL for proper request context
const baseURL = process.env.BETTER_AUTH_URL || (isDev ? 'http://localhost:3001' : 'https://api.openkey.so');

export const auth = betterAuth({
  baseURL,
  basePath: '/api/auth',
  disabledPaths: ['/token'], // Avoid conflicts with OAuth token endpoint

  database: prismaAdapter(prisma, {
    provider: 'postgresql',
  }),

  // Disable email/password - we're passkey-first
  emailAndPassword: {
    enabled: false,
  },

  // Session configuration
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // Update session every 24 hours
    storeSessionInDatabase: true, // Required for OAuth provider
  },

  plugins: [
    // Passkey authentication (required for login after initial registration)
    passkey({
      rpID,
      rpName: 'OpenKey',
      origin,
    }),

    // Email OTP for initial registration verification
    emailOTP({
      async sendVerificationOTP({ email, otp, type }) {
        if (!resend) {
          console.log(`[DEV] OTP for ${email}: ${otp} (type: ${type})`);
          return;
        }

        await resend.emails.send({
          from: 'OpenKey <noreply@openkey.so>',
          to: email,
          subject: 'Verify your OpenKey email',
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #1a1a1a; margin-bottom: 24px;">Your verification code</h2>
              <p style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; margin: 32px 0; text-align: center;">${otp}</p>
              <p style="color: #666; font-size: 14px;">This code expires in 5 minutes.</p>
              <p style="color: #888; font-size: 12px; margin-top: 24px;">If you didn't request this, you can safely ignore this email.</p>
            </div>
          `,
        });
      },
      otpLength: 6,
      expiresIn: 300, // 5 minutes
    }),

    // JWT plugin (required for OAuth provider)
    jwt(),

    // OAuth 2.1 Provider - enables third-party apps to authenticate users
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    oauthProvider({
      loginPage: isDev ? 'http://localhost:5173/auth/login' : 'https://openkey.so/auth/login',
      consentPage: isDev ? 'http://localhost:5173/oauth/consent' : 'https://openkey.so/oauth/consent',
      allowDynamicClientRegistration: false, // Pre-registered clients only
      scopes: ['openid'], // Minimal identity verification
      accessTokenExpiresIn: 60 * 60, // 1 hour in seconds
      refreshTokenExpiresIn: 60 * 60 * 24 * 7, // 7 days in seconds
      idTokenExpiresIn: 60 * 60, // 1 hour in seconds
      disableJwtPlugin: true, // Workaround for ctx.getPlugin issue
    }) as any,
  ],

  // Social providers (Google as alternative to email OTP for registration)
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    },
  },

  // Trust proxy for production (dstack gateway)
  trustedOrigins: [origin],
});

// Export auth type for client
export type Auth = typeof auth;
