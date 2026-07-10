#!/usr/bin/env bun
/**
 * CI OAuth Client Registration
 *
 * Registers a public (PKCE-only) OAuth client directly in the database.
 * Meant to run from the register-oauth-client GitHub Actions workflow, where
 * DATABASE_URL comes from the repo secret (same one the deploy workflow's
 * schema-sync step uses). Mirrors the row shape written by
 * apps/api/src/routes/oauth-admin.ts POST /clients.
 *
 * Env:
 *   DATABASE_URL          Postgres connection string (required)
 *   CLIENT_NAME           Display name (required)
 *   CLIENT_REDIRECT_URIS  Comma-separated redirect URIs (required)
 *   CLIENT_TYPE           "native" | "spa" (default "spa")
 *   CLIENT_URI            Application website URL (optional)
 *
 * Idempotent: if an active client with the same name already exists, it is
 * printed and no new client is created.
 */

import { createPrismaClient } from '../packages/db/src/index';
import { randomBytes } from 'crypto';

const prisma = createPrismaClient();

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    console.error(`Error: ${name} is required`);
    process.exit(1);
  }
  return value;
}

async function main() {
  required('DATABASE_URL');
  const name = required('CLIENT_NAME');
  const redirectUris = required('CLIENT_REDIRECT_URIS')
    .split(',')
    .map((uri) => uri.trim())
    .filter(Boolean);
  const type = process.env.CLIENT_TYPE?.trim() || 'spa';
  const uri = process.env.CLIENT_URI?.trim() || null;

  if (!['native', 'spa'].includes(type)) {
    console.error(`Error: CLIENT_TYPE must be native or spa, got: ${type}`);
    process.exit(1);
  }
  for (const redirectUri of redirectUris) {
    try {
      new URL(redirectUri);
    } catch {
      console.error(`Error: invalid redirect URI: ${redirectUri}`);
      process.exit(1);
    }
  }

  const existing = await prisma.oauthClient.findFirst({
    where: { name, disabled: false },
  });
  if (existing) {
    console.log(`Client "${name}" already exists — not creating a duplicate.`);
    console.log(`CLIENT_ID=${existing.clientId}`);
    console.log(`REDIRECT_URIS=${existing.redirectUris.join(',')}`);
    return;
  }

  const clientId = `ok_${randomBytes(16).toString('hex')}`;
  await prisma.oauthClient.create({
    data: {
      id: randomBytes(16).toString('hex'),
      clientId,
      clientSecret: null,
      name,
      uri,
      icon: null,
      redirectUris,
      scopes: ['openid', 'email', 'keys', 'offline_access'],
      disabled: false,
      skipConsent: false,
      enableEndSession: false,
      tokenEndpointAuthMethod: 'none',
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      type,
      public: true,
      contacts: [],
    },
  });

  console.log(`OAuth client registered: ${name}`);
  console.log(`CLIENT_ID=${clientId}`);
  console.log(`REDIRECT_URIS=${redirectUris.join(',')}`);
  console.log('Public PKCE-only client (no client secret).');
}

main()
  .catch((e) => {
    console.error('Error:', e.message);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
