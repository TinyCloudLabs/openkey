/**
 * OAuth Client Registration Script
 *
 * Use this script to register OAuth clients for third-party applications.
 * Since OpenKey uses pre-registered clients only (no dynamic registration),
 * this script is the primary way to add new OAuth clients.
 *
 * Usage:
 *   DATABASE_URL=<your-db-url> bun run packages/db/prisma/seed-oauth-clients.ts
 *
 * The script will output the client_id and client_secret.
 * Store the client_secret securely - it cannot be retrieved again.
 */

import { PrismaClient } from '@prisma/client';
import { createHash, randomBytes } from 'crypto';

const prisma = new PrismaClient();

interface ClientConfig {
  /** Display name for the application */
  name: string;
  /** Allowed redirect URIs (must include all environments) */
  redirectUris: string[];
  /** Application type */
  type?: 'web' | 'native' | 'spa';
  /** Application website URL */
  uri?: string;
  /** Application logo URL */
  icon?: string;
}

function generateId(): string {
  return randomBytes(16).toString('hex');
}

function generateClientId(): string {
  return `ok_${randomBytes(16).toString('hex')}`;
}

function generateClientSecret(): string {
  return `oks_${randomBytes(32).toString('hex')}`;
}

function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

async function registerClient(config: ClientConfig) {
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const hashedSecret = hashSecret(clientSecret);

  const client = await prisma.oAuthClient.create({
    data: {
      id: generateId(),
      clientId,
      clientSecret: hashedSecret,
      name: config.name,
      uri: config.uri || null,
      icon: config.icon || null,
      redirectUris: config.redirectUris,
      scopes: ['openid'], // Only openid scope for OpenKey
      disabled: false,
      skipConsent: false, // ALWAYS require consent
      enableEndSession: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      type: config.type || 'web',
      public: false,
      contacts: [],
    },
  });

  console.log('\n========================================');
  console.log(`OAuth Client Registered: ${config.name}`);
  console.log('========================================');
  console.log(`Client ID:     ${clientId}`);
  console.log(`Client Secret: ${clientSecret}`);
  console.log(`Redirect URIs: ${config.redirectUris.join(', ')}`);
  console.log('----------------------------------------');
  console.log('IMPORTANT: Store the client secret securely!');
  console.log('It is hashed in the database and cannot be retrieved.');
  console.log('========================================\n');

  return { clientId, clientSecret, id: client.id };
}

async function listClients() {
  const clients = await prisma.oAuthClient.findMany({
    select: {
      id: true,
      clientId: true,
      name: true,
      uri: true,
      redirectUris: true,
      disabled: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  console.log('\n========================================');
  console.log('Registered OAuth Clients');
  console.log('========================================');

  if (clients.length === 0) {
    console.log('No clients registered yet.');
  } else {
    for (const client of clients) {
      console.log(`\nName: ${client.name}`);
      console.log(`  Client ID: ${client.clientId}`);
      console.log(`  URI: ${client.uri || '(none)'}`);
      console.log(`  Redirect URIs: ${client.redirectUris.join(', ')}`);
      console.log(`  Status: ${client.disabled ? 'DISABLED' : 'Active'}`);
      console.log(`  Created: ${client.createdAt.toISOString()}`);
    }
  }

  console.log('\n========================================\n');
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (command === 'list') {
    await listClients();
    return;
  }

  if (command === 'register') {
    // Register OpenKey Demo app
    await registerClient({
      name: 'OpenKey Demo',
      redirectUris: [
        'http://localhost:5174/callback', // Local development
      ],
      type: 'web',
      uri: 'http://localhost:5174',
    });
    return;
  }

  // Show usage
  console.log(`
OAuth Client Registration Script

Usage:
  bun run packages/db/prisma/seed-oauth-clients.ts <command>

Commands:
  list      List all registered OAuth clients
  register  Register a new OAuth client (edit script to configure)

Environment:
  DATABASE_URL  PostgreSQL connection string (required)

Example:
  DATABASE_URL=postgresql://... bun run packages/db/prisma/seed-oauth-clients.ts register
`);
}

main()
  .catch((e) => {
    console.error('Error:', e.message);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
