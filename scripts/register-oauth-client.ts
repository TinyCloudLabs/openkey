#!/usr/bin/env bun
/**
 * OAuth Client Registration CLI
 *
 * Register OAuth clients for third-party applications to use OpenKey as an identity provider.
 *
 * Usage:
 *   bun run scripts/register-oauth-client.ts --name "App Name" --redirect-uri "https://app.com/callback"
 *
 * Options:
 *   --name, -n          Application name (required)
 *   --redirect-uri, -r  Redirect URI (required, can be specified multiple times)
 *   --uri, -u           Application website URL
 *   --icon, -i          Application icon URL
 *   --type, -t          Application type: web, native, spa (default: web)
 *   --list, -l          List all registered clients
 *   --help, -h          Show help
 *
 * Environment:
 *   DATABASE_URL        PostgreSQL connection string (required)
 *
 * Examples:
 *   # Register a web app
 *   bun run scripts/register-oauth-client.ts \
 *     --name "My App" \
 *     --redirect-uri "https://myapp.com/callback" \
 *     --redirect-uri "http://localhost:3000/callback"
 *
 *   # List all clients
 *   bun run scripts/register-oauth-client.ts --list
 */

import { PrismaClient } from '@prisma/client';
import { createHash, randomBytes } from 'crypto';
import { parseArgs } from 'util';

const prisma = new PrismaClient();

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

async function registerClient(options: {
  name: string;
  redirectUris: string[];
  uri?: string;
  icon?: string;
  type?: 'web' | 'native' | 'spa';
}) {
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const hashedSecret = hashSecret(clientSecret);

  await prisma.oAuthClient.create({
    data: {
      id: generateId(),
      clientId,
      clientSecret: hashedSecret,
      name: options.name,
      uri: options.uri || null,
      icon: options.icon || null,
      redirectUris: options.redirectUris,
      scopes: ['openid'],
      disabled: false,
      skipConsent: false,
      enableEndSession: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      type: options.type || 'web',
      public: false,
      contacts: [],
    },
  });

  console.log('\n========================================');
  console.log(`OAuth Client Registered: ${options.name}`);
  console.log('========================================');
  console.log(`Client ID:     ${clientId}`);
  console.log(`Client Secret: ${clientSecret}`);
  console.log(`Redirect URIs: ${options.redirectUris.join(', ')}`);
  console.log('----------------------------------------');
  console.log('IMPORTANT: Store the client secret securely!');
  console.log('It is hashed in the database and cannot be retrieved.');
  console.log('========================================\n');

  return { clientId, clientSecret };
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

function showHelp() {
  console.log(`
OAuth Client Registration CLI

Usage:
  bun run scripts/register-oauth-client.ts [options]

Options:
  --name, -n          Application name (required for registration)
  --redirect-uri, -r  Redirect URI (required, can specify multiple)
  --uri, -u           Application website URL
  --icon, -i          Application icon URL
  --type, -t          Application type: web, native, spa (default: web)
  --list, -l          List all registered clients
  --help, -h          Show this help

Environment:
  DATABASE_URL        PostgreSQL connection string (required)

Examples:
  # Register a new OAuth client
  bun run scripts/register-oauth-client.ts \\
    --name "Remember" \\
    --redirect-uri "https://remember.app/callback" \\
    --redirect-uri "http://localhost:3000/callback" \\
    --uri "https://remember.app"

  # List all registered clients
  bun run scripts/register-oauth-client.ts --list
`);
}

async function main() {
  const { values } = parseArgs({
    options: {
      name: { type: 'string', short: 'n' },
      'redirect-uri': { type: 'string', short: 'r', multiple: true },
      uri: { type: 'string', short: 'u' },
      icon: { type: 'string', short: 'i' },
      type: { type: 'string', short: 't' },
      list: { type: 'boolean', short: 'l' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: false,
  });

  if (values.help) {
    showHelp();
    return;
  }

  if (values.list) {
    await listClients();
    return;
  }

  // Registration mode
  if (!values.name) {
    console.error('Error: --name is required');
    console.log('Run with --help for usage information');
    process.exit(1);
  }

  const redirectUris = values['redirect-uri'];
  if (!redirectUris || redirectUris.length === 0) {
    console.error('Error: At least one --redirect-uri is required');
    console.log('Run with --help for usage information');
    process.exit(1);
  }

  const validTypes = ['web', 'native', 'spa'];
  const type = (values.type as 'web' | 'native' | 'spa') || 'web';
  if (values.type && !validTypes.includes(values.type)) {
    console.error(`Error: --type must be one of: ${validTypes.join(', ')}`);
    process.exit(1);
  }

  await registerClient({
    name: values.name,
    redirectUris,
    uri: values.uri,
    icon: values.icon,
    type,
  });
}

main()
  .catch((e) => {
    console.error('Error:', e.message);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
