#!/usr/bin/env bun
/**
 * OAuth Client Registration CLI
 *
 * Register OAuth clients via the OpenKey API.
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
 *   --delete, -d        Delete a client by client ID
 *   --help, -h          Show help
 *
 * Environment:
 *   OPENKEY_API_URL     OpenKey API URL (default: http://localhost:3001)
 *   ADMIN_API_KEY       Admin API key (required)
 *
 * Examples:
 *   # Register a web app
 *   ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts \
 *     --name "My App" \
 *     --redirect-uri "https://myapp.com/callback" \
 *     --redirect-uri "http://localhost:3000/callback"
 *
 *   # List all clients
 *   ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts --list
 *
 *   # Delete a client
 *   ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts --delete ok_abc123
 */

import { parseArgs } from 'util';

const API_URL = process.env.OPENKEY_API_URL || 'http://localhost:3001';
const ADMIN_KEY = process.env.ADMIN_API_KEY;

async function apiRequest(method: string, path: string, body?: object) {
  if (!ADMIN_KEY) {
    console.error('Error: ADMIN_API_KEY environment variable is required');
    process.exit(1);
  }

  const response = await fetch(`${API_URL}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${ADMIN_KEY}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || `API error: ${response.status}`);
  }

  return data;
}

async function registerClient(options: {
  name: string;
  redirectUris: string[];
  uri?: string;
  icon?: string;
  type?: string;
}) {
  const data = await apiRequest('POST', '/api/admin/oauth/clients', {
    name: options.name,
    redirectUris: options.redirectUris,
    uri: options.uri,
    icon: options.icon,
    type: options.type || 'web',
  });

  const { client } = data;

  console.log('\n========================================');
  console.log(`OAuth Client Registered: ${client.name}`);
  console.log('========================================');
  console.log(`Client ID:     ${client.clientId}`);
  console.log(`Client Secret: ${client.clientSecret}`);
  console.log(`Redirect URIs: ${client.redirectUris.join(', ')}`);
  console.log('----------------------------------------');
  console.log('IMPORTANT: Store the client secret securely!');
  console.log('It is hashed in the database and cannot be retrieved.');
  console.log('========================================\n');
}

async function listClients() {
  const data = await apiRequest('GET', '/api/admin/oauth/clients');

  console.log('\n========================================');
  console.log('Registered OAuth Clients');
  console.log('========================================');

  if (data.clients.length === 0) {
    console.log('No clients registered yet.');
  } else {
    for (const client of data.clients) {
      console.log(`\nName: ${client.name}`);
      console.log(`  Client ID: ${client.clientId}`);
      console.log(`  URI: ${client.uri || '(none)'}`);
      console.log(`  Redirect URIs: ${client.redirectUris.join(', ')}`);
      console.log(`  Status: ${client.disabled ? 'DISABLED' : 'Active'}`);
      console.log(`  Created: ${client.createdAt}`);
    }
  }

  console.log('\n========================================\n');
}

async function deleteClient(clientId: string) {
  await apiRequest('DELETE', `/api/admin/oauth/clients/${clientId}`);
  console.log(`\nClient ${clientId} deleted successfully.\n`);
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
  --delete, -d        Delete a client by client ID
  --help, -h          Show this help

Environment:
  OPENKEY_API_URL     OpenKey API URL (default: http://localhost:3001)
  ADMIN_API_KEY       Admin API key (required)

Examples:
  # Register a new OAuth client
  ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts \\
    --name "Remember" \\
    --redirect-uri "https://remember.app/callback" \\
    --redirect-uri "http://localhost:3000/callback" \\
    --uri "https://remember.app"

  # List all registered clients
  ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts --list

  # Delete a client
  ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts --delete ok_abc123

  # Use production API
  OPENKEY_API_URL=https://api.openkey.so ADMIN_API_KEY=secret bun run scripts/register-oauth-client.ts --list
`);
}

async function main() {
  const { values, positionals } = parseArgs({
    options: {
      name: { type: 'string', short: 'n' },
      'redirect-uri': { type: 'string', short: 'r', multiple: true },
      uri: { type: 'string', short: 'u' },
      icon: { type: 'string', short: 'i' },
      type: { type: 'string', short: 't' },
      list: { type: 'boolean', short: 'l' },
      delete: { type: 'string', short: 'd' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });

  if (values.help) {
    showHelp();
    return;
  }

  if (values.list) {
    await listClients();
    return;
  }

  if (values.delete) {
    await deleteClient(values.delete);
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
  if (values.type && !validTypes.includes(values.type)) {
    console.error(`Error: --type must be one of: ${validTypes.join(', ')}`);
    process.exit(1);
  }

  await registerClient({
    name: values.name,
    redirectUris,
    uri: values.uri,
    icon: values.icon,
    type: values.type,
  });
}

main().catch((e) => {
  console.error('Error:', e.message);
  process.exit(1);
});
