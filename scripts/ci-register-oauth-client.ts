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
 *   CLIENT_TINYCLOUD_NATIVE_DELEGATION
 *                         Native delegation ceiling JSON (optional; native
 *                         clients only). Adds tinycloud:delegation.
 *   TINYCLOUD_SQL_ISOLATED_HOSTS
 *                         Hosts allowed to carry SQL entries in that ceiling
 *
 * Idempotent: if an active client with the same name already exists, it is
 * printed and no new client is created.
 */

import { createPrismaClient, type Prisma } from '../packages/db/src/index';
import { randomBytes } from 'crypto';
import { TINYCLOUD_DELEGATION_SCOPE } from '../apps/api/src/oauth-config';
import {
  NativeDelegationPolicyError,
  validateNativeDelegationConfig,
  type NativeDelegationConfig,
} from '../apps/api/src/services/native-delegation/policy';

const prisma = createPrismaClient();

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    console.error(`Error: ${name} is required`);
    process.exit(1);
  }
  return value;
}

// The production registration path: never accept loopback TinyCloud hosts,
// whatever NODE_ENV the CI runner has.
const POLICY_OPTIONS = { allowLocalHosts: false } as const;

function nativeDelegationConfig(type: string, raw: string | undefined): NativeDelegationConfig | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('CLIENT_TINYCLOUD_NATIVE_DELEGATION is not valid JSON');
  }
  return validateNativeDelegationConfig(parsed, { type, public: true, tokenEndpointAuthMethod: 'none' }, POLICY_OPTIONS);
}

// Postgres JSONB reorders object keys, so compare both ceilings in the
// validator's canonical form.
function sameNativeDelegationConfig(
  existing: { type: string | null; public: boolean; tokenEndpointAuthMethod: string | null; tinycloudNativeDelegation: unknown },
  requested: NativeDelegationConfig,
): boolean {
  if (existing.tinycloudNativeDelegation == null) return false;
  try {
    const stored = validateNativeDelegationConfig(existing.tinycloudNativeDelegation, existing, POLICY_OPTIONS);
    return JSON.stringify(stored) === JSON.stringify(requested);
  } catch (error) {
    if (error instanceof NativeDelegationPolicyError) return false;
    throw error;
  }
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
  const nativeConfig = nativeDelegationConfig(type, process.env.CLIENT_TINYCLOUD_NATIVE_DELEGATION?.trim());
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
    if (nativeConfig && (
      !existing.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) ||
      !sameNativeDelegationConfig(existing, nativeConfig)
    )) {
      throw new Error('An active client with this name exists without this delegation ceiling; change it with the admin API');
    }
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
      scopes: ['openid', 'email', 'keys', 'offline_access', ...(nativeConfig ? [TINYCLOUD_DELEGATION_SCOPE] : [])],
      tinycloudNativeDelegation: nativeConfig ? nativeConfig as unknown as Prisma.InputJsonObject : undefined,
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
