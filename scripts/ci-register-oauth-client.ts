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
 *   CLIENT_NAME           Display name (required on create; optional on update)
 *   CLIENT_REDIRECT_URIS  Comma-separated redirect URIs (required on create)
 *   CLIENT_TYPE           "native" | "spa" (default "native")
 *   CLIENT_URI            Application website URL (optional)
 *   CLIENT_ID             Existing enabled client to update. Without a ceiling
 *                         this updates branding only: empty branding values
 *                         are unchanged; use `none` to clear icon or theme
 *                         colours.
 *   CLIENT_ICON           HTTPS icon URL (optional)
 *   CLIENT_THEME_BACKGROUND_COLOR  #rrggbb (optional)
 *   CLIENT_THEME_ACCENT_COLOR      #rrggbb (optional)
 *   CLIENT_TINYCLOUD_NATIVE_DELEGATION
 *                         Native delegation ceiling JSON (optional; native
 *                         clients only). Adds tinycloud:delegation. With
 *                         CLIENT_ID it is the full replacement ceiling for that
 *                         client (see below).
 *
 * Ceiling update (CLIENT_ID + CLIENT_TINYCLOUD_NATIVE_DELEGATION):
 *   The value is validated by the same validator the admin API PATCH uses and
 *   replaces the whole stored ceiling. The BEFORE and AFTER ceilings and the
 *   entry-level diff are printed (ceiling config only). Adding entries is
 *   allowed. A value that removes an entry, or reduces a limit, is refused
 *   unless --allow-narrow is passed. It cannot be combined with branding,
 *   redirect URI, type or website values.
 *   A ceiling update is a dry run unless --apply is passed: without it the
 *   BEFORE, AFTER and diff are printed and nothing is written.
 *   --apply               Write the ceiling.
 *   --dry-run             Same as passing neither flag (accepted for clarity);
 *                         cannot be combined with --apply.
 *   --allow-narrow        Permit a ceiling that removes or reduces entries.
 *
 * Idempotent: if an active client with the same name already exists, it is
 * printed and no new client is created.
 */

import { createPrismaClient, type Prisma } from '../packages/db/src/index';
import { randomBytes } from 'crypto';
import { TINYCLOUD_DELEGATION_SCOPE } from '../apps/api/src/oauth-config';
import { updateNativeCeiling } from '../apps/api/src/services/native-delegation/ceiling-update';
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

function optionalHttpsIcon(emptyValue: undefined | null = null): string | null | undefined {
  const rawValue = process.env.CLIENT_ICON?.trim();
  if (!rawValue) return emptyValue;
  if (rawValue.toLowerCase() === 'none') return null;
  const value = rawValue;
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('CLIENT_ICON must be an HTTPS URL'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) {
    throw new Error('CLIENT_ICON must be an HTTPS URL without credentials');
  }
  return value;
}

function themeColor(name: string, emptyValue: undefined | null = null): string | null | undefined {
  const rawValue = process.env[name]?.trim();
  if (!rawValue) return emptyValue;
  if (rawValue.toLowerCase() === 'none') return null;
  const value = rawValue;
  if (!/^#[0-9a-fA-F]{6}$/.test(value)) throw new Error(`${name} must be #rrggbb or none`);
  return value;
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

function cliFlags(args: string[]): { apply: boolean; dryRun: boolean; allowNarrow: boolean } {
  const unknown = args.filter((arg) => arg !== '--apply' && arg !== '--dry-run' && arg !== '--allow-narrow');
  if (unknown.length > 0) throw new Error(`Unknown argument: ${unknown.join(' ')}`);
  const flags = { apply: args.includes('--apply'), dryRun: args.includes('--dry-run'), allowNarrow: args.includes('--allow-narrow') };
  if (flags.apply && flags.dryRun) throw new Error('--apply and --dry-run cannot be combined');
  return flags;
}

async function main() {
  required('DATABASE_URL');
  const clientIdToUpdate = process.env.CLIENT_ID?.trim();
  const ceilingInput = process.env.CLIENT_TINYCLOUD_NATIVE_DELEGATION?.trim();
  const flags = cliFlags(process.argv.slice(2));
  if (clientIdToUpdate && ceilingInput) {
    const incompatible = [
      ['CLIENT_NAME', process.env.CLIENT_NAME],
      ['CLIENT_ICON', process.env.CLIENT_ICON],
      ['CLIENT_THEME_BACKGROUND_COLOR', process.env.CLIENT_THEME_BACKGROUND_COLOR],
      ['CLIENT_THEME_ACCENT_COLOR', process.env.CLIENT_THEME_ACCENT_COLOR],
      ['CLIENT_REDIRECT_URIS', process.env.CLIENT_REDIRECT_URIS],
      ['CLIENT_URI', process.env.CLIENT_URI],
      ['CLIENT_TYPE', process.env.CLIENT_TYPE],
    ].filter(([, value]) => value?.trim());
    if (incompatible.length > 0) {
      throw new Error(`a ceiling update changes the ceiling only; remove ${incompatible.map(([key]) => key).join(', ')}`);
    }
    await updateNativeCeiling(prisma, {
      clientId: clientIdToUpdate,
      rawCeiling: ceilingInput,
      dryRun: !flags.apply,
      allowNarrow: flags.allowNarrow,
      log: (line) => console.log(line),
    });
    console.log(`CLIENT_ID=${clientIdToUpdate}`);
    return;
  }
  if (flags.apply || flags.dryRun || flags.allowNarrow) {
    throw new Error('--apply, --dry-run and --allow-narrow apply to ceiling updates only (CLIENT_ID with CLIENT_TINYCLOUD_NATIVE_DELEGATION)');
  }
  const name = clientIdToUpdate ? process.env.CLIENT_NAME?.trim() || undefined : required('CLIENT_NAME');
  if (clientIdToUpdate) {
    const incompatible = [
      ['CLIENT_REDIRECT_URIS', process.env.CLIENT_REDIRECT_URIS],
      ['CLIENT_URI', process.env.CLIENT_URI],
      ['CLIENT_TYPE', process.env.CLIENT_TYPE],
    ].filter(([, value]) => value?.trim());
    if (incompatible.length > 0) {
      throw new Error(`client_id updates branding only; remove ${incompatible.map(([key]) => key).join(', ')}`);
    }
  }
  const redirectUris = clientIdToUpdate ? [] : required('CLIENT_REDIRECT_URIS')
    .split(',').map((uri) => uri.trim()).filter(Boolean);
  const type = process.env.CLIENT_TYPE?.trim() || 'native';
  const uri = process.env.CLIENT_URI?.trim() || null;
  const icon = optionalHttpsIcon(clientIdToUpdate ? undefined : null);
  const themeBackgroundColor = themeColor('CLIENT_THEME_BACKGROUND_COLOR', clientIdToUpdate ? undefined : null);
  const themeAccentColor = themeColor('CLIENT_THEME_ACCENT_COLOR', clientIdToUpdate ? undefined : null);

  if (clientIdToUpdate) {
    const existingClient = await prisma.oauthClient.findUnique({ where: { clientId: clientIdToUpdate } });
    if (!existingClient || existingClient.disabled) throw new Error(`Enabled OAuth client not found: ${clientIdToUpdate}`);
    await prisma.oauthClient.update({
      where: { clientId: clientIdToUpdate },
      data: {
        ...(name ? { name } : {}),
        ...(icon !== undefined ? { icon } : {}),
        ...(themeBackgroundColor !== undefined ? { themeBackgroundColor } : {}),
        ...(themeAccentColor !== undefined ? { themeAccentColor } : {}),
      },
    });
    console.log(`Branding updated for enabled OAuth client: ${name ?? clientIdToUpdate}`);
    console.log(`CLIENT_ID=${clientIdToUpdate}`);
    return;
  }

  const clientName = name ?? required('CLIENT_NAME');

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
    where: { name: clientName, disabled: false },
  });
  if (existing) {
    if (nativeConfig && (
      !existing.scopes.includes(TINYCLOUD_DELEGATION_SCOPE) ||
      !sameNativeDelegationConfig(existing, nativeConfig)
    )) {
      throw new Error('An active client with this name exists without this delegation ceiling; change it with the admin API');
    }
    console.log(`Client "${clientName}" already exists — not creating a duplicate.`);
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
      name: clientName,
      uri,
      icon,
      themeBackgroundColor,
      themeAccentColor,
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

  console.log(`OAuth client registered: ${clientName}`);
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
