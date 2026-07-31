#!/usr/bin/env bun
/**
 * Provision the production CoordinationOS OIDC client and matching Supabase
 * custom provider without ever printing the client or service-role secrets.
 *
 * This runs in GitHub Actions because the production DATABASE_URL already
 * lives there. The Supabase service-role key is supplied as a temporary Actions
 * secret and should be removed after a successful run.
 */

import { createHash, randomBytes } from 'node:crypto';
import { createPrismaClient } from '../packages/db/src/index';

const EXACT_SCOPES = ['openid', 'email', 'keys', 'tinycloud:session'];
const PROVIDER_IDENTIFIER = 'custom:openkey';
const CLIENT_NAME = 'CoordinationOS';
const TINYCLOUD_SESSION_POLICY = 'coordinationos-kv-v1';

type Configuration = {
  callbackUri: string;
  coordinationosUri: string;
  issuer: string;
  organizationId: string | undefined;
  serviceRoleKey: string | undefined;
  supabaseUrl: string;
};

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function exactStringSet(left: string[], right: string[]): boolean {
  return left.length === right.length
    && new Set(left).size === left.length
    && left.every((value) => right.includes(value));
}

export function readConfiguration(): Configuration {
  const confirm = required('CONFIRM_PROVISION');
  if (confirm !== 'PROVISION_COORDINATIONOS_OIDC') {
    throw new Error('CONFIRM_PROVISION must equal PROVISION_COORDINATIONOS_OIDC');
  }

  const callbackUri = required('SUPABASE_CALLBACK_URI');
  const coordinationosUri = required('COORDINATIONOS_URI');
  const issuer = required('OPENKEY_ISSUER');
  const organizationId = process.env.OPENKEY_ORGANIZATION_ID?.trim() || undefined;
  const serviceRoleKey = process.env.COORDINATIONOS_SUPABASE_SERVICE_ROLE_KEY?.trim() || undefined;
  const supabaseUrl = required('SUPABASE_URL').replace(/\/+$/, '');

  const callback = new URL(callbackUri);
  const coordinationos = new URL(coordinationosUri);
  const issuerUrl = new URL(issuer);
  const project = new URL(supabaseUrl);
  for (const [name, url] of [
    ['SUPABASE_CALLBACK_URI', callback],
    ['COORDINATIONOS_URI', coordinationos],
    ['OPENKEY_ISSUER', issuerUrl],
    ['SUPABASE_URL', project],
  ] as const) {
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new Error(`${name} must be a canonical HTTPS URL`);
    }
  }
  if (callback.origin !== project.origin || callback.pathname !== '/auth/v1/callback') {
    throw new Error('SUPABASE_CALLBACK_URI must be the selected project auth callback');
  }
  if (issuerUrl.pathname !== '/api/auth') {
    throw new Error('OPENKEY_ISSUER must use the production /api/auth issuer');
  }
  return { callbackUri, coordinationosUri, issuer, organizationId, serviceRoleKey, supabaseUrl };
}

async function providerRequest(
  config: Configuration,
  method: 'GET' | 'POST',
  body?: Record<string, unknown>,
): Promise<{ ok: boolean; status: number; value: Record<string, unknown> | null }> {
  const serviceRoleKey = config.serviceRoleKey;
  if (!serviceRoleKey) {
    throw new Error('COORDINATIONOS_SUPABASE_SERVICE_ROLE_KEY is required to provision the Supabase provider');
  }
  // Supabase's custom-provider router treats the colon as part of the
  // identifier. Percent-encoding it here reaches the handler as the literal
  // string "custom%3Aopenkey", which then fails the required custom: prefix.
  const suffix = method === 'GET' ? `/${PROVIDER_IDENTIFIER}` : '';
  const response = await fetch(`${config.supabaseUrl}/auth/v1/admin/custom-providers${suffix}`, {
    method,
    headers: {
      apikey: serviceRoleKey,
      authorization: `Bearer ${serviceRoleKey}`,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  let value: Record<string, unknown> | null = null;
  try {
    value = await response.json() as Record<string, unknown>;
  } catch {
    value = null;
  }
  return { ok: response.ok, status: response.status, value };
}

function safeProviderError(result: {
  status: number;
  value: Record<string, unknown> | null;
}): string {
  const code = typeof result.value?.error_code === 'string'
    ? result.value.error_code
    : 'unknown_error';
  const message = typeof result.value?.msg === 'string'
    ? result.value.msg
    : 'Supabase rejected the provider request';
  return `Supabase provider request failed (${result.status}, ${code}): ${message}`;
}

export async function assertOrganizationCanOwnClient(
  prisma: ReturnType<typeof createPrismaClient>,
  organizationId: string,
  currentOrganizationId: string | null,
) {
  if (currentOrganizationId && currentOrganizationId !== organizationId) {
    throw new Error('CoordinationOS client already belongs to another OpenKey organization');
  }
  if (currentOrganizationId === organizationId) return;

  const organization = await prisma.organization.findUnique({
    where: { id: organizationId },
    select: {
      planEntitlements: { select: { maxApps: true } },
      _count: { select: { oauthClients: true } },
    },
  });
  if (!organization) throw new Error('OPENKEY_ORGANIZATION_ID does not identify an OpenKey organization');
  if (!organization.planEntitlements) {
    throw new Error('OpenKey organization has no plan entitlements');
  }
  if (organization._count.oauthClients >= organization.planEntitlements.maxApps) {
    throw new Error('OpenKey organization application limit is exhausted');
  }
}

async function main() {
  const config = readConfiguration();
  const prisma = createPrismaClient();
  let createdClientId: string | null = null;
  let rotatedClient: {
    clientId: string;
    priorOrganizationId: string | null;
    priorSecretHash: string;
  } | null = null;

  try {
    const findCandidates = async () => (await prisma.oauthClient.findMany({
      where: { name: CLIENT_NAME, disabled: false },
    })).filter((client) => (
      !client.public
      && client.mode === 'PERSONAL'
      && client.type === 'web'
      && client.tokenEndpointAuthMethod === 'client_secret_basic'
      && exactStringSet(client.scopes, EXACT_SCOPES)
      && exactStringSet(client.grantTypes, ['authorization_code'])
      && exactStringSet(client.responseTypes, ['code'])
      && exactStringSet(client.redirectUris, [config.callbackUri])
    ));
    if (!config.serviceRoleKey) {
      const candidates = await findCandidates();
      if (candidates.length !== 1) {
        throw new Error(
          'Policy-only repair requires exactly one active CoordinationOS confidential client',
        );
      }
      const client = candidates[0]!;
      const organizationId = config.organizationId ?? client.organizationId;
      if (!organizationId) {
        throw new Error(
          'OPENKEY_ORGANIZATION_ID is required because the existing CoordinationOS client has no owner',
        );
      }
      await assertOrganizationCanOwnClient(prisma, organizationId, client.organizationId);
      await prisma.oauthClient.update({
        where: { clientId: client.clientId },
        data: {
          organizationId,
          tinycloudSessionPolicy: TINYCLOUD_SESSION_POLICY,
          tinycloudSessionOrigin: config.coordinationosUri,
        },
      });
      console.log(`Updated TinyCloud dashboard policy for existing client ${client.clientId}.`);
      return;
    }

    const currentProvider = await providerRequest(config, 'GET');
    if (currentProvider.ok) {
      const providerClientId = currentProvider.value?.client_id;
      if (typeof providerClientId !== 'string' || !providerClientId) {
        throw new Error('Existing custom:openkey provider has no client_id');
      }
      const client = await prisma.oauthClient.findUnique({ where: { clientId: providerClientId } });
      if (!client
        || client.disabled
        || client.public
        || client.mode !== 'PERSONAL'
        || client.type !== 'web'
        || client.tokenEndpointAuthMethod !== 'client_secret_basic'
        || !exactStringSet(client.scopes, EXACT_SCOPES)
        || !exactStringSet(client.grantTypes, ['authorization_code'])
        || !exactStringSet(client.responseTypes, ['code'])
        || !exactStringSet(client.redirectUris, [config.callbackUri])) {
        throw new Error('Existing custom:openkey provider is not backed by the required OpenKey client');
      }
      const organizationId = config.organizationId ?? client.organizationId;
      if (!organizationId) {
        throw new Error(
          'OPENKEY_ORGANIZATION_ID is required because the existing CoordinationOS client has no owner',
        );
      }
      await assertOrganizationCanOwnClient(prisma, organizationId, client.organizationId);
      if (client.organizationId !== organizationId
        || client.tinycloudSessionPolicy !== TINYCLOUD_SESSION_POLICY
        || client.tinycloudSessionOrigin !== config.coordinationosUri) {
        await prisma.oauthClient.update({
          where: { clientId: client.clientId },
          data: {
            organizationId,
            tinycloudSessionPolicy: TINYCLOUD_SESSION_POLICY,
            tinycloudSessionOrigin: config.coordinationosUri,
          },
        });
      }
      console.log(`Provider already configured with client ${client.clientId}; organization ownership verified.`);
      return;
    }
    if (currentProvider.status !== 404) throw new Error(safeProviderError(currentProvider));
    const organizationId = config.organizationId;
    if (!organizationId) {
      throw new Error(
        'OPENKEY_ORGANIZATION_ID is required when provisioning a new CoordinationOS client',
      );
    }

    const candidates = await findCandidates();
    if (candidates.length > 1) {
      throw new Error('Multiple active CoordinationOS confidential clients found; refusing to guess');
    }

    const clientSecret = randomBytes(32).toString('base64url');
    const clientSecretHash = createHash('sha256')
      .update(clientSecret, 'utf8')
      .digest('base64url');
    let clientId: string;
    if (candidates.length === 1) {
      const existing = candidates[0]!;
      if (!existing.clientSecret) throw new Error('Existing confidential client has no secret hash');
      await assertOrganizationCanOwnClient(prisma, organizationId, existing.organizationId);
      clientId = existing.clientId;
      rotatedClient = {
        clientId,
        priorOrganizationId: existing.organizationId,
        priorSecretHash: existing.clientSecret,
      };
      await prisma.oauthClient.update({
        where: { clientId },
        data: {
          clientSecret: clientSecretHash,
          organizationId,
          tinycloudSessionPolicy: TINYCLOUD_SESSION_POLICY,
          tinycloudSessionOrigin: config.coordinationosUri,
        },
      });
    } else {
      await assertOrganizationCanOwnClient(prisma, organizationId, null);
      clientId = `ok_${randomBytes(16).toString('hex')}`;
      createdClientId = clientId;
      await prisma.oauthClient.create({
        data: {
          id: randomBytes(16).toString('hex'),
          clientId,
          clientSecret: clientSecretHash,
          organizationId,
          name: CLIENT_NAME,
          uri: config.coordinationosUri,
          icon: null,
          redirectUris: [config.callbackUri],
          scopes: [...EXACT_SCOPES],
          tinycloudSessionPolicy: TINYCLOUD_SESSION_POLICY,
          tinycloudSessionOrigin: config.coordinationosUri,
          disabled: false,
          skipConsent: false,
          enableEndSession: false,
          tokenEndpointAuthMethod: 'client_secret_basic',
          grantTypes: ['authorization_code'],
          responseTypes: ['code'],
          type: 'web',
          public: false,
          contacts: [],
          mode: 'PERSONAL',
          metadata: { openkeyClientMode: 'PERSONAL' },
        },
      });
    }

    const createdProvider = await providerRequest(config, 'POST', {
      provider_type: 'oidc',
      identifier: PROVIDER_IDENTIFIER,
      name: 'OpenKey',
      client_id: clientId,
      client_secret: clientSecret,
      issuer: config.issuer,
      scopes: [...EXACT_SCOPES],
      pkce_enabled: true,
      email_optional: false,
      skip_nonce_check: false,
      custom_claims_allowlist: ['keys'],
    });
    if (!createdProvider.ok) throw new Error(safeProviderError(createdProvider));
    console.log(`Provisioned ${PROVIDER_IDENTIFIER} with OpenKey client ${clientId}.`);
  } catch (error) {
    if (createdClientId) {
      await prisma.oauthClient.delete({ where: { clientId: createdClientId } }).catch(() => undefined);
    }
    if (rotatedClient) {
      await prisma.oauthClient.update({
        where: { clientId: rotatedClient.clientId },
        data: {
          clientSecret: rotatedClient.priorSecretHash,
          organizationId: rotatedClient.priorOrganizationId,
        },
      }).catch(() => undefined);
    }
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(`Provisioning failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    process.exit(1);
  });
}
