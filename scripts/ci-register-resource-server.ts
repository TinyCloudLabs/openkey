#!/usr/bin/env bun
/**
 * CI Resource-Server Registration
 *
 * Registers the confidential OAuth client a hosted resource (the TinyCloud
 * MCP server) uses for OpenKey's token status check, POST
 * /api/oauth/resource/introspect. It runs from the register-resource-server
 * GitHub Actions workflow with the same DATABASE_URL secret as the public
 * client registration, and writes the row directly.
 *
 * The client secret is generated here and NEVER printed or logged. It is
 * encrypted to the public key of whoever will hold the secret (RSA-OAEP,
 * SHA-256) and only the ciphertext is printed; that is safe in a CI log.
 * The recipient decrypts it with their private key:
 *   echo "$CIPHERTEXT" | base64 -d | openssl pkeyutl -decrypt -inkey private.pem \
 *     -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
 *
 * Env:
 *   DATABASE_URL                              Postgres connection string (required)
 *   RESOURCE_SERVER_NAME                      Display name (required)
 *   RESOURCE_SERVER_ALLOWED_RESOURCES         Comma-separated canonical resource URLs, each one an
 *                                             audience this server issues tokens for
 *   RESOURCE_SERVER_RATE_LIMIT_PER_MINUTE     Requests per minute this server may make, 1 to 100000
 *                                             (optional; the default is 3000)
 *   RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY
 *                                             RSA public key (>= 2048 bits), PEM or base64 of the
 *                                             PEM (workflow inputs are single-line) (required)
 *   BETTER_AUTH_URL                           The API's base URL (default https://api.openkey.so)
 *   OAUTH_VALID_AUDIENCES                     The API's extra audiences, if it sets any (optional)
 *
 * Flags (merged with the env above; at least one resource is required in total):
 *   --allowed-resource <url>                  A resource URL; repeat it for each one
 *   --rate-limit-per-minute <n>               Same as RESOURCE_SERVER_RATE_LIMIT_PER_MINUTE
 *
 * Idempotent: an active resource server with the same name is reported and not
 * touched; its secret cannot be shown again. To rotate, disable it and register again.
 */

import { createPrismaClient, type Prisma } from '../packages/db/src/index';
import { createPublicKey, constants, publicEncrypt, randomBytes, type KeyObject } from 'node:crypto';
import { parseArgs } from 'node:util';
import { oauthValidAudiences } from '../apps/api/src/oauth-config';
import {
  MAX_RESOURCE_RATE_LIMIT_PER_MINUTE,
  hashClientSecret,
  isValidRateLimit,
  readResourceServerPolicy,
  resourceServerMetadata,
  validateAllowedResources,
} from '../apps/api/src/services/resource-server';

// A client row needs redirect URIs and scopes. These can never be used: the
// host does not resolve (RFC 2606) and `openid` grants nothing by itself.
const PLACEHOLDER_REDIRECT_URI = 'https://resource-server.invalid/callback';
const PLACEHOLDER_SCOPES = ['openid'];

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function recipientPublicKey(raw: string): KeyObject {
  const pem = raw.startsWith('-----BEGIN') ? raw : Buffer.from(raw, 'base64').toString('utf8');
  if (/PRIVATE KEY/.test(pem)) throw new Error('RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY must be a public key; never put a private key in a workflow input');
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new Error('RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY is not a public key');
  }
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new Error('RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY must be an RSA key of at least 2048 bits');
  }
  return key;
}

async function main() {
  required('DATABASE_URL');
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: { 'allowed-resource': { type: 'string', multiple: true }, 'rate-limit-per-minute': { type: 'string' } },
    strict: true,
  });
  const name = required('RESOURCE_SERVER_NAME');
  const allowedResources = [...new Set([
    ...(process.env.RESOURCE_SERVER_ALLOWED_RESOURCES ?? '').split(','),
    ...(values['allowed-resource'] ?? []),
  ].map((resource) => resource.trim()).filter(Boolean))];
  const baseURL = process.env.BETTER_AUTH_URL?.trim() || 'https://api.openkey.so';
  const problems = validateAllowedResources(allowedResources, oauthValidAudiences(baseURL, process.env.OAUTH_VALID_AUDIENCES));
  if (problems.length > 0) throw new Error(`Allowed resources: ${problems.join('; ')}`);
  const rateLimitText = (values['rate-limit-per-minute'] ?? process.env.RESOURCE_SERVER_RATE_LIMIT_PER_MINUTE ?? '').trim();
  const rateLimitPerMinute = rateLimitText === '' ? undefined : Number(rateLimitText);
  if (rateLimitPerMinute !== undefined && !isValidRateLimit(rateLimitPerMinute)) {
    throw new Error(`The rate limit must be an integer from 1 to ${MAX_RESOURCE_RATE_LIMIT_PER_MINUTE}`);
  }
  const recipient = recipientPublicKey(required('RESOURCE_SERVER_SECRET_RECIPIENT_PUBLIC_KEY'));

  const prisma = createPrismaClient();
  try {
    const existing = await prisma.oauthClient.findFirst({ where: { name, disabled: false } });
    if (existing) {
      if (!readResourceServerPolicy(existing.metadata)) {
        throw new Error('An active client with this name exists and is not a resource server; choose another name');
      }
      console.log(`Resource server "${name}" already exists - not creating a duplicate; its secret cannot be shown again.`);
      console.log(`CLIENT_ID=${existing.clientId}`);
      return;
    }

    const secret = randomBytes(32).toString('base64url');
    // Encrypt before writing: if this throws, nothing was registered.
    const ciphertext = publicEncrypt(
      { key: recipient, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(secret, 'utf8'),
    ).toString('base64');
    const clientId = `ok_${randomBytes(16).toString('hex')}`;
    await prisma.oauthClient.create({
      data: {
        id: randomBytes(16).toString('hex'),
        clientId,
        clientSecret: hashClientSecret(secret),
        name,
        redirectUris: [PLACEHOLDER_REDIRECT_URI],
        scopes: PLACEHOLDER_SCOPES,
        disabled: false,
        skipConsent: false,
        enableEndSession: false,
        tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        type: 'web',
        public: false,
        contacts: [],
        metadata: resourceServerMetadata(allowedResources, { rateLimitPerMinute }) as unknown as Prisma.InputJsonObject,
      },
    });

    console.log(`Resource server registered: ${name}`);
    console.log(`CLIENT_ID=${clientId}`);
    console.log(`ALLOWED_RESOURCES=${allowedResources.join(',')}`);
    console.log(`RATE_LIMIT_PER_MINUTE=${rateLimitPerMinute ?? 'default'}`);
    console.log(`SECRET_CIPHERTEXT_RSA_OAEP_SHA256_B64=${ciphertext}`);
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  console.error('Error:', error instanceof Error ? error.message : 'registration failed');
  process.exit(1);
});
