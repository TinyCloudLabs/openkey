// Auto-seed known OAuth clients on startup
// Ensures first-party apps are always registered
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface KnownClient {
  clientId: string;
  name: string;
  redirectUris: string[];
  type: 'native' | 'spa';
}

const KNOWN_CLIENTS: KnownClient[] = [
  {
    clientId: 'ok_051a7767dfef8299cc48dd573ee6af8d',
    name: 'Remember',
    redirectUris: ['remember://auth/callback'],
    type: 'native',
  },
];

export async function seedKnownClients() {
  for (const client of KNOWN_CLIENTS) {
    const existing = await prisma.oauthClient.findUnique({
      where: { clientId: client.clientId },
    });

    if (!existing) {
      await prisma.oauthClient.create({
        data: {
          id: crypto.randomUUID().replace(/-/g, ''),
          clientId: client.clientId,
          clientSecret: null,
          name: client.name,
          redirectUris: client.redirectUris,
          scopes: ['openid'],
          disabled: false,
          skipConsent: false,
          enableEndSession: false,
          tokenEndpointAuthMethod: 'none',
          grantTypes: ['authorization_code', 'refresh_token'],
          responseTypes: ['code'],
          type: client.type,
          public: true,
          contacts: [],
        },
      });
      console.log(`[Seed] Registered OAuth client: ${client.name} (${client.clientId})`);
    }
  }
}
