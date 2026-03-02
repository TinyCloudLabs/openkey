import { authenticatedFetch } from '../api';

export async function whoamiCommand(options: { host: string; clientId: string }) {
  const response = await authenticatedFetch(options.host, options.clientId, '/api/auth/userinfo');

  if (!response.ok) {
    throw new Error(`Failed to fetch user info: ${response.status} ${response.statusText}`);
  }

  const user = await response.json() as Record<string, unknown>;

  console.log(`Email:   ${user.email ?? 'N/A'}`);
  if (user.sub) {
    console.log(`User ID: ${user.sub}`);
  }

  const keys = user.keys as Array<{ address: string; keyType: string }> | undefined;
  if (keys && keys.length > 0) {
    console.log(`Keys:    ${keys.length}`);
    for (const key of keys) {
      console.log(`  ${key.address} (${key.keyType})`);
    }
  }
}
