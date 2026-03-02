import { authenticatedFetch } from '../api';

interface KeyInfo {
  id: string;
  address: string;
  keyType: string;
  label?: string;
  createdAt: string;
}

export async function keysCommand(options: { host: string; clientId: string }) {
  const response = await authenticatedFetch(options.host, options.clientId, '/api/keys');

  if (!response.ok) {
    throw new Error(`Failed to fetch keys: ${response.status} ${response.statusText}`);
  }

  const data = await response.json() as { keys: KeyInfo[] };
  const keys = data.keys;

  if (keys.length === 0) {
    console.log('No keys found.');
    return;
  }

  console.log(`Found ${keys.length} key(s):\n`);
  for (const key of keys) {
    const label = key.label ? ` (${key.label})` : '';
    console.log(`  ${key.id}  ${key.address}  ${key.keyType}${label}`);
  }
}
