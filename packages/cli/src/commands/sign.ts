import { authenticatedFetch } from '../api';

export async function signCommand(
  message: string,
  options: { host: string; clientId: string; keyId?: string },
) {
  // If no keyId, get the first key
  let keyId = options.keyId;
  if (!keyId) {
    const keysResponse = await authenticatedFetch(options.host, options.clientId, '/api/keys');
    if (!keysResponse.ok) {
      throw new Error(`Failed to fetch keys: ${keysResponse.status}`);
    }
    const data = await keysResponse.json() as { keys: Array<{ id: string; keyType: string }> };
    const managedKey = data.keys.find((k) => k.keyType === 'MANAGED');
    if (!managedKey) {
      throw new Error('No managed key found. Only managed keys can sign via the CLI.');
    }
    keyId = managedKey.id;
  }

  const response = await authenticatedFetch(
    options.host,
    options.clientId,
    `/api/keys/${keyId}/sign`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    },
  );

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Sign failed: ${response.status}${detail ? ` - ${detail}` : ''}`);
  }

  const result = await response.json() as { signature: string; address: string };
  console.log(`Signature: ${result.signature}`);
  console.log(`Address:   ${result.address}`);
}
