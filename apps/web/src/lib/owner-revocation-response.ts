import { ownerRevocationResult } from '@openkey/capability-review';

export async function deliverOwnerRevocation(
  input: { state: string; siwe: string; signature: string; callback?: string },
  send: typeof fetch = fetch,
): Promise<{ code: string; delivered: boolean }> {
  const envelope = {
    transportVersion: 2 as const,
    state: input.state,
    result: ownerRevocationResult(input.siwe, input.signature),
  };
  const bytes = new TextEncoder().encode(JSON.stringify(envelope));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const code = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (!input.callback) return { code, delivered: false };
  try {
    const response = await send(input.callback, {
      method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope),
    });
    const receipt: unknown = await response.json();
    return { code, delivered: response.ok && !!receipt && typeof receipt === 'object' && 'accepted' in receipt && receipt.accepted === true };
  } catch {
    return { code, delivered: false };
  }
}
