import { OpenKeyNativeError, base64UrlDecode, base64UrlEncode, type TinyCloudDelegation } from '@openkey/core';

export interface TinyCloudDelegationBindings {
  ensureInitialized(): Promise<void>;
  siweToDelegationHeaders(input: { siwe: string; signature: string }): { Authorization: string };
  computeCid(bytes: Uint8Array, codec: bigint): string;
}

/** Reproduce the server's TinyCloud delegation with the same WASM as the app. */
export async function verifyTinyCloudDelegation(
  delegation: TinyCloudDelegation,
  bindings?: TinyCloudDelegationBindings,
): Promise<void> {
  if (!delegation.siwe || !delegation.signature || !delegation.delegationHeader?.Authorization || !delegation.delegationCid) {
    throw new OpenKeyNativeError('SERVER', 'Delegation is missing signed TinyCloud material');
  }
  try {
    const wasm = bindings ?? new (await import('@tinycloud/web-sdk')).BrowserWasmBindings();
    await wasm.ensureInitialized();
    const header = wasm.siweToDelegationHeaders({ siwe: delegation.siwe, signature: delegation.signature });
    if (header.Authorization !== delegation.delegationHeader.Authorization) throw new Error('delegation header mismatch');
    const encoded = header.Authorization.replace(/^Bearer /i, '');
    let bytes: Uint8Array;
    if (encoded.includes('.')) {
      bytes = new TextEncoder().encode(encoded);
    } else {
      // TinyCloud's Cacao serializer uses padded base64url. Accept only the
      // exact padding required by the decoded length, as TinyCloudNode does.
      const match = /^([A-Za-z0-9_-]+)(={1,2})?$/.exec(encoded);
      if (!match) throw new Error('noncanonical delegation header');
      const unpadded = match[1]!;
      const remainder = unpadded.length % 4;
      if (remainder === 1) throw new Error('noncanonical delegation header');
      const required = remainder === 2 ? 2 : remainder === 3 ? 1 : 0;
      if (match[2] && match[2].length !== required) throw new Error('noncanonical delegation header');
      bytes = base64UrlDecode(unpadded);
      if (base64UrlEncode(bytes) !== unpadded) throw new Error('noncanonical delegation header');
    }
    // Match TinyCloudNode.computeDelegationCid: hash the signed bytes with
    // the raw multicodec (0x55), even when the payload is DAG-CBOR.
    if (wasm.computeCid(bytes, 0x55n) !== delegation.delegationCid) throw new Error('delegation CID mismatch');
  } catch {
    // Never include the signature, SIWE, header, or a raw WASM error in logs.
    throw new OpenKeyNativeError('SERVER', 'TinyCloud delegation integrity check failed');
  }
}
