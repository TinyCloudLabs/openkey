import { OpenKeyNativeError, base64UrlDecode, base64UrlEncode, type TinyCloudDelegation } from '@openkey/core';

/** Reproduce the server's TinyCloud delegation with the same WASM as the app. */
export async function verifyTinyCloudDelegation(delegation: TinyCloudDelegation): Promise<void> {
  if (!delegation.siwe || !delegation.signature || !delegation.delegationHeader?.Authorization || !delegation.delegationCid) {
    throw new OpenKeyNativeError('SERVER', 'Delegation is missing signed TinyCloud material');
  }
  try {
    const { BrowserWasmBindings } = await import('@tinycloud/web-sdk');
    const wasm = new BrowserWasmBindings();
    await wasm.ensureInitialized();
    const header = wasm.siweToDelegationHeaders({ siwe: delegation.siwe, signature: delegation.signature }) as { Authorization?: string };
    if (header.Authorization !== delegation.delegationHeader.Authorization) throw new Error('delegation header mismatch');
    const encoded = header.Authorization.replace(/^Bearer /i, '');
    let bytes: Uint8Array;
    if (encoded.includes('.')) {
      bytes = new TextEncoder().encode(encoded);
    } else {
      if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('noncanonical delegation header');
      bytes = base64UrlDecode(encoded);
      if (base64UrlEncode(bytes) !== encoded) throw new Error('noncanonical delegation header');
    }
    // Match TinyCloudNode.computeDelegationCid: hash the signed bytes with
    // the raw multicodec (0x55), even when the payload is DAG-CBOR.
    if (wasm.computeCid(bytes, 0x55n) !== delegation.delegationCid) throw new Error('delegation CID mismatch');
  } catch {
    // Never include the signature, SIWE, header, or a raw WASM error in logs.
    throw new OpenKeyNativeError('SERVER', 'TinyCloud delegation integrity check failed');
  }
}
