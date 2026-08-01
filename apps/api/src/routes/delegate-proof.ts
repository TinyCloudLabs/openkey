import { getAddress, recoverMessageAddress } from 'viem';
import { SiweMessage } from 'siwe';

export interface VerifiedDelegationProof {
  siwe: string;
  signature: string;
  address: string;
  chainId: number;
  expirationTime: string;
  expiresAt: string;
}

export interface DelegationResponseSession {
  delegationHeader: { Authorization: string };
  delegationCid: string;
  verificationMethod: string;
}

/**
 * Verify the owner proof that authorizes a completed delegation and derive all
 * owner metadata from the signed SIWE. Callers must not use request metadata
 * for these fields: it is not cryptographically authoritative.
 */
export async function verifyDelegationProof(
  siwe: unknown,
  signature: unknown,
  expectedAddress?: string,
): Promise<VerifiedDelegationProof> {
  if (typeof siwe !== 'string' || typeof signature !== 'string' || signature.length === 0) {
    throw new Error('completed delegation proof is malformed');
  }

  let parsed: SiweMessage;
  try {
    parsed = new SiweMessage(siwe);
  } catch {
    throw new Error('completed delegation SIWE is invalid');
  }

  let address: string;
  try {
    address = getAddress(parsed.address);
  } catch {
    throw new Error('completed delegation owner address is invalid');
  }

  if (!Number.isSafeInteger(parsed.chainId) || parsed.chainId <= 0) {
    throw new Error('completed delegation chain ID is invalid');
  }

  const expirationTime = parsed.expirationTime;
  if (
    typeof expirationTime !== 'string' ||
    !Number.isFinite(Date.parse(expirationTime)) ||
    Date.parse(expirationTime) <= Date.now()
  ) {
    throw new Error('completed delegation SIWE is expired or missing an expiry');
  }

  let recoveredAddress: string;
  try {
    recoveredAddress = getAddress(await recoverMessageAddress({
      message: siwe,
      signature: signature as `0x${string}`,
    }));
  } catch {
    throw new Error('completed delegation signature is invalid');
  }

  if (recoveredAddress !== address) {
    throw new Error('completed delegation signature owner mismatch');
  }

  if (expectedAddress !== undefined) {
    let canonicalExpectedAddress: string;
    try {
      canonicalExpectedAddress = getAddress(expectedAddress);
    } catch {
      throw new Error('expected delegation owner address is invalid');
    }
    if (address !== canonicalExpectedAddress) {
      throw new Error('completed delegation owner does not match the managed key');
    }
  }

  return {
    siwe,
    signature,
    address,
    chainId: parsed.chainId,
    expirationTime,
    expiresAt: expirationTime,
  };
}

export function delegationResponse(
  session: DelegationResponseSession,
  input: {
    spaceId: string;
    jwk: object;
    proof: VerifiedDelegationProof;
    hostActivated: boolean;
    edited: boolean;
    reason?: string;
  },
) {
  return {
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId: input.spaceId,
    ownerDid: `did:pkh:eip155:${input.proof.chainId}:${input.proof.address}`,
    verificationMethod: session.verificationMethod,
    jwk: input.jwk,
    address: input.proof.address,
    chainId: input.proof.chainId,
    hostActivated: input.hostActivated,
    edited: input.edited,
    reason: input.reason,
    expirationTime: input.proof.expirationTime,
    expiresAt: input.proof.expiresAt,
    expiry: input.proof.expiresAt,
    siwe: String(input.proof.siwe),
    signature: String(input.proof.signature),
  };
}
