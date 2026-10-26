import { getAddress, isAddress } from 'viem';
export type OwnerRevocationRequest = {
  kind: 'owner-revocation';
  ownerDid: string;
  cid: string;
  nonce: string;
  expiresAt: string;
};

const fields = ['kind', 'ownerDid', 'cid', 'nonce', 'expiresAt'];
const didPattern = /^did:pkh:eip155:([1-9][0-9]*):(0x[0-9a-fA-F]{40})$/;
const cidPattern = /^b[a-z2-7]{58,118}$/;
const noncePattern = /^[A-Za-z0-9]{22,}$/;
const datePattern = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/;

export function parseOwnerRevocationRequest(value: unknown, now = new Date()): OwnerRevocationRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid owner-revocation request');
  const input = value as Record<string, unknown>;
  if (input.kind !== 'owner-revocation') throw new Error('Invalid owner-revocation kind');
  if (Object.keys(input).some(field => !fields.includes(field)) || Object.keys(input).length !== fields.length) {
    throw new Error('Unknown or missing owner-revocation field');
  }
  if (typeof input.ownerDid !== 'string' || !didPattern.test(input.ownerDid) || !Number.isSafeInteger(Number(didPattern.exec(input.ownerDid)?.[1]))) {
    throw new Error('Invalid ownerDid');
  }
  if (!isAddress(didPattern.exec(input.ownerDid)![2]!, { strict: true })) throw new Error('Invalid ownerDid checksum');
  if (typeof input.cid !== 'string' || !cidPattern.test(input.cid)) throw new Error('Invalid cid');
  if (typeof input.nonce !== 'string' || !noncePattern.test(input.nonce)) throw new Error('Invalid nonce');
  if (typeof input.expiresAt !== 'string' || !datePattern.test(input.expiresAt) || !Number.isFinite(Date.parse(input.expiresAt))) {
    throw new Error('Invalid expiresAt');
  }
  const expiry = Date.parse(input.expiresAt);
  if (expiry <= now.getTime()) throw new Error('Owner-revocation request expired');
  return { ...input, expiresAt: new Date(Math.min(expiry, now.getTime() + 600_000)).toISOString() } as OwnerRevocationRequest;
}

export function ownerRevocationAddress(request: OwnerRevocationRequest): string {
  return getAddress(didPattern.exec(request.ownerDid)![2]!);
}

export function buildOwnerRevocationSiwe(request: OwnerRevocationRequest, domain: string, issuedAt: Date): string {
  const match = didPattern.exec(request.ownerDid)!;
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    ownerRevocationAddress(request), '', '',
    `URI: ucan:${request.cid}`,
    'Version: 1',
    `Chain ID: ${match[1]}`,
    `Nonce: ${request.nonce}`,
    `Issued At: ${issuedAt.toISOString()}`,
    `Expiration Time: ${new Date(Math.min(Date.parse(request.expiresAt), issuedAt.getTime() + 600_000)).toISOString()}`,
  ].join('\n');
}

export function ownerRevocationResult(siwe: string, signature: string) {
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) throw new Error('Invalid owner signature');
  return { siwe, signature };
}
