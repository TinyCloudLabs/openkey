import { webcrypto } from 'node:crypto';
import configuredAdmins from './escrow-admins.json';

export interface EscrowApprovalRequest {
  policyHash: string;
  nonce: string;
  expiresAt: string;
  dryRun: boolean;
  operatorId: string;
  approverId: string;
  signatures: readonly { id: string; signature: string }[];
}
export interface EscrowAuthorizationRecord {
  kind: 'preflight' | 'export'; policyHash: string; nonce: string; expiresAt: string;
  dryRun: boolean; operatorId: string; approverId: string | null;
}
export interface EscrowAuthorizationStore {
  /** Atomically rate-limit and insert a unique nonce plus its audit record. */
  consume(request: EscrowAuthorizationRecord): Promise<true>;
}
export interface EscrowAdmin { id: string; publicKey: string }
const admins: readonly EscrowAdmin[] = Object.freeze((configuredAdmins as EscrowAdmin[]).map(admin => Object.freeze({ id: admin.id, publicKey: admin.publicKey })));

function decode(text: string, length: number): Uint8Array {
  if (typeof text !== 'string') throw new Error('Invalid escrow approval');
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== text) throw new Error('Invalid escrow approval');
  return new Uint8Array(bytes);
}
export function escrowApprovalMessage(request: Pick<EscrowApprovalRequest, 'policyHash' | 'nonce' | 'expiresAt' | 'dryRun'>): Uint8Array {
  if (!/^[a-f0-9]{64}$/.test(request.policyHash) || typeof request.policyHash !== 'string'
    || typeof request.dryRun !== 'boolean' || typeof request.expiresAt !== 'string'
    || !Number.isFinite(Date.parse(request.expiresAt)) || new Date(request.expiresAt).toISOString() !== request.expiresAt) throw new Error('Invalid escrow approval');
  decode(request.nonce, 32);
  return new TextEncoder().encode(JSON.stringify(['tinycloud/escrow/approve', 1, request.policyHash, request.nonce, request.expiresAt, request.dryRun]));
}

/** Admin keys are compiled into the measured API image, never read from request/env. */
export async function verifyEscrowApprovalSignatures(request: EscrowApprovalRequest): Promise<EscrowApprovalRequest> {
  if (admins.length < 2) throw new Error('Escrow approval not configured');
  const copied = structuredClone(request);
  const message = escrowApprovalMessage(copied);
  if (Date.parse(copied.expiresAt) <= Date.now()
    || typeof copied.operatorId !== 'string' || typeof copied.approverId !== 'string'
    || copied.operatorId.length > 4096 || copied.approverId.length > 4096
    || copied.operatorId === copied.approverId || !copied.operatorId || !copied.approverId
    || !Array.isArray(copied.signatures) || copied.signatures.length !== 2) throw new Error('Invalid escrow approval');
  const identities = [copied.operatorId, copied.approverId];
  const usedKeys = new Set<string>();
  for (const id of identities) {
    const candidates = admins.filter(admin => admin.id === id);
    const signatures = copied.signatures.filter(signature => signature.id === id);
    if (candidates.length !== 1 || signatures.length !== 1) throw new Error('Invalid escrow approver');
    const admin = candidates[0]!;
    if (usedKeys.has(admin.publicKey)) throw new Error('Approvers must use distinct keys');
    usedKeys.add(admin.publicKey);
    const raw = decode(admin.publicKey, 65);
    if (raw[0] !== 4) throw new Error('Invalid admin key');
    const key = await webcrypto.subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, decode(signatures[0]!.signature, 64), message) !== true) throw new Error('Invalid escrow signature');
  }
  if (Date.parse(copied.expiresAt) <= Date.now()) throw new Error('Escrow approval expired');
  return copied;
}


export function assertEscrowApprovalMatches(request: EscrowApprovalRequest, expected: Omit<EscrowApprovalRequest, 'signatures'>): void {
  if (Buffer.from(escrowApprovalMessage(request)).toString('hex') !== Buffer.from(escrowApprovalMessage(expected)).toString('hex')
    || request.operatorId !== expected.operatorId || request.approverId !== expected.approverId) throw new Error('Escrow policy mismatch');
}

export async function authorizeEscrow(request: EscrowApprovalRequest, expected: Omit<EscrowApprovalRequest, 'signatures'>, store: EscrowAuthorizationStore): Promise<true> {
  const verified = await verifyEscrowApprovalSignatures(request);
  assertEscrowApprovalMatches(verified, expected);
  const { signatures: _signatures, ...audit } = verified;
  if (await store.consume({ ...audit, kind: 'export' }) !== true) throw new Error('Escrow approval refused');
  return true;
}


export interface EscrowPreflightRequest {
  measuredConfigHash: string; nonce: string; expiresAt: string; adminId: string; signature: string;
}
export function escrowPreflightMessage(request: Omit<EscrowPreflightRequest, 'signature'>): Uint8Array {
  if (typeof request.measuredConfigHash !== 'string' || !/^[a-f0-9]{64}$/.test(request.measuredConfigHash)
    || typeof request.adminId !== 'string' || !request.adminId || request.adminId.length > 4096
    || typeof request.expiresAt !== 'string' || !Number.isFinite(Date.parse(request.expiresAt))
    || new Date(request.expiresAt).toISOString() !== request.expiresAt) throw new Error('Invalid escrow preflight');
  decode(request.nonce, 32);
  return new TextEncoder().encode(JSON.stringify(['tinycloud/escrow/preflight', 1, request.measuredConfigHash, request.nonce, request.expiresAt, request.adminId]));
}
export async function verifyEscrowPreflightSignature(request: EscrowPreflightRequest, measuredConfigHash: string): Promise<EscrowPreflightRequest> {
  if (admins.length === 0) throw new Error('Escrow approval not configured');
  const copied = structuredClone(request);
  const message = escrowPreflightMessage(copied);
  const expiry = Date.parse(copied.expiresAt);
  if (copied.measuredConfigHash !== measuredConfigHash || expiry <= Date.now() || expiry > Date.now() + 900_000) throw new Error('Invalid preflight expiry or config');
  const candidates = admins.filter(admin => admin.id === copied.adminId);
  if (candidates.length !== 1) throw new Error('Invalid preflight admin');
  const raw = decode(candidates[0]!.publicKey, 65);
  if (raw[0] !== 4) throw new Error('Invalid admin key');
  const key = await webcrypto.subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, decode(copied.signature, 64), message) !== true) throw new Error('Invalid preflight signature');
  if (Date.parse(copied.expiresAt) <= Date.now()) throw new Error('Preflight approval expired');
  return copied;
}


export async function authorizeEscrowPreflight(request: EscrowPreflightRequest, measuredConfigHash: string, store: EscrowAuthorizationStore): Promise<true> {
  const verified = await verifyEscrowPreflightSignature(request, measuredConfigHash);
  if (await store.consume({ kind: 'preflight', policyHash: measuredConfigHash, nonce: verified.nonce, expiresAt: verified.expiresAt, operatorId: verified.adminId, approverId: null, dryRun: true }) !== true) throw new Error('Preflight approval refused');
  return true;
}
