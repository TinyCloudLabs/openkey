// Account setup on OpenKey's own page (/widget/account-setup, routes/account-setup.ts).
//
// One approval does two things for the owner's managed key, in this order:
// 1. sets the account up on TinyCloud hosting (the bootstrap, `ownPageProvisionAuthority('account-setup')`);
// 2. publishes the owner's location record on the TinyCloud registry, naming the TinyCloud node for the six account
//    spaces, signed by the managed key.
// The record text is built here when the owner taps "Set up", stored on the request row and shown on the page. It is
// the only text the key signs: the publisher's prepared record must equal it byte for byte. Nothing the app sends
// reaches the record: the subject comes from the key, the chain is 1, the node is OpenKey's trusted TinyCloud node.
//
// Create-only is OpenKey's own choice: the registry accepts a record with a higher sequence, but this flow never
// writes over a record that exists. An owner with a record is told the account is set up (`present`).
import { createHash } from 'node:crypto';
import { getAddress } from 'viem';
import type { PrismaClient } from '@openkey/db';
import {
  BOOTSTRAP_SPACE_NAMES,
  DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL,
  canonicalLocationPayloadV2,
  registryOwnerSubjectV1,
  type LocationRecordV2Payload,
} from '@tinycloud/sdk-core';
import { publishLocationRecordV2 } from '@tinycloud/sdk-core/registry-publication';
import { signManagedKey, unsealManagedKey } from './managed-key-signing';
import { ownPageProvisionAuthority } from './provision-authority';
import { ensureTinyCloudBootstrap } from './tinycloud-bootstrap';

/** The record's owner subject is on chain 1 whatever chain an app signs in on. */
export const ACCOUNT_SETUP_CHAIN_ID = 1;
export const ACCOUNT_SETUP_PLACEMENT = 'tinycloud';
/** How long a prepared request may wait for the owner's approval. */
export const ACCOUNT_SETUP_TTL_MS = 5 * 60 * 1000;
/** How long one approve call holds a request; a crashed call frees it after this. */
export const ACCOUNT_SETUP_APPROVING_LEASE_MS = 2 * 60 * 1000;
/** How long one call holds the setup run and the publication. */
export const ACCOUNT_SETUP_PUBLISHING_LEASE_MS = 2 * 60 * 1000;
/**
 * The registry takes a record whose `updated_at` is within ten minutes of its clock. The stored text carries the time
 * the owner tapped "Set up", so it is published within nine minutes of that or not at all.
 */
export const ACCOUNT_SETUP_RECORD_WINDOW_MS = 9 * 60 * 1000;
export const ACCOUNT_SETUP_REGISTRY_URL = DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL;

const NODE_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

export class AccountSetupError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'AccountSetupError';
  }
}

type AccountSetupFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

async function readJsonObject(response: Response): Promise<Record<string, unknown> | null> {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) return null;
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/**
 * The DID of the node at `nodeUrl`, as the node states it twice: `/info` `nodeId` and the node-keys document's
 * `nodeDid` must agree. No redirects, five seconds, 64 KiB per answer. The publisher checks the same pair a second
 * time before it signs.
 */
export async function readNodeDid(nodeUrl: string, fetchImpl: AccountSetupFetch = fetch): Promise<string> {
  const read = async (path: string) => {
    let response: Response;
    try {
      response = await fetchImpl(`${nodeUrl}${path}`, { redirect: 'error', signal: AbortSignal.timeout(NODE_TIMEOUT_MS) });
    } catch {
      throw new AccountSetupError('account_setup_node_unavailable', "The TinyCloud node isn't answering.");
    }
    const body = response.ok ? await readJsonObject(response) : null;
    if (!body) throw new AccountSetupError('account_setup_node_unavailable', "The TinyCloud node isn't answering.");
    return body;
  };
  const [info, keys] = await Promise.all([read('/info'), read('/.well-known/tinycloud/node-keys')]);
  if (typeof info.nodeId !== 'string' || !info.nodeId.startsWith('did:key:') || keys.nodeDid !== info.nodeId) {
    throw new AccountSetupError('account_setup_node_unavailable', "The TinyCloud node didn't state one identity.");
  }
  return info.nodeId;
}

/** Has the owner a location record on the registry? Any answer other than a record or a clean 404 refuses. */
export async function registryHasRecord(address: string, fetchImpl: AccountSetupFetch = fetch): Promise<boolean> {
  const key = encodeURIComponent(getAddress(address));
  let response: Response;
  try {
    response = await fetchImpl(`${ACCOUNT_SETUP_REGISTRY_URL}/v2/locations/${key}`, {
      headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(NODE_TIMEOUT_MS),
    });
  } catch {
    throw new AccountSetupError('account_setup_registry_unavailable', "The TinyCloud registry isn't answering.");
  }
  if (response.status === 200) {
    const body = await readJsonObject(response);
    if (body && body.record && typeof body.record === 'object') return true;
  }
  if (response.status === 404) {
    const body = await readJsonObject(response);
    if (body && body.error === 'location record not found') return false;
  }
  throw new AccountSetupError('account_setup_registry_unavailable', "The TinyCloud registry isn't answering.");
}

/** The space URI of one of the owner's account spaces on chain 1. */
export function accountSpaceUri(address: string, name: string): string {
  return `tinycloud:pkh:eip155:${ACCOUNT_SETUP_CHAIN_ID}:${getAddress(address)}:${name}`;
}

/**
 * The exact record this setup publishes for an owner with no record: the TinyCloud node, read-write, for each of the
 * six account spaces and as the encryption node; sequence 0. The same text the publisher prepares when the registry
 * has no record (the publisher checks that at publish time).
 */
export function accountSetupPayload(input: { address: string; nodeUrl: string; nodeDid: string; at: Date }): {
  payload: string;
  payloadDigest: string;
} {
  const record: LocationRecordV2Payload = {
    version: 2,
    subject: registryOwnerSubjectV1(getAddress(input.address)),
    nodes: [{ did: input.nodeDid, url: input.nodeUrl }],
    spaces: BOOTSTRAP_SPACE_NAMES.map((name) => ({
      space: accountSpaceUri(input.address, name),
      nodes: [{ did: input.nodeDid, mode: 'read-write' as const }],
    })),
    encryptionNode: input.nodeDid,
    updated_at: input.at.toISOString(),
    sequence: 0,
  };
  const payload = canonicalLocationPayloadV2(record);
  return { payload, payloadDigest: createHash('sha256').update(payload).digest('hex') };
}

type SetupKey = { id: string; userId: string | null; address: string; keyType: string; sealedBlob: string | null; sealingContext: string | null };

export type AccountSetupRow = {
  id: string;
  userId: string;
  nodeUrl: string;
  nodeDid: string;
  payload: string;
  createdAt: Date;
};

/**
 * Publishes the stored record. `published` when the registry holds exactly the stored record (this call's write or
 * an earlier one), `present` when it holds any other record: OpenKey does not write over it.
 */
export async function publishAccountSetupRecord(
  row: AccountSetupRow, key: SetupKey, fetchImpl?: AccountSetupFetch,
): Promise<'published' | 'present'> {
  if (!key.sealedBlob) throw new AccountSetupError('account_setup_unavailable', 'This key cannot sign here.');
  const blob = key.sealedBlob;
  const node = { did: row.nodeDid, url: row.nodeUrl };
  let other = false;
  try {
    const record = await publishLocationRecordV2({
      registryUrl: ACCOUNT_SETUP_REGISTRY_URL,
      subject: registryOwnerSubjectV1(getAddress(key.address)),
      signer: { type: 'did:pkh', signMessage: (message) => signManagedKey(key, blob, message) },
      memberships: BOOTSTRAP_SPACE_NAMES.map((name) => ({ space: accountSpaceUri(key.address, name), node, mode: 'read-write' as const })),
      encryptionNode: node,
      now: () => row.createdAt,
      onPrepared: (prepared, current) => {
        other = current !== null;
        return current === null && canonicalLocationPayloadV2(prepared) === row.payload;
      },
      ...(fetchImpl ? { fetch: fetchImpl } : {}),
    });
    // The publisher answers with the registry's record as it stands when the registry holds the same placement.
    return canonicalLocationPayloadV2(record) === row.payload ? 'published' : 'present';
  } catch (error) {
    if (other) return 'present';
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new AccountSetupError('account_setup_record_changed', "The record OpenKey built doesn't match. Start setup over.");
    }
    throw new AccountSetupError('account_setup_registry_unavailable', "The TinyCloud registry didn't take the record.");
  }
}

export type AccountSetupRunResult =
  | { state: 'published' | 'present' }
  | { state: 'working' }
  | { state: 'failed'; code: string; message: string };

/**
 * Sets the account up on the row's node and publishes the record. Runs only for a consumed row (the owner approved
 * it): the caller holds the row's publishing lease.
 */
export async function runAccountSetup(
  prisma: PrismaClient, row: AccountSetupRow, key: SetupKey, fetchImpl?: AccountSetupFetch,
): Promise<AccountSetupRunResult> {
  if (key.keyType !== 'MANAGED' || !key.sealedBlob) {
    return { state: 'failed', code: 'account_setup_unavailable', message: 'This key cannot be set up here.' };
  }
  const blob = key.sealedBlob;
  const bootstrap = await ensureTinyCloudBootstrap({
    authority: ownPageProvisionAuthority('account-setup'),
    prisma,
    userId: row.userId,
    key: { id: key.id, address: key.address, keyType: key.keyType },
    privateKey: () => unsealManagedKey(key, blob),
    host: row.nodeUrl,
    chainId: ACCOUNT_SETUP_CHAIN_ID,
  });
  if (bootstrap.status === 'skipped') {
    return { state: 'failed', code: 'account_setup_unavailable', message: "Account setup isn't available on this server." };
  }
  if (bootstrap.status === 'failed') {
    if (bootstrap.errorCode === 'tinycloud_bootstrap_in_progress') return { state: 'working' };
    return { state: 'failed', code: bootstrap.errorCode, message: "Your spaces weren't created." };
  }
  if (bootstrap.status !== 'complete') return { state: 'working' };
  try {
    return { state: await publishAccountSetupRecord(row, key, fetchImpl) };
  } catch (error) {
    const failure = error instanceof AccountSetupError
      ? error
      : new AccountSetupError('account_setup_registry_unavailable', "The TinyCloud registry didn't take the record.");
    return { state: 'failed', code: failure.code, message: failure.message };
  }
}
