import { registryRecordSignOriginAllowed } from '@openkey/capability-review';
import {
  DEFAULT_REGISTRY_OWNER_CHAIN_ID,
  DEFAULT_TINYCLOUD_FALLBACK_HOST,
  DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL,
  REGISTRY_LOOKUP_MAX_BODY_BYTES,
  REGISTRY_NOT_FOUND_BODY,
  httpUrlToMultiaddr,
  registryOwnerKeyV2,
  registryOwnerSubjectV1,
  signLocationRecord,
  verifyLocationRecord,
} from '@tinycloud/sdk-core';
import { approvalRequestDigest, verifyApprovalPasskey, type ApprovalBinding, type ApprovalSubject, type RelyingParty } from './approval-passkey';
import { logOwnerLocationRecord } from '../log';

/**
 * Whether a first-party sign needs the owner's explicit say-so before the API publishes the account's public v1
 * location record. The ONLY place that decides it: `ownerLocationPublishAllowed` reads this constant and nothing else.
 *
 * - `required`: the sign request must carry `publishOwnerLocation: true` and a passkey assertion bound to the publish.
 */
export type OwnerLocationConsent = 'required' | 'silent';
export const OWNER_LOCATION_PUBLISH_CONSENT: OwnerLocationConsent = 'required';

/**
 * The one host a published record names: the SDK's default node, verbatim. Never derived from the bootstrap host
 * (`tee.node` is a trusted bootstrap host too): a record naming any other host locks the owner out of every SDK app.
 */
export const OWNER_LOCATION_NODE_HOST: string = DEFAULT_TINYCLOUD_FALLBACK_HOST;

const REGISTRY_CALL_TIMEOUT_MS = 5_000;

export interface OwnerLocationPublishRequest {
  /** The verified origin of the requesting site, as the sign route received it. */
  requestOrigin?: unknown;
  /** The sign request's explicit consent field. Only the boolean `true` counts. */
  publishOwnerLocation?: unknown;
  /** `{ challengeToken, response }` for the challenge from `/:keyId/owner-location/passkey`. */
  ownerLocationPasskeyAssertion?: unknown;
}

/** What `ownerLocationPublishAllowed` needs to check the owner's passkey assertion. */
export interface OwnerLocationConsentContext {
  db: Parameters<typeof verifyApprovalPasskey>[0];
  /** The account and the session the assertion's challenge was issued to. */
  subject: ApprovalSubject;
  keyId: string;
  /** The key's address, any case. */
  address: string;
  rp?: RelyingParty;
}

export const OWNER_LOCATION_PASSKEY_PURPOSE = 'owner_location_publish';

/**
 * What a passkey assertion for the publish confirms: this key, the v1 subject, the default node and the record's
 * version and sequence. An assertion issued for anything else does not verify.
 */
export function ownerLocationPublishBinding(keyId: string, address: string): ApprovalBinding {
  return {
    purpose: OWNER_LOCATION_PASSKEY_PURPOSE,
    requestDigest: approvalRequestDigest(
      keyId, registryOwnerSubjectV1(address, DEFAULT_REGISTRY_OWNER_CHAIN_ID), OWNER_LOCATION_NODE_HOST, 'v1', '0',
    ),
  };
}

/**
 * First-party origins only (the registry-record sign set), and consent as `OWNER_LOCATION_PUBLISH_CONSENT` requires.
 * Under `required` the sign request must say so (`publishOwnerLocation: true`) AND carry a passkey assertion for
 * `ownerLocationPublishBinding`. The assertion is always required here, whatever the account's passkey-approval
 * setting: an account without a passkey that counts for step-up cannot produce one, so it is not published for. A
 * refusal never fails the sign; it only means no publish. Call it before the key is unsealed.
 */
export async function ownerLocationPublishAllowed(
  request: OwnerLocationPublishRequest,
  context: OwnerLocationConsentContext,
  consent: OwnerLocationConsent = OWNER_LOCATION_PUBLISH_CONSENT,
): Promise<boolean> {
  if (!registryRecordSignOriginAllowed(request.requestOrigin)) return false;
  if (consent === 'silent') return true;
  if (request.publishOwnerLocation !== true) return false;
  let verified = false;
  if (request.ownerLocationPasskeyAssertion !== undefined && request.ownerLocationPasskeyAssertion !== null) {
    verified = await verifyApprovalPasskey(
      context.db, context.subject, ownerLocationPublishBinding(context.keyId, context.address),
      request.ownerLocationPasskeyAssertion, context.rp,
    ).then((result) => result === 'verified', () => false);
  }
  if (!verified) logOwnerLocationRecord('skipped_consent_not_verified');
  return verified;
}

/**
 * What tells the caller the account is hosted on the default node.
 * - `completed_now`: the bootstrap run that just finished moved the row to `complete` after its own probe and setup.
 * - `complete_row`: a `complete` row was already there, which is only a hint. `probe` asks the node itself (a fresh
 *   2xx on the account space) and runs after the registry reads, before the record is signed.
 */
export type OwnerLocationHostedSignal =
  | { kind: 'completed_now' }
  | { kind: 'complete_row'; probe: () => Promise<boolean> };

export interface EnsureOwnerLocationRecordInput {
  /** The owner's address, any case. */
  address: string;
  /** The host the account's bootstrap row is on. */
  hostedHost: string;
  /** Default `completed_now`. */
  hosted?: OwnerLocationHostedSignal;
  /**
   * Signs EIP-191 text: the hosting probe's session and the canonical record. The only uses of the owner's key; the key
   * itself never reaches this module, and the closure is dropped when the publish ends.
   */
  signMessage: (message: string) => Promise<string>;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

/** A busy account signs often: an owner already looked at is not looked at again for this long. */
export const OWNER_LOCATION_MEMO_MS = 5 * 60 * 1000;
const OWNER_LOCATION_MEMO_MAX = 1_000;
const checkedOwners = new Map<string, number>();

/** Test seam: forget which owners were looked at. */
export function resetOwnerLocationMemoForTests(): void {
  checkedOwners.clear();
}

function checkedRecently(owner: string, nowMs: number): boolean {
  if ((checkedOwners.get(owner) ?? 0) > nowMs) return true;
  if (checkedOwners.size >= OWNER_LOCATION_MEMO_MAX) {
    for (const [key, until] of checkedOwners) if (until <= nowMs) checkedOwners.delete(key);
    if (checkedOwners.size >= OWNER_LOCATION_MEMO_MAX) checkedOwners.clear();
  }
  checkedOwners.set(owner, nowMs + OWNER_LOCATION_MEMO_MS);
  return false;
}

/** `published`, `skipped_<reason>` or `failed_<status>`. Nothing else is logged. */
export type OwnerLocationOutcome = string;

type RegistryRead = 'absent' | 'exists' | 'unauthorized' | 'unexpected' | 'unreachable';

/**
 * Publishes the owner's public v1 location record (sequence 0, naming exactly the default node), create-only.
 * The caller has seen an affirmative hosted signal for `hostedHost`. Resolves with a short outcome code and never
 * throws; every non-affirmative or unclear answer skips, and a failed PUT is final (no retry, no append).
 */
export async function ensureOwnerLocationRecord(input: EnsureOwnerLocationRecordInput): Promise<OwnerLocationOutcome> {
  try {
    if (input.hostedHost !== OWNER_LOCATION_NODE_HOST) return 'skipped_not_default_node';
    const fetchImpl = input.fetchImpl ?? globalThis.fetch;
    const subject = registryOwnerSubjectV1(input.address, DEFAULT_REGISTRY_OWNER_CHAIN_ID);
    const base = DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL.replace(/\/+$/, '');
    const now = input.now?.() ?? new Date();
    const hosted = input.hosted ?? { kind: 'completed_now' };
    if (hosted.kind === 'complete_row' && checkedRecently(registryOwnerKeyV2(subject), now.getTime())) {
      return 'skipped_checked_recently';
    }

    // Registry reads first, without the key: v2 by owner key, then v1 by subject. Only a canonical 404 on both is absence.
    const v2 = await readRegistry(fetchImpl, `${base}/v2/locations/${encodeURIComponent(registryOwnerKeyV2(subject))}`);
    if (v2 !== 'absent') return `skipped_registry_${v2}`;
    const v1 = await readRegistry(fetchImpl, `${base}/v1/locations/${encodeURIComponent(subject)}`);
    if (v1 !== 'absent') return `skipped_registry_${v1}`;

    // A stale `complete` row proves nothing: only a fresh affirmative answer from the node does.
    if (hosted.kind === 'complete_row' && !(await hosted.probe().catch(() => false))) return 'skipped_not_hosted';

    const record = await signLocationRecord(
      {
        version: 1,
        subject,
        multiaddrs: [httpUrlToMultiaddr(OWNER_LOCATION_NODE_HOST)],
        updated_at: (input.now?.() ?? new Date()).toISOString(),
        sequence: 0,
      },
      { type: 'did:pkh', signMessage: input.signMessage },
    );
    // The record is checked locally, by the SDK's own verifier, before it leaves the process: an invalid one is never sent.
    if (!(await verifyLocationRecord(record).catch(() => false))) return 'skipped_record_invalid';

    const response = await fetchImpl(`${base}/v1/locations/${encodeURIComponent(subject)}`, {
      method: 'PUT',
      redirect: 'error',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify(record),
      signal: AbortSignal.timeout(REGISTRY_CALL_TIMEOUT_MS),
    });
    await response.body?.cancel().catch(() => undefined);
    return response.status >= 200 && response.status < 300 ? 'published' : `failed_${response.status}`;
  } catch {
    return 'failed_error';
  }
}

/** Fire and forget: runs outside the sign response, logs only the outcome code, never fails the sign. */
export function publishOwnerLocationInBackground(input: EnsureOwnerLocationRecordInput): void {
  void ensureOwnerLocationRecord(input).then(logOwnerLocationRecord, () => logOwnerLocationRecord('failed_error'));
}

async function readRegistry(fetchImpl: typeof fetch, url: string): Promise<RegistryRead> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      redirect: 'error',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(REGISTRY_CALL_TIMEOUT_MS),
    });
  } catch {
    return 'unreachable';
  }
  try {
    if (response.status === 404) {
      const body = await boundedText(response, REGISTRY_LOOKUP_MAX_BODY_BYTES);
      return body !== null && body.trim() === REGISTRY_NOT_FOUND_BODY ? 'absent' : 'unexpected';
    }
    await response.body?.cancel().catch(() => undefined);
    if (response.status === 200) return 'exists';
    if (response.status === 401 || response.status === 403) return 'unauthorized';
    return 'unexpected';
  } catch {
    return 'unreachable';
  }
}

/** The body as text, or null once it passes `maxBytes`. */
async function boundedText(response: Response, maxBytes: number): Promise<string | null> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}
