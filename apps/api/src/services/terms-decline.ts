// TC-3232: declining the Terms stops the account's renewals at the node, revoking each renewal lease the way
// stopping it from Settings or signing out does. Two kinds of lease are stopped:
// - leases OpenKey recorded (approval links): every one, under any session, through `revokeRenewalLeases`;
// - sign-in leases, which OpenKey signs and hands to the app without keeping a record: found by listing the
//   owner's active grants at the TinyCloud node, through a short-lived session the owner's managed key signs.
//   A lease is a grant to the node's renewer whose only ability is `tinycloud.delegation/renew` on one
//   `urn:cid:`; nothing else the owner granted is touched.
// An outside wallet's leases can't be signed for: they are reported, not stopped. Stopping is best effort and
// answers within a budget; whatever is still under way then finishes on its own. No new lease can be signed
// while the account hasn't accepted (every route that signs one is behind the Terms gate), but an app admits a
// sign-in lease a few seconds after the sign-in that signed it, so one admitted just after the listing would be
// missed: a second pass runs once that window has passed. It is in-process (a restart drops it) and is skipped
// if the account has accepted by then, so a lease signed after accepting is not revoked.
import type { PrismaClient } from '@openkey/db';
import { TCWSessionManager, completeSessionSetup, ensureEip55, invoke, prepareSession } from '@tinycloud/node-sdk-wasm';
import { SIWE_DOMAIN } from '../routes/delegate-session';
import { signManagedKey } from './managed-key-signing';
import { discoverRenewalNodeIdentity } from './renewal-lease';
import { liveLeaseWhere, revokeRenewalLeases, revokeUnrecordedLease } from './renewal-lease-revocation';
import { trustedTinyCloudBootstrapHost } from './tinycloud-bootstrap';
import { hasAcceptedTerms } from './terms';

/** How long the decline's answer waits; stopping carries on after that. */
const DECLINE_STOP_BUDGET_MS = 3_000;
/** An app admits a sign-in lease within 5 s of the sign-in; the second pass waits that out with margin. */
const ADMISSION_WINDOW_MS = 15_000;
const NODE_CALL_TIMEOUT_MS = 5_000;
/** The listing session's life: long enough for every page and revocation of one decline. */
const LISTING_SESSION_MS = 5 * 60_000;
const PAGE_SIZE = 100;
const MAX_PAGES = 50;
/** OpenKey's sign-ins are issued on chain 1; the node lists an account's grants by its exact owner DID. */
const LISTED_CHAIN_ID = 1;
const RENEW = 'tinycloud.delegation/renew';
const OWNER_DID = /^did:pkh:eip155:[1-9][0-9]*:(0x[0-9a-fA-F]{40})$/;
/** A CIDv1 in base32 (the node's form); anything else is not a lease OpenKey will sign a revocation for. */
const CID = /^b[a-z2-7]{58,118}$/;

export interface DeclineRenewalsReport {
  /** Leases the node confirmed stopped. */
  stopped: number;
  /**
   * Leases found that the node did not confirm stopped: recorded ones the budget ran out on, and lease-shaped
   * entries the node listed with a CID that is not one (never signed for).
   */
  notStopped: number;
  /** Recorded leases an outside wallet signed: only that wallet can stop them. */
  walletRequired: number;
  /** Whether the node's list of the owner's leases, within `nodeScope`, was read to the end. False: some may still renew. */
  nodeChecked: boolean;
  /** What the node list covered: the node and the chain IDs the owner was listed as. Null when no list was read. */
  nodeScope: { node: string; chainIds: number[] } | null;
}

type DeclineDatabase = Pick<PrismaClient, 'renewalLease' | 'ethereumKey' | 'termsAcceptance' | '$transaction'>;
type ManagedKey = { address: string; userId: string | null; sealingContext: string | null; sealedBlob: string };

export interface DeclineDeps {
  signManaged: (key: { userId: string | null; sealingContext: string | null }, sealedBlob: string, message: string) => Promise<string>;
  fetch: typeof fetch;
  now: () => Date;
  /** Runs the second pass once the admission window has passed. */
  afterAdmissionWindow: (pass: () => Promise<void>) => void;
}

export const defaultDeclineDeps: DeclineDeps = {
  signManaged: signManagedKey,
  fetch,
  now: () => new Date(),
  afterAdmissionWindow: (pass) => { setTimeout(() => void pass(), ADMISSION_WINDOW_MS).unref?.(); },
};

interface ListedGrant {
  cid?: unknown;
  delegatorDid?: unknown;
  delegateDid?: unknown;
  status?: unknown;
  resources?: unknown;
}

interface Progress {
  stopped: number;
  notStopped: number;
  walletRequired: number;
  nodeChecked: boolean;
  nodeScope: DeclineRenewalsReport['nodeScope'];
  recordedSettled: boolean;
}

function ownerAddress(did: unknown): string | null {
  return typeof did === 'string' ? OWNER_DID.exec(did)?.[1]?.toLowerCase() ?? null : null;
}

/**
 * A renewal lease the owner granted the node's renewer: one `urn:cid:` resource, `renew` only. Its own CID is
 * checked apart (`CID`): a lease-shaped entry whose CID is not a CID is never put into a message the owner signs.
 */
function isRenewalLease(item: ListedGrant, address: string, renewerDid: string): item is ListedGrant & { delegatorDid: string } {
  if (item.status !== 'active') return false;
  if (ownerAddress(item.delegatorDid) !== address.toLowerCase() || item.delegateDid !== renewerDid) return false;
  if (!Array.isArray(item.resources) || item.resources.length !== 1) return false;
  const [resource] = item.resources as Array<{ resource?: unknown; actions?: unknown }>;
  return typeof resource?.resource === 'string' && resource.resource.startsWith('urn:cid:') &&
    Array.isArray(resource.actions) && resource.actions.length === 1 && resource.actions[0] === RENEW;
}

async function nodeCall(deps: DeclineDeps, url: string, init: RequestInit): Promise<Response> {
  return deps.fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS) });
}

interface ListedLeases {
  /** Leases with a well-formed CID: these are revoked. */
  leases: Array<{ cid: string; ownerDid: string }>;
  /** Lease-shaped entries whose CID is not a CID: never signed for, so reported not stopped. */
  malformed: number;
  /** False when the node's answers stop short of the last page; what was found before that is still stopped. */
  complete: boolean;
}

/**
 * The active renewal leases `key`'s owner granted at `host`. The listing is signed by a session the owner key
 * delegates `tinycloud.delegation/list` on its account space for a few minutes: the node lists an account's
 * grants only to a session of that account.
 */
async function listedLeases(host: string, key: ManagedKey, renewerDid: string, deps: DeclineDeps): Promise<ListedLeases> {
  const partial: ListedLeases = { leases: [], malformed: 0, complete: false };
  const address = ensureEip55(key.address);
  const manager = new TCWSessionManager();
  const jwkText = manager.jwk(manager.createSessionKey('terms-decline'));
  if (!jwkText) return partial;
  const issuedAt = deps.now();
  const prepared = prepareSession({
    address,
    chainId: LISTED_CHAIN_ID,
    domain: SIWE_DOMAIN,
    issuedAt: issuedAt.toISOString(),
    expirationTime: new Date(issuedAt.getTime() + LISTING_SESSION_MS).toISOString(),
    spaceId: `tinycloud:pkh:eip155:${LISTED_CHAIN_ID}:${address}:account`,
    jwk: JSON.parse(jwkText) as Record<string, unknown>,
    abilities: { delegation: { '': ['tinycloud.delegation/list'] } },
  });
  const session = completeSessionSetup({ ...prepared, signature: await deps.signManaged(key, key.sealedBlob, prepared.siwe) });
  const activated = await nodeCall(deps, `${host}/delegate`, { method: 'POST', headers: session.delegationHeader as Record<string, string> });
  await activated.body?.cancel();
  if (!activated.ok) return partial;

  const cursors = new Set<string>();
  let cursor: string | undefined;
  try {
    for (let page = 0; page < MAX_PAGES; page++) {
      const headers = invoke(session, 'delegation', '', 'tinycloud.delegation/list', undefined) as Record<string, string>;
      const response = await nodeCall(deps, `${host}/delegation/query`, {
        method: 'POST',
        headers: { ...headers, 'content-type': 'application/json' },
        body: JSON.stringify({ direction: 'granted', status: 'active', limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }),
      });
      if (!response.ok) { await response.body?.cancel(); return partial; }
      const body = await response.json() as { items?: unknown; nextCursor?: unknown };
      if (!Array.isArray(body.items)) return partial;
      for (const item of body.items as ListedGrant[]) {
        if (!item || typeof item !== 'object' || !isRenewalLease(item, address, renewerDid)) continue;
        if (typeof item.cid === 'string' && CID.test(item.cid)) partial.leases.push({ cid: item.cid, ownerDid: item.delegatorDid });
        else partial.malformed++;
      }
      if (body.nextCursor === undefined) return { ...partial, complete: true };
      if (typeof body.nextCursor !== 'string' || cursors.has(body.nextCursor)) return partial;
      cursors.add(body.nextCursor);
      cursor = body.nextCursor;
    }
  } catch {
    // A page that fails or times out ends the listing; the leases already found are still stopped.
  }
  return partial;
}

/** One pass over every lease the decline can reach, counted into `progress` as it goes. Never throws. */
async function stopOnce(database: DeclineDatabase, userId: string, deps: DeclineDeps, progress: Progress): Promise<void> {
  const recorded = (async () => {
    const report = await revokeRenewalLeases(database, userId, { kind: 'all' }, undefined, { waitForLock: false }).catch(() => null);
    if (!report) return;
    progress.stopped += report.stopped.length;
    progress.notStopped += report.notStopped.filter((lease) => lease.reason === 'node_unavailable').length;
    progress.walletRequired += report.notStopped.filter((lease) => lease.reason === 'wallet_required').length;
    progress.recordedSettled = true;
  })();

  const swept = (async () => {
    const keys = await database.ethereumKey.findMany({
      where: { userId },
      select: { address: true, keyType: true, sealedBlob: true, userId: true, sealingContext: true },
    });
    const managed = keys.filter((key): key is typeof key & { sealedBlob: string } => key.keyType === 'MANAGED' && key.sealedBlob !== null);
    // No key at all: nothing could have been granted. Only outside wallets: their node lists can't be read.
    if (managed.length === 0) { progress.nodeChecked = keys.length === 0; return; }
    const host = trustedTinyCloudBootstrapHost();
    const { renewerDid } = await discoverRenewalNodeIdentity(host, deps.fetch);
    progress.nodeScope = { node: host, chainIds: [LISTED_CHAIN_ID] };
    let complete = managed.length === keys.length;
    for (const key of managed) {
      const listed: ListedLeases = await listedLeases(host, key, renewerDid, deps).catch(() => ({ leases: [], malformed: 0, complete: false }));
      if (!listed.complete) complete = false;
      progress.notStopped += listed.malformed;
      if (listed.leases.length === 0) continue;
      // A lease OpenKey recorded is stopped by its record, which also marks it stopped in Settings.
      const known = new Set((await database.renewalLease.findMany({
        where: { userId, leaseCid: { in: listed.leases.map((lease) => lease.cid) } }, select: { leaseCid: true },
      })).map((row) => row.leaseCid));
      for (const lease of listed.leases) {
        if (known.has(lease.cid)) continue;
        if (await revokeUnrecordedLease(host, { ownerDid: lease.ownerDid, leaseCid: lease.cid }, key, deps)) progress.stopped++;
        else progress.notStopped++;
      }
    }
    progress.nodeChecked = complete;
  })().catch(() => undefined);

  await Promise.all([recorded, swept]);
}

const fresh = (): Progress => ({ stopped: 0, notStopped: 0, walletRequired: 0, nodeChecked: false, nodeScope: null, recordedSettled: false });

/**
 * Stops every renewal of `userId` the decline can reach, and reports it; never throws. Answers within the budget:
 * a lease not confirmed stopped by then is reported not stopped (a recorded one) or leaves `nodeChecked` false.
 * Once the first pass is over, a second one runs after the admission window; it is not reported.
 */
export async function stopRenewalsOnDecline(database: DeclineDatabase, userId: string, deps: DeclineDeps = defaultDeclineDeps): Promise<DeclineRenewalsReport> {
  const progress = fresh();
  const liveRecorded = await database.renewalLease.count({ where: liveLeaseWhere(userId, { kind: 'all' }, deps.now()) }).catch(() => 0);
  const firstPass = stopOnce(database, userId, deps, progress);
  void firstPass.then(() => deps.afterAdmissionWindow(async () => {
    // Accepted since: a lease signed now is one the person agreed to. Unknown: stop, the safe side.
    if (await hasAcceptedTerms(database, userId).catch(() => false)) return;
    await stopOnce(database, userId, deps, fresh());
  }));

  const { promise: timedOut, resolve: timeUp } = Promise.withResolvers<'timeout'>();
  const timer = setTimeout(() => timeUp('timeout'), DECLINE_STOP_BUDGET_MS);
  const finished = await Promise.race([firstPass.then(() => 'done' as const), timedOut]);
  clearTimeout(timer);
  const report: DeclineRenewalsReport = {
    stopped: progress.stopped, notStopped: progress.notStopped, walletRequired: progress.walletRequired,
    nodeChecked: finished === 'done' && progress.nodeChecked, nodeScope: progress.nodeScope,
  };
  // A recorded pass that failed or didn't finish in time: its live leases are not confirmed stopped.
  if (!progress.recordedSettled) report.notStopped += liveRecorded;
  return report;
}
