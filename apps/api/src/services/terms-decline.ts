// TC-3232: declining the Terms stops the account's renewals at the node, revoking each renewal lease the way
// stopping it from Settings or signing out does. Two kinds of lease are stopped:
// - leases OpenKey recorded (approval links): every one, under any session, through `revokeRenewalLeases`;
// - sign-in leases, which OpenKey signs and hands to the app without keeping a record: found by listing the
//   owner's active grants at the TinyCloud node, through a short-lived session the owner's managed key signs.
//   A lease is a grant to the node's renewer whose only ability is `tinycloud.delegation/renew` on one
//   `urn:cid:`; nothing else the owner granted is touched.
// An outside wallet's leases can't be signed for: they are reported, not stopped. Stopping is best effort and
// answers within a budget; whatever is still under way then finishes on its own.
import type { PrismaClient } from '@openkey/db';
import { TCWSessionManager, completeSessionSetup, ensureEip55, invoke, prepareSession } from '@tinycloud/node-sdk-wasm';
import { SIWE_DOMAIN } from '../routes/delegate-session';
import { signManagedKey } from './managed-key-signing';
import { discoverRenewalNodeIdentity } from './renewal-lease';
import { liveLeaseWhere, revokeRenewalLeases, revokeUnrecordedLease } from './renewal-lease-revocation';
import { trustedTinyCloudBootstrapHost } from './tinycloud-bootstrap';

/** How long the decline's answer waits; stopping carries on after that. */
const DECLINE_STOP_BUDGET_MS = 3_000;
const NODE_CALL_TIMEOUT_MS = 5_000;
/** The listing session's life: long enough for every page and revocation of one decline. */
const LISTING_SESSION_MS = 5 * 60_000;
const PAGE_SIZE = 100;
const MAX_PAGES = 50;
const RENEW = 'tinycloud.delegation/renew';
const OWNER_DID = /^did:pkh:eip155:[1-9][0-9]*:(0x[0-9a-fA-F]{40})$/;

export interface DeclineRenewalsReport {
  /** Leases the node confirmed stopped. */
  stopped: number;
  /** Leases found that the node did not confirm stopped. */
  notStopped: number;
  /** Recorded leases an outside wallet signed: only that wallet can stop them. */
  walletRequired: number;
  /** Whether the node's own list of the owner's leases was read to the end. False: some may still renew. */
  nodeChecked: boolean;
}

type DeclineDatabase = Pick<PrismaClient, 'renewalLease' | 'ethereumKey' | '$transaction'>;
type ManagedKey = { address: string; userId: string | null; sealingContext: string | null; sealedBlob: string };

export interface DeclineDeps {
  signManaged: (key: { userId: string | null; sealingContext: string | null }, sealedBlob: string, message: string) => Promise<string>;
  fetch: typeof fetch;
  now: () => Date;
}

const defaultDeps: DeclineDeps = { signManaged: signManagedKey, fetch, now: () => new Date() };

interface ListedGrant {
  cid?: unknown;
  delegatorDid?: unknown;
  delegateDid?: unknown;
  status?: unknown;
  resources?: unknown;
}

function ownerAddress(did: unknown): string | null {
  return typeof did === 'string' ? OWNER_DID.exec(did)?.[1]?.toLowerCase() ?? null : null;
}

/** A renewal lease the owner granted the node's renewer: one `urn:cid:` resource, `renew` only. */
function isRenewalLease(item: ListedGrant, address: string, renewerDid: string): item is ListedGrant & { cid: string; delegatorDid: string } {
  if (item.status !== 'active' || typeof item.cid !== 'string' || ownerAddress(item.delegatorDid) !== address.toLowerCase()) return false;
  if (item.delegateDid !== renewerDid || !Array.isArray(item.resources) || item.resources.length !== 1) return false;
  const [resource] = item.resources as Array<{ resource?: unknown; actions?: unknown }>;
  return typeof resource?.resource === 'string' && resource.resource.startsWith('urn:cid:') &&
    Array.isArray(resource.actions) && resource.actions.length === 1 && resource.actions[0] === RENEW;
}

async function nodeCall(deps: DeclineDeps, url: string, init: RequestInit): Promise<Response> {
  return deps.fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS) });
}

/**
 * Every active renewal lease `key`'s owner granted at `host`. The listing is signed by a session the owner key
 * delegates `tinycloud.delegation/list` on its account space for a few minutes: the node lists an account's
 * grants only to a session of that account. Null when the node's answers stop short of the last page.
 */
async function listedLeases(host: string, key: ManagedKey, renewerDid: string, deps: DeclineDeps): Promise<Array<{ cid: string; ownerDid: string }> | null> {
  const address = ensureEip55(key.address);
  const manager = new TCWSessionManager();
  const jwkText = manager.jwk(manager.createSessionKey('terms-decline'));
  if (!jwkText) return null;
  const issuedAt = deps.now();
  const prepared = prepareSession({
    address,
    chainId: 1,
    domain: SIWE_DOMAIN,
    issuedAt: issuedAt.toISOString(),
    expirationTime: new Date(issuedAt.getTime() + LISTING_SESSION_MS).toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${address}:account`,
    jwk: JSON.parse(jwkText) as Record<string, unknown>,
    abilities: { delegation: { '': ['tinycloud.delegation/list'] } },
  });
  const session = completeSessionSetup({ ...prepared, signature: await deps.signManaged(key, key.sealedBlob, prepared.siwe) });
  const activated = await nodeCall(deps, `${host}/delegate`, { method: 'POST', headers: session.delegationHeader as Record<string, string> });
  await activated.body?.cancel();
  if (!activated.ok) return null;

  const leases: Array<{ cid: string; ownerDid: string }> = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const headers = invoke(session, 'delegation', '', 'tinycloud.delegation/list', undefined) as Record<string, string>;
    const response = await nodeCall(deps, `${host}/delegation/query`, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({ direction: 'granted', status: 'active', limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }),
    });
    if (!response.ok) { await response.body?.cancel(); return null; }
    const body = await response.json() as { items?: unknown; nextCursor?: unknown };
    if (!Array.isArray(body.items)) return null;
    for (const item of body.items as ListedGrant[]) {
      if (item && typeof item === 'object' && isRenewalLease(item, address, renewerDid)) leases.push({ cid: item.cid, ownerDid: item.delegatorDid });
    }
    if (body.nextCursor === undefined) return leases;
    if (typeof body.nextCursor !== 'string' || cursors.has(body.nextCursor)) return null;
    cursors.add(body.nextCursor);
    cursor = body.nextCursor;
  }
  return null;
}

/**
 * Stops every renewal of `userId` the decline can reach, and reports it; never throws. Answers within the budget:
 * a lease not confirmed stopped by then is reported not stopped (a recorded one) or leaves `nodeChecked` false.
 */
export async function stopRenewalsOnDecline(database: DeclineDatabase, userId: string, deps: DeclineDeps = defaultDeps): Promise<DeclineRenewalsReport> {
  const progress = { stopped: 0, notStopped: 0, walletRequired: 0, nodeChecked: false, recordedSettled: false };
  const liveRecorded = await database.renewalLease.count({ where: liveLeaseWhere(userId, { kind: 'all' }, deps.now()) }).catch(() => 0);

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
    let complete = managed.length === keys.length;
    for (const key of managed) {
      const leases = await listedLeases(host, key, renewerDid, deps);
      if (!leases) { complete = false; continue; }
      // A lease OpenKey recorded is stopped by its record, which also marks it stopped in Settings.
      const known = new Set((await database.renewalLease.findMany({
        where: { userId, leaseCid: { in: leases.map((lease) => lease.cid) } }, select: { leaseCid: true },
      })).map((row) => row.leaseCid));
      for (const lease of leases) {
        if (known.has(lease.cid)) continue;
        if (await revokeUnrecordedLease(host, { ownerDid: lease.ownerDid, leaseCid: lease.cid }, key, deps)) progress.stopped++;
        else progress.notStopped++;
      }
    }
    progress.nodeChecked = complete;
  })().catch(() => undefined);

  const { promise: timedOut, resolve: timeUp } = Promise.withResolvers<'timeout'>();
  const timer = setTimeout(() => timeUp('timeout'), DECLINE_STOP_BUDGET_MS);
  const finished = await Promise.race([Promise.all([recorded, swept]).then(() => 'done' as const), timedOut]);
  clearTimeout(timer);
  const report = { stopped: progress.stopped, notStopped: progress.notStopped, walletRequired: progress.walletRequired, nodeChecked: progress.nodeChecked };
  if (finished === 'timeout') report.nodeChecked = false;
  // A recorded pass that failed or didn't finish in time: its live leases are not confirmed stopped.
  if (!progress.recordedSettled) report.notStopped += liveRecorded;
  return report;
}
