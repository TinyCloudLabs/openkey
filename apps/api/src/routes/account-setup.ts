// OpenKey's own account setup page (/widget/account-setup): the owner sets their account up on TinyCloud hosting.
//
// Every route is for a cookie session from an OpenKey browser origin: a bearer token or another site's Origin is
// refused before anything is read. A request row belongs to one user and one session, and every route finds it by
// `{ id, userId, sessionId }`. The record text, the chain and the node are the server's; a request field never
// changes them.
//
// prepare   the owner tapped "Set up": the request row (created on this tap) with the exact record text, or `present`.
// passkey   a passkey challenge bound to the row id and the stored record digest; without a step-up passkey, the
//           email code is offered instead (or nothing, when the account has no verified email).
// email-code  mails the code, only for an account without a step-up passkey, only on the owner's tap.
// approve   one approval per row: lease, step-up, consume, then the setup and the record.
// finish    the setup's status, and the next attempt of a consumed row's setup and record.
import { randomUUID } from 'node:crypto';
import { Hono, type Context } from 'hono';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { requireSession, type SessionContext } from '../middleware/session';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';
import {
  PASSKEY_APPROVAL_INVALID,
  PASSKEY_APPROVAL_NOT_STEP_UP,
  PASSKEY_APPROVAL_REQUIRED,
  approvalRequestDigest,
  createApprovalPasskeyChallenge,
  verifyApprovalPasskey,
} from '../services/approval-passkey';
import {
  ACCOUNT_SETUP_APPROVING_LEASE_MS,
  ACCOUNT_SETUP_CHAIN_ID,
  ACCOUNT_SETUP_PLACEMENT,
  ACCOUNT_SETUP_PUBLISHING_LEASE_MS,
  ACCOUNT_SETUP_RECORD_WINDOW_MS,
  ACCOUNT_SETUP_TTL_MS,
  AccountSetupError,
  accountSetupPayload,
  readNodeDid,
  registryHasRecord,
  runAccountSetup,
} from '../services/account-setup';
import { gradeAccountSetupCode, sendAccountSetupCode } from '../services/account-setup-step-up';
import { trustedTinyCloudBootstrapHost } from '../services/tinycloud-bootstrap';

export const ACCOUNT_SETUP_UNAVAILABLE = {
  error: "Account setup isn't available here. Finish setup in TinyCloud One.",
  code: 'ACCOUNT_SETUP_UNAVAILABLE',
} as const;
const WALLET_KEY_UNAVAILABLE = {
  error: "OpenKey can't set this up for a wallet key. Finish setup in TinyCloud One.",
  code: 'ACCOUNT_SETUP_UNAVAILABLE',
  reason: 'wallet_key',
} as const;
const NO_STEP_UP = {
  error: 'Add a passkey in OpenKey settings to set up TinyCloud.',
  code: 'ACCOUNT_SETUP_UNAVAILABLE',
  reason: 'no_step_up',
} as const;
const KEY_NOT_FOUND = { error: 'This key is not one of your keys.', code: 'account_setup_key_not_found' } as const;
const REQUEST_NOT_FOUND = { error: 'This setup request has ended. Start setup over.', code: 'account_setup_not_found' } as const;
const REQUEST_USED = { error: 'This setup request has been used. Start setup over.', code: 'account_setup_used' } as const;
const CODE_INVALID = { error: "That code didn't match. Check the email for the latest code.", code: 'account_setup_code_invalid' } as const;
const CODE_ENDED = { error: 'That code has ended. Send a new code.', code: 'account_setup_code_ended' } as const;
const WINDOW_PASSED = {
  error: 'The record OpenKey built has run out of time. Start setup over.',
  code: 'account_setup_record_window_passed',
} as const;

let prisma: PrismaClient | undefined;
const db = () => prisma ??= createPrismaClient();

export const accountSetupRouter = new Hono<SessionContext>();

accountSetupRouter.use('*', async (c, next) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  await next();
});
accountSetupRouter.use('*', requireSession);

async function body(c: Context<SessionContext>): Promise<Record<string, unknown>> {
  const value = await c.req.json().catch(() => null);
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

/** An exact web origin, or null. Shown to the owner and stored on the row; never a reason to allow anything. */
function exactOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin === value ? value : null;
  } catch {
    return null;
  }
}

const maskEmail = (email: string) => {
  const at = email.indexOf('@');
  return at > 0 ? `${email[0]}•••${email.slice(at)}` : '•••';
};

const SETUP_KEY_SELECT = { id: true, userId: true, address: true, keyType: true, sealedBlob: true, sealingContext: true } as const;

async function hasStepUpPasskey(userId: string): Promise<boolean> {
  return await db().passkey.count({ where: { userId, countsForStepUp: true } }) > 0;
}

/** The live (unconsumed, unsuperseded, unexpired) row of this user and session. */
function liveRow(c: Context<SessionContext>, now: Date) {
  return db().accountSetupRequest.findFirst({
    where: {
      id: c.req.param('id'), userId: c.get('user').id, sessionId: c.get('session').id,
      consumedAt: null, supersededAt: null, expiresAt: { gt: now },
    },
  });
}

accountSetupRouter.post('/prepare', async (c) => {
  const user = c.get('user');
  const session = c.get('session');
  const input = await body(c);
  if (typeof input.keyId !== 'string' || input.keyId.length === 0 || input.keyId.length > 64) {
    return c.json(KEY_NOT_FOUND, 404);
  }
  if (input.placement !== undefined && input.placement !== ACCOUNT_SETUP_PLACEMENT) {
    return c.json(ACCOUNT_SETUP_UNAVAILABLE, 400);
  }
  const key = await db().ethereumKey.findFirst({
    where: { id: input.keyId, userId: user.id, archivedAt: null }, select: SETUP_KEY_SELECT,
  });
  if (!key) return c.json(KEY_NOT_FOUND, 404);
  if (key.keyType !== 'MANAGED' || !key.sealedBlob) return c.json(WALLET_KEY_UNAVAILABLE, 403);

  let nodeUrl: string;
  let nodeDid: string;
  try {
    if (await registryHasRecord(key.address)) return c.json({ state: 'present' });
    nodeUrl = trustedTinyCloudBootstrapHost();
    nodeDid = await readNodeDid(nodeUrl);
  } catch (error) {
    if (error instanceof AccountSetupError) return c.json({ error: error.message, code: error.code }, 503);
    return c.json(ACCOUNT_SETUP_UNAVAILABLE, 503);
  }

  const now = new Date();
  // An account that can confirm neither by passkey nor by email code gets no row.
  const stepUp = await hasStepUpPasskey(user.id) ? 'passkey' : await emailVerified(user.id, user.email) ? 'email' : null;
  if (stepUp === null) return c.json(NO_STEP_UP, 403);
  const leaseStart = new Date(now.getTime() - ACCOUNT_SETUP_APPROVING_LEASE_MS);
  const row = await db().$transaction(async (tx) => {
    // One prepare per key at a time: the key row lock orders them, so two taps cannot leave two fresh rows.
    await tx.$queryRaw`SELECT id FROM "ethereum_keys" WHERE id = ${key.id} FOR UPDATE`;
    const live = await tx.accountSetupRequest.findFirst({
      where: {
        keyId: key.id, userId: user.id, sessionId: session.id,
        consumedAt: null, supersededAt: null, approvingAt: null, expiresAt: { gt: now },
      },
      orderBy: { createdAt: 'desc' },
    });
    if (live) return live;
    // A row another call is approving keeps its lease; any other open row for the key ends here.
    await tx.accountSetupRequest.updateMany({
      where: {
        keyId: key.id, consumedAt: null, supersededAt: null,
        OR: [{ approvingAt: null }, { approvingAt: { lt: leaseStart } }],
      },
      data: { supersededAt: now },
    });
    const record = accountSetupPayload({ address: key.address, nodeUrl, nodeDid, at: now });
    return tx.accountSetupRequest.create({ data: {
      id: randomUUID(),
      userId: user.id,
      sessionId: session.id,
      keyId: key.id,
      chainId: ACCOUNT_SETUP_CHAIN_ID,
      requestOrigin: exactOrigin(input.requestOrigin),
      placement: ACCOUNT_SETUP_PLACEMENT,
      nodeUrl,
      nodeDid,
      payload: record.payload,
      payloadDigest: record.payloadDigest,
      expiresAt: new Date(now.getTime() + ACCOUNT_SETUP_TTL_MS),
      createdAt: now,
    } });
  });
  return c.json({
    state: 'ready',
    id: row.id,
    record: row.payload,
    nodeUrl: row.nodeUrl,
    expiresAt: row.expiresAt.toISOString(),
    stepUp,
  });
});

async function emailVerified(userId: string, email: string | undefined): Promise<boolean> {
  if (!email) return false;
  const user = await db().user.findUnique({ where: { id: userId }, select: { emailVerified: true } });
  return user?.emailVerified === true;
}

accountSetupRouter.post('/:id/passkey', async (c) => {
  const user = c.get('user');
  const session = c.get('session');
  const row = await liveRow(c, new Date());
  if (!row) return c.json(REQUEST_NOT_FOUND, 404);
  const offer = await createApprovalPasskeyChallenge(
    db(), { sessionId: session.id, userId: user.id },
    { purpose: 'account_setup', requestDigest: approvalRequestDigest(row.id, row.payloadDigest) },
  );
  if (offer) return c.json({ stepUp: 'passkey', ...offer });
  if (await emailVerified(user.id, user.email)) return c.json({ stepUp: 'email', email: maskEmail(user.email) });
  return c.json(NO_STEP_UP, 403);
});

accountSetupRouter.post('/:id/email-code', async (c) => {
  const user = c.get('user');
  const session = c.get('session');
  const row = await liveRow(c, new Date());
  if (!row) return c.json(REQUEST_NOT_FOUND, 404);
  // The email code is for an account with no step-up passkey only: it never stands in for one.
  if (await hasStepUpPasskey(user.id)) return c.json(PASSKEY_APPROVAL_REQUIRED, 403);
  if (!await emailVerified(user.id, user.email)) return c.json(NO_STEP_UP, 403);
  const sent = await sendAccountSetupCode(db(), { sessionId: session.id, requestId: row.id, email: user.email });
  if (sent === 'unavailable') return c.json(ACCOUNT_SETUP_UNAVAILABLE, 503);
  return c.json({ sent: sent === 'sent', email: maskEmail(user.email) });
});

type StepUpRefusal = { body: { error: string; code: string }; status: 403 };

async function stepUpRefusal(
  c: Context<SessionContext>, row: { id: string; payloadDigest: string }, input: Record<string, unknown>,
): Promise<StepUpRefusal | null> {
  const user = c.get('user');
  const session = c.get('session');
  const subject = { sessionId: session.id, userId: user.id };
  if (input.passkeyAssertion !== undefined) {
    const result = await verifyApprovalPasskey(db(), subject, {
      purpose: 'account_setup', requestDigest: approvalRequestDigest(row.id, row.payloadDigest),
    }, input.passkeyAssertion);
    if (result === 'verified') return null;
    return { body: result === 'not_step_up' ? PASSKEY_APPROVAL_NOT_STEP_UP : PASSKEY_APPROVAL_INVALID, status: 403 };
  }
  if (input.emailCode !== undefined) {
    if (await hasStepUpPasskey(user.id)) return { body: PASSKEY_APPROVAL_REQUIRED, status: 403 };
    const grade = await gradeAccountSetupCode(db(), { sessionId: session.id, requestId: row.id, code: input.emailCode });
    if (grade === 'match') return null;
    return { body: grade === 'missing' ? CODE_ENDED : CODE_INVALID, status: 403 };
  }
  return { body: PASSKEY_APPROVAL_REQUIRED, status: 403 };
}

accountSetupRouter.post('/:id/approve', async (c) => {
  const user = c.get('user');
  const session = c.get('session');
  const id = c.req.param('id');
  const input = await body(c);
  const now = new Date();
  // 1. The lease: one approve call at a time holds the row.
  const lease = new Date(now);
  const leased = await db().accountSetupRequest.updateMany({
    where: {
      id, userId: user.id, sessionId: session.id, consumedAt: null, supersededAt: null, expiresAt: { gt: now },
      OR: [{ approvingAt: null }, { approvingAt: { lt: new Date(now.getTime() - ACCOUNT_SETUP_APPROVING_LEASE_MS) } }],
    },
    data: { approvingAt: lease },
  });
  if (leased.count !== 1) return c.json(REQUEST_USED, 409);
  const row = await db().accountSetupRequest.findUniqueOrThrow({ where: { id } });
  // 2. The owner's step-up for this row. A refusal frees the lease so the owner can retry.
  const refusal = await stepUpRefusal(c, row, input);
  if (refusal) {
    await db().accountSetupRequest.updateMany({ where: { id, approvingAt: lease, consumedAt: null }, data: { approvingAt: null } });
    return c.json(refusal.body, refusal.status);
  }
  // 3. Consume: only while this call's lease holds and no newer prepare superseded the row.
  const consumed = await db().accountSetupRequest.updateMany({
    where: { id, approvingAt: lease, supersededAt: null, consumedAt: null },
    data: { consumedAt: new Date(), outcome: 'pending' },
  });
  if (consumed.count !== 1) return c.json(REQUEST_USED, 409);
  return c.json(await advance(id, user.id, session.id));
});

accountSetupRouter.post('/:id/finish', async (c) => {
  const row = await db().accountSetupRequest.findFirst({
    where: { id: c.req.param('id'), userId: c.get('user').id, sessionId: c.get('session').id, consumedAt: { not: null } },
    select: { id: true },
  });
  if (!row) return c.json(REQUEST_NOT_FOUND, 404);
  return c.json(await advance(row.id, c.get('user').id, c.get('session').id));
});

type SetupState =
  | { state: 'published' | 'present' | 'working' }
  | { state: 'failed'; code: string; error: string; retry: boolean };

/**
 * The next step of a consumed row: its outcome when it has one; otherwise, under the row's publishing lease, the setup
 * run and the record. A call that finds the lease held answers `working`.
 */
async function advance(id: string, userId: string, sessionId: string): Promise<SetupState> {
  const now = new Date();
  const row = await db().accountSetupRequest.findFirstOrThrow({ where: { id, userId, sessionId } });
  if (row.outcome === 'published' || row.outcome === 'present') return { state: row.outcome };
  if (row.outcome === 'failed') return { state: 'failed', code: row.failureCode ?? WINDOW_PASSED.code, error: WINDOW_PASSED.error, retry: false };
  if (now.getTime() - row.createdAt.getTime() > ACCOUNT_SETUP_RECORD_WINDOW_MS) {
    await db().accountSetupRequest.updateMany({ where: { id, outcome: 'pending' }, data: { outcome: 'failed', failureCode: WINDOW_PASSED.code } });
    return { state: 'failed', code: WINDOW_PASSED.code, error: WINDOW_PASSED.error, retry: false };
  }
  const lease = new Date(now);
  const claimed = await db().accountSetupRequest.updateMany({
    where: {
      id, outcome: 'pending',
      OR: [{ publishingAt: null }, { publishingAt: { lt: new Date(now.getTime() - ACCOUNT_SETUP_PUBLISHING_LEASE_MS) } }],
    },
    data: { publishingAt: lease },
  });
  if (claimed.count !== 1) return { state: 'working' };
  const key = await db().ethereumKey.findFirst({ where: { id: row.keyId, userId, archivedAt: null }, select: SETUP_KEY_SELECT });
  const result = key
    ? await runAccountSetup(db(), row, key)
    : { state: 'failed' as const, code: 'account_setup_key_not_found', message: KEY_NOT_FOUND.error };
  if (result.state === 'published' || result.state === 'present') {
    await db().accountSetupRequest.updateMany({
      where: { id, publishingAt: lease, outcome: 'pending' }, data: { outcome: result.state, failureCode: null },
    });
    return { state: result.state };
  }
  await db().accountSetupRequest.updateMany({
    where: { id, publishingAt: lease, outcome: 'pending' },
    data: { publishingAt: null, failureCode: result.state === 'failed' ? result.code : null },
  });
  if (result.state === 'failed') return { state: 'failed', code: result.code, error: result.message, retry: true };
  return { state: 'working' };
}
