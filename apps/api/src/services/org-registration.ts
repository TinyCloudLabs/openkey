import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { compactVerify, importJWK, type JWK, type JWTPayload } from 'jose';
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { Prisma, PrismaClient } from '@openkey/db';
import { generatePrivateKey, getAddressFromPrivateKey, seal, type TeeClient } from '@openkey/tee';
import { canonicalSignatureHash, controllerDidForAddress, OrgKeyRefusal } from './org-keys';
import { createSealingContext, deriveKeyForRecord } from './key-sealing';

const INTENT_ISSUER = 'did:web:issuer.credentials.org';
const INTENT_AUDIENCE = 'https://api.openkey.so';
const INTENT_DID_URL = 'https://issuer.credentials.org/.well-known/did.json';
const PROOF_ISSUER = 'https://api.openkey.so/api/auth';
const PROOF_AUDIENCE = 'https://witness.credentials.org';
const PURPOSE = 'org-registration/v1';
const CHALLENGE_DOMAIN = 'tinycloud:org-key:org-registration:v1';
const WINDOW_MS = 5 * 60 * 1000;
const FORCED_REFRESH_INTERVAL_MS = 10_000;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ORG_ID = /^o[a-z2-7]{26}$/;
const RESERVED_HANDLES = new Set([
  'issuer', 'orgs', 'witness', 'control', 'account', 'www', 'api', 'app', 'admin', 'mail', 'email',
  'smtp', 'mx', 'auth', 'login', 'id', 'oauth', 'openkey', 'tinycloud-internal', 'status', 'docs',
  'cdn', 'static', 'assets', 'pages', 'billing', 'pay', 'support', 'help', 'security', 'abuse',
  'postmaster', 'hostmaster', 'webmaster', 'root', 'ns', 'ns1', 'ns2', 'dns', 'test', 'staging', 'dev', 'preview',
]);
const INTENT_FIELDS = ['iss', 'aud', 'registrationId', 'orgId', 'nonce', 'handle', 'displayName', 'purpose', 'iat', 'exp'];
const REQUEST_FIELDS = ['intentJws', 'registrationId', 'orgId', 'nonce', 'handle', 'orgName', 'challengeNonce', 'assertion'];
const utf8 = new TextDecoder('utf-8', { fatal: true });

export interface OrgRegistrationIntent {
  iss: string;
  aud: string;
  registrationId: string;
  orgId: string;
  nonce: string;
  handle: string;
  displayName: string;
  purpose: string;
  iat: number;
  exp: number;
}

export interface OrgRegistrationProof extends JWTPayload {
  iss: string;
  aud: string;
  sub: string;
  registrationId: string;
  orgId: string;
  nonce: string;
  handle: string;
  displayName: string;
  keyId: string;
  controllerDid: string;
  purpose: string;
  jti: string;
  iat: number;
  exp: number;
}

export interface OrgRegistrationActor {
  userId: string;
  sessionId: string;
  origin: string | undefined;
  rpID: string;
  expectedOrigin: string;
}

export type OrgRegistrationFetch = (url: string, init?: RequestInit) => Promise<Response>;
export type OrgRegistrationSigner = (claims: OrgRegistrationProof) => Promise<string>;
export interface OrgRegistrationDependencies {
  fetch?: OrgRegistrationFetch;
  signProof: OrgRegistrationSigner;
}

interface RegistrationRequest {
  intentJws: string;
  registrationId: string;
  orgId: string;
  nonce: string;
  handle: string;
  orgName: string;
  challengeNonce?: string;
  assertion?: AuthenticationResponseJSON;
}
interface RegistrationKey {
  keyId: string;
  grantId: string;
  address: string;
  label: string | null;
  controllerDid: string;
}
export type OrgRegistrationResponse =
  | { status: 200; body: { registrationChallenge: { challengeNonce: string; challenge: string; expiresAt: string; allowCredentials: { id: string; type: 'public-key' }[] } } }
  | { status: 200 | 201; body: { key: RegistrationKey; registrationProof: string } };

function refuse(status: 400 | 403 | 409 | 410 | 503, code: string, message: string): never {
  throw new OrgKeyRefusal(status, code, message);
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exactFields(value: Record<string, unknown>, names: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === names.length && keys.every((key) => names.includes(key));
}
function digest(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
function canonicalBytes(value: unknown, length: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === length && bytes.toString('base64url') === value;
}

/** Same duplicate-member detection pattern as app-key-refusal.ts; never accept JSON.parse's last-wins ambiguity. */
function strictJson(text: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text);
  if (!object(parsed)) throw new Error('Expected a JSON object');
  const objects: Array<Set<string> | null> = [];
  let expectKey = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const keys = objects[objects.length - 1];
      if (keys && expectKey) {
        const key = JSON.parse(text.slice(i, end + 1)) as string;
        if (keys.has(key)) throw new Error('Repeated JSON member');
        keys.add(key);
        expectKey = false;
      }
      i = end + 1;
      continue;
    }
    if (ch === '{') {
      objects.push(new Set());
      expectKey = true;
    } else if (ch === '[') {
      objects.push(null);
      expectKey = false;
    } else if (ch === '}' || ch === ']') {
      objects.pop();
      expectKey = false;
    } else if (ch === ',') {
      expectKey = objects[objects.length - 1] instanceof Set;
    }
    i += 1;
  }
  return parsed;
}
function decodeObject(segment: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('Noncanonical JWS encoding');
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw new Error('Noncanonical JWS encoding');
  return strictJson(utf8.decode(bytes));
}
function validHandle(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(value)
    && !value.startsWith('xn--') && value.slice(2, 4) !== '--'
    && !RESERVED_HANDLES.has(value) && !ORG_ID.test(value);
}
function validDisplayName(value: unknown): value is string {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 1 && Buffer.byteLength(value, 'utf8') <= 256
    && !/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u.test(value);
}
function readRequest(raw: string): RegistrationRequest {
  try {
    const body = strictJson(raw);
    if (Object.keys(body).some((key) => !REQUEST_FIELDS.includes(key))) throw new Error('Unexpected registration field');
    for (const key of ['intentJws', 'registrationId', 'orgId', 'nonce', 'handle', 'orgName']) {
      if (typeof body[key] !== 'string' || body[key].length === 0) throw new Error('Missing registration field');
    }
    if ('challengeNonce' in body && !canonicalBytes(body.challengeNonce, 32)) throw new Error('Malformed challenge nonce');
    if ('assertion' in body && !object(body.assertion)) throw new Error('Malformed assertion');
    if (('challengeNonce' in body) !== ('assertion' in body)) throw new Error('Incomplete consent');
    return body as unknown as RegistrationRequest;
  } catch {
    return refuse(400, 'registration_invalid', 'A signed registration intent and exact registration fields are required');
  }
}
function readIntent(value: Record<string, unknown>): OrgRegistrationIntent {
  if (!exactFields(value, INTENT_FIELDS)
    || value.iss !== INTENT_ISSUER || value.aud !== INTENT_AUDIENCE || value.purpose !== PURPOSE
    || typeof value.registrationId !== 'string' || !UUID_V4.test(value.registrationId)
    || typeof value.orgId !== 'string' || !ORG_ID.test(value.orgId)
    || !canonicalBytes(value.nonce, 32) || !validHandle(value.handle) || !validDisplayName(value.displayName)
    || !Number.isSafeInteger(value.iat) || !Number.isSafeInteger(value.exp)
    || Number(value.iat) < 0 || Number(value.exp) !== Number(value.iat) + 600) {
    return refuse(400, 'registration_intent_invalid', 'Registration intent claims are invalid');
  }
  return value as unknown as OrgRegistrationIntent;
}

/** Only the pinned issuer DID can supply keys; kid never selects an outbound URL. */
export function createOrgRegistrationIntentVerifier(fetcher: OrgRegistrationFetch = fetch) {
  let document: Record<string, unknown> | undefined;
  let expiresAt = 0;
  let inFlight: Promise<void> | undefined;
  let lastForcedRefresh = Number.NEGATIVE_INFINITY;
  async function refresh(forced: boolean): Promise<void> {
    if (inFlight) return inFlight;
    const now = Date.now();
    if (forced && now - lastForcedRefresh < FORCED_REFRESH_INTERVAL_MS) return;
    if (forced) lastForcedRefresh = now;
    inFlight = (async () => {
      try {
        const response = await fetcher(INTENT_DID_URL, { redirect: 'error', cache: forced ? 'no-store' : 'default', signal: AbortSignal.timeout(10_000) });
        if (!response.ok || response.status >= 300) throw new Error('Issuer DID unavailable');
        const text = await response.text();
        const parsed = strictJson(text);
        if (parsed.id !== INTENT_ISSUER || !Array.isArray(parsed.verificationMethod) || !Array.isArray(parsed.assertionMethod)) {
          throw new Error('Issuer DID is malformed');
        }
        document = parsed;
        expiresAt = Date.now() + WINDOW_MS;
      } catch {
        refuse(503, 'registration_issuer_unavailable', 'Registration issuer verification is unavailable');
      }
    })();
    try { await inFlight; } finally { inFlight = undefined; }
  }
  function methodFor(keyId: string): Record<string, unknown> | undefined {
    if (!document) return undefined;
    const assertions = document.assertionMethod as unknown[];
    const asserted = assertions.some((method) => method === keyId || (object(method) && method.id === keyId));
    if (!asserted) return undefined;
    const methods = (document.verificationMethod as unknown[]).filter((method) => object(method) && method.id === keyId);
    return methods.length === 1 ? methods[0] as Record<string, unknown> : undefined;
  }
  return async (intentJws: string): Promise<OrgRegistrationIntent> => {
    let header: Record<string, unknown>;
    let claims: OrgRegistrationIntent;
    try {
      const segments = intentJws.split('.');
      if (segments.length !== 3 || !canonicalBytes(segments[2], 64)) throw new Error('Malformed compact JWS');
      header = decodeObject(segments[0]!);
      if (!exactFields(header, ['alg', 'kid', 'typ']) || header.alg !== 'EdDSA' || header.typ !== 'org-registration-intent+jwt'
        || typeof header.kid !== 'string' || !header.kid.startsWith(`${INTENT_ISSUER}#`)) throw new Error('Invalid intent header');
      claims = readIntent(decodeObject(segments[1]!));
    } catch (error) {
      if (error instanceof OrgKeyRefusal) throw error;
      return refuse(400, 'registration_intent_invalid', 'Registration intent is malformed');
    }
    if (!document || expiresAt <= Date.now()) await refresh(false);
    let method = methodFor(header.kid as string);
    if (!method) { await refresh(true); method = methodFor(header.kid as string); }
    if (!method || method.controller !== INTENT_ISSUER || !object(method.publicKeyJwk)) {
      return refuse(403, 'registration_intent_signature_invalid', 'Registration intent signing key is not asserted by its issuer');
    }
    const jwk = method.publicKeyJwk;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !canonicalBytes(jwk.x, 32) || 'd' in jwk
      || (jwk.alg !== undefined && jwk.alg !== 'EdDSA')) {
      return refuse(403, 'registration_intent_signature_invalid', 'Registration intent verification key is invalid');
    }
    try {
      const key = await importJWK(jwk as JWK, 'EdDSA');
      await compactVerify(intentJws, key, { algorithms: ['EdDSA'] });
    } catch {
      return refuse(403, 'registration_intent_signature_invalid', 'Registration intent signature did not verify');
    }
    // Time expiry is deliberately handled after durable-binding lookup, not by JWT verification.
    return claims;
  };
}

export function orgRegistrationChallenge(input: OrgRegistrationIntent, intentDigest: string, userId: string, challengeNonce: string): string {
  const hash = createHash('sha256');
  for (const part of [CHALLENGE_DOMAIN, input.registrationId, input.orgId, input.nonce, input.handle, input.displayName, intentDigest, userId, challengeNonce]) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest('base64url');
}

export function createOrgRegistrationHandler(prisma: PrismaClient, tee: TeeClient, dependencies: OrgRegistrationDependencies) {
  const verifyIntent = createOrgRegistrationIntentVerifier(dependencies.fetch);
  function sameBinding(binding: { ownerSubject: string; intentDigest: string; orgId: string; nonce: string; handle: string; displayName: string }, intent: OrgRegistrationIntent, intentDigest: string, userId: string): void {
    if (binding.ownerSubject !== userId || binding.intentDigest !== intentDigest || binding.orgId !== intent.orgId
      || binding.nonce !== intent.nonce || binding.handle !== intent.handle || binding.displayName !== intent.displayName) {
      refuse(409, 'registration_conflict', 'Registration intent is already bound to another account or tuple');
    }
  }
  async function storedResponse(database: Prisma.TransactionClient, intent: OrgRegistrationIntent, intentDigest: string, userId: string): Promise<OrgRegistrationResponse | undefined> {
    const binding = await database.orgKeyRegistration.findUnique({ where: { registrationId: intent.registrationId }, include: { key: true } });
    if (!binding) return undefined;
    sameBinding(binding, intent, intentDigest, userId);
    return { status: 200, body: { key: { keyId: binding.keyId, grantId: binding.grantId, address: binding.key.address, label: binding.key.label, controllerDid: binding.controllerDid }, registrationProof: binding.proof } };
  }
  function requireOrigin(actor: OrgRegistrationActor): void {
    if (!actor.expectedOrigin || !actor.rpID || actor.origin !== actor.expectedOrigin) {
      refuse(403, 'registration_origin_invalid', 'Registration consent requires the OpenKey passkey origin');
    }
  }
  async function requireSession(database: Prisma.TransactionClient, actor: OrgRegistrationActor): Promise<void> {
    const session = await database.session.findFirst({ where: { id: actor.sessionId, userId: actor.userId, expiresAt: { gt: new Date() } }, select: { id: true } });
    if (!session) refuse(403, 'registration_session_invalid', 'Registration consent requires the same active session');
  }
  return async (raw: string, actor: OrgRegistrationActor): Promise<OrgRegistrationResponse> => {
    const request = readRequest(raw);
    const intent = await verifyIntent(request.intentJws);
    if (request.registrationId !== intent.registrationId || request.orgId !== intent.orgId || request.nonce !== intent.nonce
      || request.handle !== intent.handle || request.orgName !== intent.displayName) {
      return refuse(400, 'registration_tuple_mismatch', 'Registration fields do not match the signed intent');
    }
    requireOrigin(actor);
    const intentDigest = digest(request.intentJws);
    const stored = await storedResponse(prisma, intent, intentDigest, actor.userId);
    if (stored) return stored;
    const now = Math.floor(Date.now() / 1000);
    if (intent.iat > now) return refuse(400, 'registration_intent_future', 'Registration intent was issued in the future');
    if (intent.exp <= now) return refuse(410, 'registration_intent_expired', 'Registration intent has expired');
    await requireSession(prisma, actor);
    if (!request.challengeNonce || !request.assertion) {
      const passkeys = await prisma.passkey.findMany({ where: { userId: actor.userId }, select: { credentialID: true } });
      if (!passkeys.length) return refuse(403, 'registration_passkey_required', 'A registered passkey is required for org registration');
      await prisma.orgKeyRegistrationChallenge.deleteMany({ where: { expiresAt: { lte: new Date() } } });
      const challengeNonce = randomBytes(32).toString('base64url');
      const expiresAt = new Date(Math.min(Date.now() + WINDOW_MS, intent.exp * 1000));
      await prisma.orgKeyRegistrationChallenge.create({ data: {
        challengeNonce, registrationId: intent.registrationId, ownerSubject: actor.userId, sessionId: actor.sessionId,
        intentDigest, orgId: intent.orgId, nonce: intent.nonce, handle: intent.handle, displayName: intent.displayName, expiresAt,
      } });
      return { status: 200, body: { registrationChallenge: {
        challengeNonce, challenge: orgRegistrationChallenge(intent, intentDigest, actor.userId, challengeNonce), expiresAt: expiresAt.toISOString(),
        allowCredentials: passkeys.map((passkey) => ({ id: passkey.credentialID, type: 'public-key' })),
      } } };
    }
    const challenge = await prisma.orgKeyRegistrationChallenge.findUnique({ where: { challengeNonce: request.challengeNonce } });
    if (!challenge || challenge.registrationId !== intent.registrationId || challenge.ownerSubject !== actor.userId
      || challenge.sessionId !== actor.sessionId || challenge.intentDigest !== intentDigest || challenge.orgId !== intent.orgId
      || challenge.nonce !== intent.nonce || challenge.handle !== intent.handle || challenge.displayName !== intent.displayName
      || challenge.consumedAt || challenge.expiresAt.getTime() <= Date.now()) {
      return refuse(403, 'registration_challenge_invalid', 'Registration challenge does not match this account, session and intent');
    }
    const assertion = request.assertion;
    if (typeof assertion.id !== 'string' || typeof assertion.response?.signature !== 'string') {
      return refuse(403, 'registration_passkey_invalid', 'Registration passkey assertion is malformed');
    }
    const passkey = await prisma.passkey.findFirst({ where: { userId: actor.userId, credentialID: assertion.id } });
    if (!passkey) return refuse(403, 'registration_passkey_invalid', 'Registration requires a passkey belonging to this account');
    let newCounter: number;
    let assertionHash: string;
    try {
      const verification = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: orgRegistrationChallenge(intent, intentDigest, actor.userId, request.challengeNonce),
        expectedOrigin: actor.expectedOrigin, expectedRPID: actor.rpID, requireUserVerification: true,
        credential: { id: passkey.credentialID, publicKey: Buffer.from(passkey.publicKey, 'base64'), counter: passkey.counter },
      });
      if (!verification.verified) throw new Error('Passkey did not verify');
      newCounter = verification.authenticationInfo.newCounter;
      assertionHash = canonicalSignatureHash(assertion.response.signature);
    } catch {
      return refuse(403, 'registration_passkey_invalid', 'Registration passkey assertion did not verify');
    }
    // Preparing key material has no durable registration side effects. Only the transaction publishes it.
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const controllerDid = controllerDidForAddress(address);
    const sealingContext = createSealingContext();
    const sealingKey = await deriveKeyForRecord(tee, { userId: null, sealingContext });
    let sealedBlob: string;
    try { sealedBlob = await seal(privateKey, sealingKey); } finally { sealingKey.fill(0); }
    const jti = randomUUID();
    const keyId = randomUUID();
    const iat = Math.floor(Date.now() / 1000);
    const exp = Math.min(intent.exp, iat + WINDOW_MS / 1000);
    if (exp <= iat) return refuse(410, 'registration_intent_expired', 'Registration intent has expired');
    const claims: OrgRegistrationProof = {
      iss: PROOF_ISSUER, aud: PROOF_AUDIENCE, sub: actor.userId, registrationId: intent.registrationId,
      orgId: intent.orgId, nonce: intent.nonce, handle: intent.handle, displayName: intent.displayName,
      keyId, controllerDid, purpose: PURPOSE, jti, iat, exp,
    };
    // The candidate proof remains private unless this request's transaction commits.
    let proof: string;
    try {
      proof = await dependencies.signProof(claims);
      const header = decodeObject(proof.split('.')[0] ?? '');
      if (!exactFields(header, ['alg', 'kid']) || header.alg !== 'EdDSA' || typeof header.kid !== 'string' || !header.kid) {
        throw new Error('Unsupported issuer signing key');
      }
    } catch {
      return refuse(503, 'registration_signer_unavailable', 'Registration proof signing is unavailable');
    }
    try {
      return await prisma.$transaction(async (tx): Promise<OrgRegistrationResponse> => {
        const winner = await storedResponse(tx, intent, intentDigest, actor.userId);
        if (winner) return winner;
        if (intent.exp <= Math.floor(Date.now() / 1000)) return refuse(410, 'registration_intent_expired', 'Registration intent has expired');
        await requireSession(tx, actor);
        const consumed = await tx.orgKeyRegistrationChallenge.updateMany({
          where: { challengeNonce: request.challengeNonce, ownerSubject: actor.userId, sessionId: actor.sessionId, consumedAt: null, expiresAt: { gt: new Date() } },
          data: { consumedAt: new Date(), assertionHash },
        });
        if (consumed.count !== 1) {
          const completed = await storedResponse(tx, intent, intentDigest, actor.userId);
          if (completed) return completed;
          return refuse(403, 'registration_challenge_used', 'Registration challenge is expired or already used');
        }
        const key = await tx.ethereumKey.create({ data: {
          id: keyId, custody: 'ORG', userId: null, keyType: 'MANAGED', address, publicKey: address, sealedBlob, sealingContext,
          isCanonicalTinyCloud: false, label: intent.displayName,
        }, select: { id: true, address: true, label: true } });
        await tx.orgKey.create({ data: { keyId: key.id, orgId: intent.orgId, orgName: intent.displayName, controllerDid } });
        const grant = await tx.keyGrant.create({ data: {
          keyId: key.id, role: 'OWNER', granteeUserId: actor.userId, invitedByUserId: actor.userId, acceptedAt: new Date(),
        } });
        const owner = await tx.keyGrant.findFirst({ where: { id: grant.id, keyId: key.id, role: 'OWNER', granteeUserId: actor.userId, revokedAt: null, acceptedAt: { not: null } }, select: { id: true } });
        if (!owner) return refuse(403, 'registration_owner_required', 'An active OWNER grant is required for registration');
        const counter = await tx.passkey.updateMany({ where: { id: passkey.id, userId: actor.userId, counter: passkey.counter }, data: { counter: newCounter } });
        if (counter.count !== 1) return refuse(403, 'registration_passkey_changed', 'Registration passkey state changed');
        await tx.orgKeyRegistration.create({ data: {
          registrationId: intent.registrationId, ownerSubject: actor.userId, intentDigest,
          orgId: intent.orgId, nonce: intent.nonce, handle: intent.handle, displayName: intent.displayName,
          keyId: key.id, grantId: owner.id, controllerDid, jti, proof,
        } });
        return { status: 201, body: { key: { keyId: key.id, grantId: owner.id, address: key.address, label: key.label, controllerDid }, registrationProof: proof } };
      });
    } catch (error) {
      const uniqueRace = (error as { code?: string }).code === 'P2002';
      const counterRace = error instanceof OrgKeyRefusal && error.code === 'registration_passkey_changed';
      if (uniqueRace || counterRace) {
        // Reload only after rollback: an overlapping approval may commit before this counter update.
        const winner = await storedResponse(prisma, intent, intentDigest, actor.userId);
        if (winner) return winner;
        if (uniqueRace) return refuse(403, 'registration_assertion_used', 'Registration assertion was already used');
      }
      throw error;
    }
  };
}

export interface OrgRegistrationCompletion {
  registrationId: string;
  orgId: string;
  handle: string;
  displayName: string;
  controllerDid: string;
  issuerDid: string;
  tier: 'free';
}

/** The proof remains server-side; only the confirmed OC tuple may reach the browser. */
export async function completeOrgRegistration(prisma: PrismaClient, keyId: string, fetcher: OrgRegistrationFetch = fetch): Promise<OrgRegistrationCompletion> {
  const binding = await prisma.orgKeyRegistration.findUnique({ where: { keyId } });
  if (!binding || !UUID_V4.test(binding.registrationId)) {
    return refuse(503, 'registration_completion_unavailable', 'Registration completion is unavailable; retry in OpenKey');
  }
  const expected: OrgRegistrationCompletion = {
    registrationId: binding.registrationId, orgId: binding.orgId, handle: binding.handle, displayName: binding.displayName,
    controllerDid: binding.controllerDid, issuerDid: `did:web:${binding.orgId}.orgs.credentials.org`, tier: 'free',
  };
  try {
    const response = await fetcher(`https://witness.credentials.org/v1/org-registration-intents/${binding.registrationId}/complete`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ownerProof: binding.proof }),
      redirect: 'error', signal: AbortSignal.timeout(10_000),
    });
    if (response.status === 409 || response.status === 410) {
      return refuse(response.status, 'registration_completion_terminal', 'This registration cannot complete; start a new registration at credentials.org');
    }
    if (response.status !== 200 && response.status !== 201) throw new Error('Completion was not confirmed');
    const result = strictJson(await response.text());
    if (!exactFields(result, Object.keys(expected)) || Object.entries(expected).some(([field, value]) => result[field] !== value)) {
      throw new Error('Completion tuple did not match');
    }
    return expected;
  } catch (error) {
    if (error instanceof OrgKeyRefusal) throw error;
    return refuse(503, 'registration_completion_unavailable', 'Registration completion is temporarily unavailable; retry in OpenKey');
  }
}
