import { DeviceAuthorizationError, type DeviceAuthorizationRecord } from '../services/device-authorization';
import { checkSignedSubset, parseStrictSiwe, SIGNED_SUBSET_REFUSAL_CODE } from '../services/signed-subset';
import { actionKey, parsePreparedRecap, prepareDelegationSession, type DelegationJwk } from './delegate-session';
import { deviceAuthorizationService } from './device-authorization';

type DelegationWindowRefusal = { body: { error: string; code: string; reason?: string }; status: 400 | 410 };

/**
 * TC-539: a `/api/delegate` prepare, sign, or complete request that names a
 * device transaction (`deviceTransactionId`) must stay within that pending
 * transaction's session key, Node origin, and lifetime. Sign and complete
 * pass `signedSiwe`, the SIWE that is (or was) signed; the session key and
 * expiry are read from its canonical form, and the message must be a subset
 * of what the device requested (`deviceSignedSubsetRefusal`). Prepare, which
 * has no SIWE yet, passes the expiry it is about to request. Called before
 * signing and before any host activation. Returns the error response, or null
 * when the request names no device transaction or fits it. Requests without a
 * transaction id follow ordinary `/delegate` behaviour.
 */
export async function deviceDelegationWindowError(
  body: object,
  input: { host: unknown } & ({ signedSiwe: string } | { expirationTime: string }),
): Promise<DelegationWindowRefusal | null> {
  const { deviceTransactionId, jwk } = body as { deviceTransactionId?: unknown; jwk?: unknown };
  if (deviceTransactionId === undefined) return null;
  let record: DeviceAuthorizationRecord;
  try {
    record = await deviceAuthorizationService.assertDelegationWindow(deviceTransactionId, {
      nodeOrigin: input.host,
      jwk,
      ...('signedSiwe' in input ? { signedSiwe: input.signedSiwe } : { expiresAt: new Date(input.expirationTime) }),
    });
  } catch (error) {
    if (!(error instanceof DeviceAuthorizationError)) throw error;
    return { body: { error: error.message, code: error.code }, status: error.status === 410 ? 410 : 400 };
  }
  return 'signedSiwe' in input ? deviceSignedSubsetRefusal(record, input.signedSiwe) : null;
}

/**
 * The signed message is a subset of what the device requested. The record
 * holds the request as a permission list (validated at start), so the
 * reference is the message the server prepares for the whole request with
 * the signed message's own header and the device's session key; the signed
 * bytes must then pass the same check as the authorize-sign routes, with
 * every requested capability selectable. Widened or re-spaced capabilities,
 * another session key, and any header field the server would not write are
 * refused. The lifetime is the window check's (above).
 */
function deviceSignedSubsetRefusal(record: DeviceAuthorizationRecord, signedSiwe: string): DelegationWindowRefusal | null {
  const refuse = (reason: string, error: string): DelegationWindowRefusal =>
    ({ body: { error, code: SIGNED_SUBSET_REFUSAL_CODE, reason }, status: 400 });
  const parsed = parseStrictSiwe(signedSiwe);
  if (!parsed.ok) return refuse('signed_unparsable', `The SIWE to sign is not well formed: ${parsed.message}`);
  const signed = parsed.siwe;
  let reference: string;
  try {
    reference = prepareDelegationSession({
      address: signed.address,
      chainId: Number(signed.chainId),
      prefix: '',
      // publicSessionJwk() validated this at start: exactly { kty: 'OKP', crv: 'Ed25519', x }.
      jwk: record.publicJwk as unknown as DelegationJwk,
      permissions: record.permissions,
      deviceTransaction: true,
      expiryMs: Date.parse(signed.expirationTime ?? '') - Date.parse(signed.issuedAt),
      domain: signed.domain,
      nonce: signed.nonce,
      issuedAt: new Date(signed.issuedAt),
    }).prepared.siwe;
  } catch (e) {
    return refuse('request_unparsable', e instanceof Error ? e.message : 'The device request could not be prepared');
  }
  const requestedIds = new Set(parsePreparedRecap(reference).flatMap((entry) => entry.actions.map((action) => actionKey(entry, action))));
  const outcome = checkSignedSubset({ requested: reference, signed: signedSiwe, selectedActionIds: requestedIds, longerExpiryAllowed: false });
  return outcome.ok ? null : refuse(outcome.reason, outcome.message);
}

/**
 * Signing routes that do not enforce device transactions (the authorize-sign
 * routes, `/api/delegate/sign`, `/api/delegate/host`, and
 * `/api/keys/:keyId/sign`) refuse a request carrying `deviceTransactionId`
 * rather than silently signing it without the device constraints.
 */
export function deviceTransactionUnsupportedError(body: unknown): { error: string; code: string } | null {
  return body && typeof body === 'object' && Object.hasOwn(body, 'deviceTransactionId')
    ? {
        error: 'device authorization is not supported on this route; approve device requests through /api/delegate/prepare and /api/delegate',
        code: 'device_transaction_unsupported',
      }
    : null;
}
