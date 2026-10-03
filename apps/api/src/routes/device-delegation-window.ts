import { DeviceAuthorizationError } from '../services/device-authorization';
import { deviceAuthorizationService } from './device-authorization';

/**
 * TC-539: a `/api/delegate` prepare, sign, or complete request that names a
 * device transaction (`deviceTransactionId`) must stay within that pending
 * transaction's session key, Node origin, and lifetime. Sign and complete
 * pass `signedSiwe`, the SIWE that is (or was) signed; the session key and
 * expiry are read from its canonical form. Prepare, which has no SIWE yet,
 * passes the expiry it is about to request. Called before signing and before
 * any host activation. Returns the error response, or null when the request
 * names no device transaction or fits it. Requests without a transaction id
 * follow ordinary `/delegate` behaviour.
 */
export async function deviceDelegationWindowError(
  body: object,
  input: { host: unknown } & ({ signedSiwe: string } | { expirationTime: string }),
): Promise<{ body: { error: string; code: string }; status: 400 | 410 } | null> {
  const { deviceTransactionId, jwk } = body as { deviceTransactionId?: unknown; jwk?: unknown };
  if (deviceTransactionId === undefined) return null;
  try {
    await deviceAuthorizationService.assertDelegationWindow(deviceTransactionId, {
      nodeOrigin: input.host,
      jwk,
      ...('signedSiwe' in input ? { signedSiwe: input.signedSiwe } : { expiresAt: new Date(input.expirationTime) }),
    });
    return null;
  } catch (error) {
    if (!(error instanceof DeviceAuthorizationError)) throw error;
    return { body: { error: error.message, code: error.code }, status: error.status === 410 ? 410 : 400 };
  }
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
