import { DeviceAuthorizationError } from '../services/device-authorization';
import { deviceAuthorizationService } from './device-authorization';

/**
 * TC-539: a `/api/delegate` prepare or sign request made for a device
 * transaction (`deviceTransactionId`) must stay within that pending
 * transaction's session key, Node origin, and lifetime. Called before
 * signing and before any host activation. Returns the error response, or
 * null when the request is not for a device transaction or fits it.
 */
export async function deviceDelegationWindowError(
  body: object,
  input: { expirationTime: string; host: unknown },
): Promise<{ body: { error: string; code: string }; status: 400 | 410 } | null> {
  const { deviceTransactionId, jwk } = body as { deviceTransactionId?: unknown; jwk?: unknown };
  if (deviceTransactionId === undefined) return null;
  try {
    await deviceAuthorizationService.assertDelegationWindow(deviceTransactionId, {
      expiresAt: new Date(input.expirationTime),
      nodeOrigin: input.host,
      jwk,
    });
    return null;
  } catch (error) {
    if (!(error instanceof DeviceAuthorizationError)) throw error;
    return { body: { error: error.message, code: error.code }, status: error.status === 410 ? 410 : 400 };
  }
}
