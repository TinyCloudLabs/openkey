export interface SignOutWidgetRequest {
  requestId: string;
  protocolVersion: 1;
}

/**
 * Only accept a sign-out request from the exact SDK parent/opener origin.
 * A `sessionToken` sent by older SDKs is ignored: the widget revokes the
 * session it holds in OpenKey-origin storage or cookies (TC-688).
 */
export function readSignOutWidgetRequest(
  event: Pick<MessageEvent, 'origin' | 'source' | 'data'>,
  origin: string | null,
  source: MessageEventSource | null,
): SignOutWidgetRequest | null {
  const request = event.data;
  if (
    origin === null ||
    event.origin !== origin ||
    event.source !== source ||
    request?.type !== 'openkey:sign-out:request' ||
    typeof request.requestId !== 'string' ||
    request.requestId.length === 0 ||
    request.protocolVersion !== 1
  ) return null;

  return {
    requestId: request.requestId,
    protocolVersion: 1,
  };
}
