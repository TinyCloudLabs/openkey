export interface SignOutWidgetRequest {
  requestId: string;
  protocolVersion: 1;
  sessionToken?: string;
}

/** Only accept a sign-out request from the exact SDK parent/opener origin. */
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
    request.protocolVersion !== 1 ||
    (request.sessionToken !== undefined && typeof request.sessionToken !== 'string')
  ) return null;

  return {
    requestId: request.requestId,
    protocolVersion: 1,
    sessionToken: request.sessionToken,
  };
}
