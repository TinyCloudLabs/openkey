export const ORG_SIGN_REQUEST_TYPE = 'openkey:org-sign:request';
export const ORG_SIGN_RESPONSE_TYPE = 'openkey:org-sign:response';

export interface OrgSignWidgetRequest {
  requestId: string;
  keyId: string;
  message: string;
  protocolVersion: 1;
}

/**
 * Only accept an org-key signing request from the exact requesting parent or
 * opener origin and window. The requesting origin is taken from the verified
 * transport, never from the request body, because the server binds it into the
 * fresh-passkey challenge (K1 D4.5).
 */
export function readOrgSignWidgetRequest(
  event: Pick<MessageEvent, 'origin' | 'source' | 'data'>,
  origin: string | null,
  source: MessageEventSource | null,
): OrgSignWidgetRequest | null {
  const request = event.data;
  if (
    origin === null ||
    event.origin !== origin ||
    event.source !== source ||
    request?.type !== ORG_SIGN_REQUEST_TYPE ||
    typeof request.requestId !== 'string' ||
    request.requestId.length === 0 ||
    typeof request.keyId !== 'string' ||
    request.keyId.length === 0 ||
    typeof request.message !== 'string' ||
    request.message.length === 0 ||
    request.protocolVersion !== 1
  ) return null;

  return {
    requestId: request.requestId,
    keyId: request.keyId,
    message: request.message,
    protocolVersion: 1,
  };
}
