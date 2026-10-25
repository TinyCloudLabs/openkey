// Reading the server's answer to authorize-sign-prepare, -preview and
// -sign. A 200 only counts when its body is a JSON object that carries the
// fields the next step needs. An empty body, text that is not JSON, or an
// object without those fields is an unreadable reply: nothing is approved.

/** String 20: shown when a reply cannot be read. The HTTP status is not part of it. */
export const SERVER_REPLY_TITLE = "OpenKey couldn't finish this request";
export const SERVER_REPLY_BODY =
  "OpenKey couldn't read the server's reply, so nothing was approved. Please try again. If it keeps happening, contact the app.";

/** The failure code and message the widget reports to the host. No reply content. */
export const SERVER_REPLY_ERROR = { code: 'UNKNOWN', message: 'SERVER_REPLY_UNREADABLE' } as const;

/** A 200 whose body could not be used. Carries the HTTP status only. */
export class ServerReplyError extends Error {
  readonly status: number;
  constructor(status: number) {
    super(`unreadable server reply (HTTP ${status})`);
    this.name = 'ServerReplyError';
    this.status = status;
  }
}

// The pages read nested fields of a checked reply the way they read any parsed JSON.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ReplyBody = Record<string, any>;

export const hasText = (body: ReplyBody, ...fields: string[]): boolean =>
  fields.every((field) => typeof body[field] === 'string' && body[field] !== '');

/**
 * Read one reply. A non-2xx answer keeps the server's own error text, or
 * `<fallback>` when it has none. A 2xx answer must be a JSON object that
 * satisfies `valid`; otherwise this throws `ServerReplyError` with the status.
 */
export async function readReply(
  response: Response,
  valid: (body: ReplyBody) => boolean,
  fallback: string,
): Promise<ReplyBody> {
  if (!response.ok) {
    const failure: unknown = await response.json().catch(() => ({ error: fallback }));
    const text =
      failure !== null && typeof failure === 'object' && 'error' in failure && typeof failure.error === 'string' && failure.error
        ? failure.error
        : `HTTP ${response.status}`;
    throw new Error(text);
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    throw new ServerReplyError(response.status);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new ServerReplyError(response.status);
  const body: ReplyBody = parsed as ReplyBody;
  if (!valid(body)) throw new ServerReplyError(response.status);
  return body;
}
