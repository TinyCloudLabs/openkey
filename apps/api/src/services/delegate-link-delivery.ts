/**
 * How a legacy `/delegate` link returns its delegation, as the server reads it from what the page sent at prepare
 * time. A COMPATIBILITY allowance for the CLI and Courier, not a security boundary: any app can send a link that
 * names a loopback callback or no callback at all. The owner approves it on OpenKey's own page, which says what
 * approving does and that the requester's words are unchecked (see `OWN_PAGE_APPROVAL_ENABLED`).
 *
 * - `paste`: the link names no callback; the owner copies a code.
 * - `loopback`: the callback is an `http` URL on 127.0.0.1, [::1] or localhost with an explicit port.
 *
 * Anything else (an https callback, a lookalike host, a number spelling of the loopback address) is not recognised.
 */
export type DelegateLinkDelivery = 'paste' | 'loopback';

// The host and port are read from the raw text, so a spelling the URL parser would normalise to 127.0.0.1
// (2130706433, 0177.0.0.1, 0x7f.0.0.1) is never taken for it. Lower case only, as the CLI writes it.
const LOOPBACK_CALLBACK = /^http:\/\/(127\.0\.0\.1|\[::1\]|localhost):([1-9][0-9]{0,4})(?:[/?#][^\s\\]*)?$/;

/** True for exactly `http://127.0.0.1:PORT`, `http://[::1]:PORT` or `http://localhost:PORT`, with an optional path, query or fragment. */
export function isLoopbackCallback(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = LOOPBACK_CALLBACK.exec(value);
  if (!match) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  // The parsed form must agree with the text: an explicit, non-default, in-range port; the same host; no user info.
  return url.protocol === 'http:' && url.hostname === match[1] && url.port === match[2]
    && Number(url.port) <= 65535 && url.username === '' && url.password === '';
}

/**
 * `deliveryKind` and `callback` are what the page reported for the link. `paste` is a server-known enum value the
 * page sends, never inferred from a missing callback; a `callback` kind counts only for a loopback callback.
 */
export function classifyDelegateLinkDelivery(deliveryKind: unknown, callback: unknown): DelegateLinkDelivery | undefined {
  if (deliveryKind === 'paste') return callback === undefined ? 'paste' : undefined;
  if (deliveryKind === 'callback') return isLoopbackCallback(callback) ? 'loopback' : undefined;
  return undefined;
}
