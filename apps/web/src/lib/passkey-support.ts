// Clients that cannot use WebAuthn (for example an ad-hoc-signed desktop
// webview) open OpenKey with `passkeys=false`. Any other value, or no
// parameter, means passkeys are supported, so existing clients are
// unaffected.

export const PASSKEYS_UNSUPPORTED_PARAM = 'passkeys';

export function passkeysSupportedFromParams(params: URLSearchParams): boolean {
  return params.get(PASSKEYS_UNSUPPORTED_PARAM) !== 'false';
}

/** Appends `passkeys=false` to an OpenKey-relative URL when passkeys are unsupported. */
export function withPasskeysFlag(path: string, passkeysSupported: boolean): string {
  if (passkeysSupported) return path;
  return `${path}${path.includes('?') ? '&' : '?'}${PASSKEYS_UNSUPPORTED_PARAM}=false`;
}
