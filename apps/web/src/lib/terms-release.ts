// Whether this build reads the Terms status before a signed-in page or frame goes on. The web is built from the same
// tree as the API's terms-release.json, and vite.config.ts defines `__OPENKEY_TERMS_RELEASE__` from it: with no
// release, nothing reads the status first, so nothing waits on it or fails on it. A call the API refuses with
// `terms_required` still reads the status and shows the Terms in place, which covers an API whose release went live
// before this build.
declare const __OPENKEY_TERMS_RELEASE__: boolean | undefined;
const SHIPPED = typeof __OPENKEY_TERMS_RELEASE__ === 'boolean' && __OPENKEY_TERMS_RELEASE__;

/**
 * The dev server only (the browser tests). `VITE_OPENKEY_TERMS_RELEASE` for the whole server, or this key in a page's
 * sessionStorage, says `on` or `off` in place of the file. A production build ignores both.
 */
export const DEV_TERMS_RELEASE_KEY = 'openkey_dev_terms_release';

export function termsCheckedFirst(): boolean {
  if (import.meta.env.DEV) {
    const forced = globalThis.sessionStorage?.getItem(DEV_TERMS_RELEASE_KEY) ?? import.meta.env.VITE_OPENKEY_TERMS_RELEASE;
    if (forced === 'on' || forced === 'off') return forced === 'on';
  }
  return SHIPPED;
}
