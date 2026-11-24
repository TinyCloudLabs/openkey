// TC-3893: the popup route `/widget/registry-change` runs top-level only.
// Authoritative framing headers (`frame-ancestors 'none'` + `X-Frame-Options: DENY`)
// are set in `apps/web/src/hooks.server.ts`. This guard is belt-and-braces if a proxy
// ever strips headers.
export const ssr = false;

export const load = (): { embeddedRefusalMessage: string | null } => {
  if (typeof window === 'undefined') return { embeddedRefusalMessage: null };
  if (window.top !== window.self) {
    return {
      embeddedRefusalMessage:
        'This window must open on its own. Go back to the app and try again.',
    };
  }
  return { embeddedRefusalMessage: null };
};
