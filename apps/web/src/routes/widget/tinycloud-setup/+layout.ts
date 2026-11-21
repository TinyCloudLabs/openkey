// TC-3657 Bobbie N1 (14:53:16Z) + F2 fix (15:16:27Z) client half: this widget runs as
// a top-level popup only. The authoritative `frame-ancestors 'none'` + `X-Frame-Options:
// DENY` headers are set in `apps/web/src/hooks.server.ts` (so they actually reach the
// HTML document even with `ssr=false`). This guard refuses to render if the browser
// somehow served the page inside a frame anyway (e.g. headers lost at a proxy).
export const ssr = false;

export const load = (): { embeddedRefusalMessage: string | null } => {
  if (typeof window === 'undefined') return { embeddedRefusalMessage: null };
  if (window.top !== window.self) {
    return {
      embeddedRefusalMessage:
        'TinyCloud setup cannot run inside an embedded frame. This window will close; retry the setup from your app and allow the popup.',
    };
  }
  return { embeddedRefusalMessage: null };
};
