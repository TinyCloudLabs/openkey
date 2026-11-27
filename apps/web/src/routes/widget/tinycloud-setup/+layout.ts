// TC-3657 client half: the setup widget runs as a top-level popup only. The authoritative
// `frame-ancestors 'none'` + `X-Frame-Options: DENY` headers are set in
// `apps/web/src/hooks.server.ts` so they reach the HTML document even under `ssr=false`.
// This guard refuses to render if a proxy ever strips the headers and the page somehow
// loads inside a frame.
export const ssr = false;

export const load = (): { embeddedRefusalMessage: string | null } => {
  if (typeof window === 'undefined') return { embeddedRefusalMessage: null };
  if (window.top !== window.self) {
    return {
      embeddedRefusalMessage:
        'Setup has to open in its own window. Go back to the app, allow pop-ups and try again.',
    };
  }
  return { embeddedRefusalMessage: null };
};
