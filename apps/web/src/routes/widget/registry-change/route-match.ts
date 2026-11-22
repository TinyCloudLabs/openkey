// TC-3893: route-id matchers for the registry-change widget surfaces.
// Matches on SvelteKit's normalised `event.route.id` (same pattern as TC-3657
// `tinycloud-setup/route-match.ts`) so percent-encoded URL spellings cannot bypass
// the framing headers in `hooks.server.ts`.
//
// Popup (`/widget/registry-change`) gets `frame-ancestors 'none'` + `X-Frame-Options: DENY`
// + `Referrer-Policy: no-referrer`.
// Embed (`/widget/embed/registry-change`) allows framing by embedding apps and still sets
// `Referrer-Policy: no-referrer`.

export function isRegistryChangePopupWidgetRoute(routeId: string): boolean {
  return routeId === '/widget/registry-change' || routeId.startsWith('/widget/registry-change/');
}

export function isRegistryChangeEmbedWidgetRoute(routeId: string): boolean {
  return routeId === '/widget/embed/registry-change' || routeId.startsWith('/widget/embed/registry-change/');
}
