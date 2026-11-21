// TC-3657 Bobbie N2 (15:42:43Z): the framing-headers predicate for
// `/widget/tinycloud-setup` must match on the SvelteKit route id (the normalised, decoded
// route template) and NOT on the raw URL pathname. A `/widget/tinycloud%2Dsetup` URL
// decodes to the same route template `/widget/tinycloud-setup`, so the headers apply.
//
// This module is standalone (no SvelteKit `$lib/...` imports) so unit tests can import
// the predicate without pulling in the whole hooks-server chain.
export function isTinyCloudSetupWidgetRoute(routeId: string): boolean {
  return routeId === '/widget/tinycloud-setup' || routeId.startsWith('/widget/tinycloud-setup/');
}
