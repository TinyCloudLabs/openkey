import type { Handle } from '@sveltejs/kit';
import { accountHostname, accountOrigin, consoleHostname, consoleOrigin } from '$lib/console-host';
import { routeConsoleHost } from '$lib/console-routing';

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character] ?? character);
}

function reservedConsoleHostPage(accountOrigin: string) {
  const accountDashboard = new URL('/dashboard', accountOrigin).href;
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Page not found · OpenKey Console</title>
    <style>
      :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8f9fb; color: #1a1c21; }
      body { display: grid; min-block-size: 100vh; place-items: center; margin: 0; padding: 1.5rem; }
      main { max-inline-size: 34rem; text-align: center; }
      p { color: #475569; line-height: 1.6; }
      a { display: inline-flex; margin-block-start: 1rem; border: 1px solid #c4d3ff; border-radius: 9999px; background: #eef3ff; color: #1e42c8; padding: .625rem .875rem; font-weight: 600; text-decoration: none; }
      a:hover { background: #dfe7ff; }
      a:focus-visible { outline: 2px solid #2a56f6; outline-offset: 3px; }
    </style>
  </head>
  <body>
    <main>
      <p>OpenKey Console</p>
      <h1>Page not found</h1>
      <p>This hostname is reserved for the OpenKey administrative console. Return to your OpenKey Account to continue.</p>
      <a href="${escapeHtml(accountDashboard)}">OpenKey Account</a>
    </main>
  </body>
</html>`;
}

import { isTinyCloudSetupWidgetRoute } from './routes/widget/tinycloud-setup/route-match';

export const handle: Handle = async ({ event, resolve }) => {
  const route = routeConsoleHost({
    hostname: event.url.hostname,
    pathname: event.url.pathname,
    search: event.url.search,
    accountHostname: accountHostname(),
    accountOrigin: accountOrigin() || event.url.origin,
    consoleHostname: consoleHostname(),
    // Local development normally keeps both surfaces on one Vite origin. A
    // configured console origin is required only when exercising host routing.
    consoleOrigin: consoleOrigin() || 'https://console.openkey.so',
  });

  if (route.type === 'redirect') {
    return new Response(null, {
      status: 308,
      headers: { location: route.location },
    });
  }

  if (route.type === 'not-found') {
    return new Response(reservedConsoleHostPage(accountOrigin() || event.url.origin), {
      status: 404,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  const response = await resolve(event);
  // TC-3657: `/widget/tinycloud-setup` sets `ssr=false` on its layout, so neither a
  // `+page.server.ts` nor a `+layout.server.ts` `setHeaders` call reaches the HTML
  // document; only the `__data.json` payload. Set the framing headers here in the request
  // handler so the document itself carries them regardless of SSR mode. Matching on
  // `event.route.id` (the normalised route template SvelteKit resolves after decoding)
  // rather than the raw pathname closes the percent-encoded-ASCII bypass: a URL like
  // `/widget/tinycloud%2Dsetup` decodes to the same route template and still gets the
  // headers. The client-side guard in `+layout.ts` is a belt-and-braces check.
  if (isTinyCloudSetupWidgetRoute(event.route?.id ?? '')) {
    response.headers.set('Content-Security-Policy', "frame-ancestors 'none'");
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('Referrer-Policy', 'no-referrer');
  }
  return response;
};
