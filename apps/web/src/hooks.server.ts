import type { Handle } from '@sveltejs/kit';
import { accountHostname, accountOrigin, consoleHostname, consoleOrigin } from '$lib/console-host';
import { routeConsoleHost } from '$lib/console-routing';

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
    return new Response('This hostname is reserved for the OpenKey administrative console.', {
      status: 404,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  return resolve(event);
};
