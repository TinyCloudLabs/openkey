import { isConsolePath } from './console-host';

export type ConsoleHostRoute =
  | { type: 'continue' }
  | { type: 'redirect'; location: string }
  | { type: 'not-found' };

type ConsoleHostRouteInput = {
  hostname: string;
  pathname: string;
  search: string;
  accountHostname: string;
  accountOrigin: string;
  consoleHostname: string;
  consoleOrigin: string;
};

/**
 * Keep the account and administrative surfaces separate at the host boundary.
 * Fragment identifiers are not sent to an HTTP server; browsers retain an
 * existing fragment when following this same-path redirect.
 */
export function routeConsoleHost(input: ConsoleHostRouteInput): ConsoleHostRoute {
  const hostname = input.hostname.toLowerCase();
  if (hostname === input.consoleHostname.toLowerCase()) {
    if (input.pathname === '/') {
      return {
        type: 'redirect',
        location: new URL(`/console${input.search}`, input.consoleOrigin).href,
      };
    }
    // Preserve the useful destination of account-host bookmarks without
    // rendering an account page inside the console host boundary.
    if (input.pathname === '/dashboard' || input.pathname.startsWith('/dashboard/')) {
      return {
        type: 'redirect',
        location: new URL(`${input.pathname}${input.search}`, input.accountOrigin).href,
      };
    }
    return isConsolePath(input.pathname) ? { type: 'continue' } : { type: 'not-found' };
  }

  if (hostname === input.accountHostname.toLowerCase() && isConsolePath(input.pathname)) {
    return {
      type: 'redirect',
      location: new URL(`${input.pathname}${input.search}`, input.consoleOrigin).href,
    };
  }

  return { type: 'continue' };
}
