const DEFAULT_ACCOUNT_ORIGIN = 'https://openkey.so';
const DEFAULT_CONSOLE_ORIGIN = 'https://console.openkey.so';

function configuredOrigin(value: string | undefined, fallback: string): string {
  const candidate = value?.trim() || fallback;
  try {
    const url = new URL(candidate);
    if ((url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password) {
      return url.origin;
    }
  } catch {
    // Fall through to the known-good OpenKey origin.
  }
  return fallback;
}

/**
 * Production has two deliberately separate browser surfaces. Local development
 * keeps them on one Vite host by default, so contributors do not need DNS or a
 * second certificate just to use the console.
 */
export function accountOrigin(): string {
  return import.meta.env.DEV
    ? configuredOrigin(import.meta.env.VITE_ACCOUNT_ORIGIN, '')
    : configuredOrigin(import.meta.env.VITE_ACCOUNT_ORIGIN, DEFAULT_ACCOUNT_ORIGIN);
}

export function consoleOrigin(): string {
  return import.meta.env.DEV
    ? configuredOrigin(import.meta.env.VITE_CONSOLE_ORIGIN, '')
    : configuredOrigin(import.meta.env.VITE_CONSOLE_ORIGIN, DEFAULT_CONSOLE_ORIGIN);
}

function hrefFor(origin: string, path: string): string {
  // Resolve against a sentinel first. This rejects protocol-relative and
  // backslash-normalized inputs such as `//other.example` before they can turn
  // an otherwise trusted host link into an external navigation.
  const localOrigin = 'https://openkey.invalid';
  if (!path.startsWith('/') || new URL(path, localOrigin).origin !== localOrigin) {
    throw new Error('OpenKey host paths must be origin-relative.');
  }
  return origin ? new URL(path, origin).href : path;
}

export function accountHref(path: string): string {
  return hrefFor(accountOrigin(), path);
}

export function consoleHref(path = '/console'): string {
  return hrefFor(consoleOrigin(), path);
}

export function isConsolePath(pathname: string): boolean {
  return pathname === '/console' || pathname.startsWith('/console/');
}

export function consoleHostname(): string {
  return new URL(consoleOrigin() || DEFAULT_CONSOLE_ORIGIN).hostname;
}

export function accountHostname(): string {
  return new URL(accountOrigin() || DEFAULT_ACCOUNT_ORIGIN).hostname;
}
