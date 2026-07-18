const PRIVATE_USE_SCHEME = /^[a-z][a-z0-9+.-]{2,63}$/;
const BLOCKED_SCHEMES = new Set([
  'about', 'blob', 'chrome', 'chrome-extension', 'data', 'file', 'ftp', 'ftps', 'geo', 'git', 'http', 'https',
  'intent', 'irc', 'ircs', 'javascript', 'ldap', 'ldaps', 'mailto', 'moz-extension', 'ms-appx',
  'ms-appx-web', 'news', 'nfs', 'nntp', 'resource', 'sftp', 'smb', 'sms', 'ssh', 'tel', 'urn',
  'vbscript', 'view-source', 'ws', 'wss',
]);

function parseSafeUrl(value: unknown): URL | null {
  if (typeof value !== 'string' || !value || value.trim() !== value
    || /[\u0000-\u0020\u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    return url.username || url.password || url.hash ? null : url;
  } catch {
    return null;
  }
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname.endsWith('.localhost')
    || hostname === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

export function safeExternalHttpUrl(value: unknown): string | null {
  const url = parseSafeUrl(value);
  if (!url) return null;
  if (url.protocol === 'https:' && url.hostname) return value as string;
  if (url.protocol === 'http:' && isLoopback(url.hostname)) return value as string;
  return null;
}

export function safeOAuthNavigationUrl(value: unknown): string | null {
  const httpUrl = safeExternalHttpUrl(value);
  if (httpUrl) return httpUrl;
  const url = parseSafeUrl(value);
  if (!url || typeof value !== 'string') return null;
  const scheme = value.slice(0, value.indexOf(':'));
  return PRIVATE_USE_SCHEME.test(scheme) && !BLOCKED_SCHEMES.has(scheme)
    && url.pathname.startsWith('/') && url.pathname !== '/'
    ? value
    : null;
}
