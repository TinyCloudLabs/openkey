export type OAuthApplicationType = 'spa' | 'native';

export type RedirectUriValidation =
  | { valid: true }
  | { valid: false; reason: string };

const BLOCKED_SCHEMES = new Set([
  'about',
  'blob',
  'data',
  'file',
  'intent',
  'javascript',
  'vbscript',
  'chrome',
  'chrome-extension',
  'ftp',
  'ftps',
  'geo',
  'git',
  'irc',
  'ircs',
  'ldap',
  'ldaps',
  'mailto',
  'moz-extension',
  'ms-appx',
  'ms-appx-web',
  'news',
  'nfs',
  'nntp',
  'resource',
  'sftp',
  'smb',
  'sms',
  'ssh',
  'tel',
  'urn',
  'view-source',
  'ws',
  'wss',
]);

const PRIVATE_USE_SCHEME = /^[a-z][a-z0-9+.-]{2,63}$/;

function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

export function oauthApplicationType(value: string | null | undefined): OAuthApplicationType {
  return value === 'native' ? 'native' : 'spa';
}

export function validateOAuthRedirectUri(
  value: unknown,
  applicationType: OAuthApplicationType,
): RedirectUriValidation {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) {
    return { valid: false, reason: 'Redirect URI must be a non-empty string of at most 2048 characters' };
  }
  if (value.trim() !== value || /[\u0000-\u0020\u007f]/.test(value)) {
    return { valid: false, reason: 'Redirect URI must not contain whitespace or control characters' };
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { valid: false, reason: 'Redirect URI must be an absolute URI' };
  }

  const scheme = url.protocol.slice(0, -1).toLowerCase();
  if (BLOCKED_SCHEMES.has(scheme)) {
    return { valid: false, reason: 'Redirect URI scheme is not allowed' };
  }
  if (url.username || url.password) {
    return { valid: false, reason: 'Redirect URI must not contain credentials' };
  }
  if (url.hash) {
    return { valid: false, reason: 'Redirect URI must not contain a fragment' };
  }

  if (scheme === 'https') {
    return url.hostname
      ? { valid: true }
      : { valid: false, reason: 'HTTPS redirect URI must contain a host' };
  }

  if (scheme === 'http') {
    return isLoopbackHostname(url.hostname)
      ? { valid: true }
      : { valid: false, reason: 'HTTP redirect URI must use a loopback host' };
  }

  if (applicationType !== 'native') {
    return { valid: false, reason: 'Browser applications require HTTPS or a loopback HTTP redirect URI' };
  }

  const sourceScheme = value.slice(0, value.indexOf(':'));
  if (!PRIVATE_USE_SCHEME.test(sourceScheme)) {
    return {
      valid: false,
      reason: 'Native custom schemes must use a lowercase private-use application identifier',
    };
  }
  if (!url.pathname.startsWith('/') || url.pathname === '/') {
    return { valid: false, reason: 'Native custom-scheme redirect URI must contain a callback path' };
  }
  return { valid: true };
}

export function validateOAuthRedirectUris(
  values: unknown,
  applicationType: OAuthApplicationType,
): RedirectUriValidation {
  if (!Array.isArray(values) || values.length === 0 || values.length > 20) {
    return { valid: false, reason: 'redirectUris must contain between 1 and 20 entries' };
  }
  for (const value of values) {
    const result = validateOAuthRedirectUri(value, applicationType);
    if (!result.valid) return result;
  }
  return { valid: true };
}

export function validateOAuthClientMetadataUrl(value: unknown): RedirectUriValidation {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048
    || value.trim() !== value || /[\u0000-\u0020\u007f]/.test(value)) {
    return { valid: false, reason: 'Application URL must be a non-empty HTTP(S) URL' };
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return { valid: false, reason: 'Application URL must be an absolute HTTP(S) URL' };
  }
  if (url.username || url.password || url.hash) {
    return { valid: false, reason: 'Application URL must not contain credentials or a fragment' };
  }
  if (url.protocol === 'https:' && url.hostname) return { valid: true };
  if (url.protocol === 'http:' && isLoopbackHostname(url.hostname)) return { valid: true };
  return { valid: false, reason: 'Application URL must use HTTPS or loopback HTTP' };
}
