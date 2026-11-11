export const mcpAppCopy = {
  title: 'Connected MCP apps',
  intro: 'Apps you connected to your TinyCloud through the MCP server. Disconnect an app to stop it using your account.',
  empty: 'No MCP apps are connected.',
  connected: 'Connected',
  disconnect: 'Disconnect',
  cancel: 'Cancel',
  confirmAction: 'Disconnect app',
  confirmTitle: (name: string) => `Disconnect ${name}?`,
  confirmBody: 'The app will lose the access you gave it, including any other access this connection allowed. It can ask you to connect again later.',
  disconnected: 'Disconnected. The app will stop being able to use your TinyCloud through MCP, usually within a minute and always within 5 minutes.',
  failed: 'Could not disconnect the app. Try again.',
} as const;
export const identityAppCopy = {
  title: 'Apps that can see your wallet address',
  intro: "These apps can see your OpenKey wallet address. They can't sign anything or use your TinyCloud data. Disconnect an app to stop its future access.",
  connected: 'Connected',
  disconnect: 'Disconnect',
  cancel: 'Cancel',
  confirmAction: 'Disconnect app',
  confirmTitle: (name: string) => `Disconnect ${name}?`,
  confirmBody: "The app won't be able to ask for your wallet address again, but it keeps anything it already received. It can ask you to connect again later.",
  disconnected: "Disconnected. The app can't ask for your wallet address again. It keeps anything it already received.",
  failed: "Couldn't disconnect the app. Try again.",
} as const;

const SCOPE_WORDS: Record<string, string> = {
  'tinycloud:mcp': 'Lets this app use your TinyCloud through the MCP server.',
  openid: 'Lets this app recognize your account.',
  email: 'Lets this app see your email address.',
  profile: 'Lets this app see your profile name.',
  keys: 'Lets this app see your account keys.',
  offline_access: 'Lets this app stay connected until you disconnect it.',
};

/** Only https icons are rendered; anything else (data:, javascript:, http:) is skipped. */
export function safeMcpIcon(icon: string | null): string | null {
  if (!icon) return null;
  try { return new URL(icon).protocol === 'https:' ? icon : null; } catch { return null; }
}

/** Plain-words lines for a consent's scopes; the MCP scope is always first. */
export function describeMcpScopes(scopes: readonly string[]): string[] {
  const known = Object.keys(SCOPE_WORDS);
  const ordered = [...scopes].sort((a, b) => {
    const rank = (scope: string) => (scope === 'tinycloud:mcp' ? -1 : known.includes(scope) ? known.indexOf(scope) : known.length);
    return rank(a) - rank(b);
  });
  return ordered.map((scope) => SCOPE_WORDS[scope] ?? `Access named “${scope}”.`);
}
