import { authClient, API_BASE } from './auth-client';
import { setSessionToken } from './embed-passkey';

export type SocialProviderId = 'google' | 'apple';

type PopupLike = {
  closed: boolean;
  close(): void;
  location: { href: string };
};

type PopupEvent = {
  origin: string;
  source: unknown;
  data?: {
    type?: string;
    sessionToken?: string;
    message?: string;
  };
};

export type SocialPopupDependencies = {
  origin: string;
  open: () => PopupLike | null;
  addMessageListener: (listener: (event: PopupEvent) => void) => void;
  removeMessageListener: (listener: (event: PopupEvent) => void) => void;
  setPoll: (listener: () => void) => number;
  clearPoll: (id: number) => void;
  persistToken: (token: string) => void;
  begin: (provider: SocialProviderId, callbackURL: string) => Promise<{
    error?: { message?: string } | null;
    data?: { url?: string } | null;
  }>;
};

function browserPopupDependencies(): SocialPopupDependencies {
  return {
    origin: window.location.origin,
    open: () => window.open('', 'openkey-social-sign-in', 'popup=true,width=520,height=720') as PopupLike | null,
    addMessageListener: (listener) => window.addEventListener('message', listener as unknown as EventListener),
    removeMessageListener: (listener) => window.removeEventListener('message', listener as unknown as EventListener),
    setPoll: (listener) => window.setInterval(listener, 500),
    clearPoll: (id) => window.clearInterval(id),
    persistToken: setSessionToken,
    begin: async (provider, callbackURL) => authClient.signIn.social({
      provider,
      callbackURL,
      errorCallbackURL: callbackURL,
      disableRedirect: true,
    }) as never,
  };
}

function safeAuthorizationUrl(value: unknown, origin: string): string | null {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value, origin);
    if (url.protocol === 'https:') return url.href;
    if (url.protocol === 'http:' && (
      url.hostname === 'localhost'
      || url.hostname.endsWith('.localhost')
      || url.hostname === '127.0.0.1'
    )) return url.href;
  } catch {
    // Invalid provider response.
  }
  return null;
}

export async function signInWithSocialPopup(
  provider: SocialProviderId,
  dependencies?: SocialPopupDependencies,
): Promise<string> {
  const deps = dependencies ?? browserPopupDependencies();

  // This must remain the first asynchronous-flow action so it retains the click
  // gesture and provider pages load in a top-level browsing context.
  const popup = deps.open();
  if (!popup) {
    throw new Error(`Your browser blocked the ${provider === 'google' ? 'Google' : 'Apple'} sign-in window. Allow popups, then try again.`);
  }

  let abortCompletion: (error: Error) => void = () => {};
  const completion = new Promise<string>((resolve, reject) => {
    let settled = false;
    let poll = 0;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      deps.removeMessageListener(onMessage);
      deps.clearPoll(poll);
      callback();
    };
    abortCompletion = (error) => finish(() => reject(error));
    const onMessage = (event: PopupEvent) => {
      if (event.origin !== deps.origin || event.source !== popup) return;
      if (event.data?.type === 'openkey:social:error') {
        finish(() => reject(new Error(event.data?.message || 'Social sign-in failed.')));
        return;
      }
      if (event.data?.type !== 'openkey:social:complete' || !event.data.sessionToken) return;
      finish(() => {
        popup.close();
        deps.persistToken(event.data!.sessionToken!);
        resolve(event.data!.sessionToken!);
      });
    };
    deps.addMessageListener(onMessage);
    poll = deps.setPoll(() => {
      if (popup.closed) {
        finish(() => reject(new Error(`${provider === 'google' ? 'Google' : 'Apple'} sign-in was cancelled.`)));
      }
    });
  });

  try {
    const callbackURL = new URL('/auth/social/callback', deps.origin).href;
    const startup = await Promise.race([
      deps.begin(provider, callbackURL).then((result) => ({
        kind: 'authorization' as const,
        result,
      })),
      completion.then(() => ({ kind: 'completion' as const })),
    ]);
    if (startup.kind === 'completion') return completion;
    const { result } = startup;
    if (result.error) {
      throw new Error(result.error.message || `${provider === 'google' ? 'Google' : 'Apple'} sign-in failed.`);
    }
    const authorizationUrl = safeAuthorizationUrl(result.data?.url, deps.origin);
    if (!authorizationUrl) {
      throw new Error('The sign-in provider returned an invalid authorization URL.');
    }
    popup.location.href = authorizationUrl;
  } catch (error) {
    popup.close();
    abortCompletion(error instanceof Error ? error : new Error('Social sign-in failed.'));
    return completion;
  }

  return completion;
}

export async function loadConfiguredSocialProviders(
  fetchImpl: typeof fetch = fetch,
): Promise<SocialProviderId[]> {
  const response = await fetchImpl(`${API_BASE}/api/auth/providers`, {
    headers: { Accept: 'application/json' },
    credentials: 'include',
  });
  if (!response.ok) return [];
  const body = await response.json().catch(() => null);
  if (!Array.isArray(body?.providers)) return [];
  return body.providers.filter(
    (provider: unknown): provider is SocialProviderId =>
      provider === 'google' || provider === 'apple',
  );
}
