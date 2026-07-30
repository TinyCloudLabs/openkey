import { API_BASE } from './auth-client';
import { setSessionToken } from './embed-passkey';

export type SocialProviderId = 'google' | 'apple';

type PopupLike = {
  closed: boolean;
  close(): void;
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
  open: (url: string) => PopupLike | null;
  addMessageListener: (listener: (event: PopupEvent) => void) => void;
  removeMessageListener: (listener: (event: PopupEvent) => void) => void;
  setPoll: (listener: () => void) => number;
  clearPoll: (id: number) => void;
  persistToken: (token: string) => void;
};

function browserPopupDependencies(): SocialPopupDependencies {
  return {
    origin: window.location.origin,
    open: (url) => window.open(url, 'openkey-social-sign-in', 'popup=true,width=520,height=720') as PopupLike | null,
    addMessageListener: (listener) => window.addEventListener('message', listener as unknown as EventListener),
    removeMessageListener: (listener) => window.removeEventListener('message', listener as unknown as EventListener),
    setPoll: (listener) => window.setInterval(listener, 500),
    clearPoll: (id) => window.clearInterval(id),
    persistToken: setSessionToken,
  };
}

export function socialPopupStartUrl(provider: SocialProviderId, origin: string): string {
  const url = new URL('/auth/social/callback', origin);
  url.searchParams.set('provider', provider);
  return url.href;
}

export function safeSocialAuthorizationUrl(
  value: unknown,
  provider: SocialProviderId,
): string | null {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    const expectedOrigin = provider === 'google'
      ? 'https://accounts.google.com'
      : 'https://appleid.apple.com';
    if (url.origin === expectedOrigin) return url.href;
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

  // Open the same-origin starter page directly from the click. It initiates
  // Better Auth from the top-level popup so OAuth state cookies do not depend
  // on third-party cookie access from the embedding iframe.
  const popup = deps.open(socialPopupStartUrl(provider, deps.origin));
  if (!popup) {
    throw new Error(`Your browser blocked the ${provider === 'google' ? 'Google' : 'Apple'} sign-in window. Allow popups, then try again.`);
  }

  return new Promise<string>((resolve, reject) => {
    let settled = false;
    let poll = 0;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      deps.removeMessageListener(onMessage);
      deps.clearPoll(poll);
      callback();
    };
    const onMessage = (event: PopupEvent) => {
      if (event.origin !== deps.origin || event.source !== popup) return;
      if (event.data?.type === 'openkey:social:error') {
        finish(() => {
          popup.close();
          reject(new Error(event.data?.message || 'Social sign-in failed.'));
        });
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
