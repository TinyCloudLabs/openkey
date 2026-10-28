// TC-1632: Cloudflare Turnstile loader for the new-account step. The site key
// is public (VITE_TURNSTILE_SITE_KEY); the secret stays on the API.

export interface TurnstileRenderOptions {
  sitekey: string;
  action: string;
  appearance: 'always' | 'execute' | 'interaction-only';
  callback: (token: string) => void;
  'expired-callback': () => void;
  'error-callback': () => void;
  'timeout-callback': () => void;
}

export interface TurnstileApi {
  render(container: HTMLElement, options: TurnstileRenderOptions): string;
  reset(widgetId: string): void;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

/** Must match the API's TURNSTILE_ACTION (apps/api/src/services/turnstile.ts). */
export const TURNSTILE_ACTION = 'email-signup';

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
/** A stalled script fails visibly after this timeout, so the step never waits forever. */
const SCRIPT_TIMEOUT_MS = 10_000;

let loading: Promise<TurnstileApi> | null = null;

export function turnstileSiteKey(): string {
  return import.meta.env.VITE_TURNSTILE_SITE_KEY || '';
}

export function loadTurnstile(): Promise<TurnstileApi> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  loading ??= new Promise<TurnstileApi>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = SCRIPT_URL;
    script.async = true;
    const fail = () => {
      clearTimeout(timer);
      loading = null;
      script.remove();
      reject(new Error('Verification did not load.'));
    };
    const timer = setTimeout(fail, SCRIPT_TIMEOUT_MS);
    script.onload = () => {
      clearTimeout(timer);
      if (window.turnstile) resolve(window.turnstile);
      else fail();
    };
    script.onerror = fail;
    document.head.appendChild(script);
  });
  return loading;
}
