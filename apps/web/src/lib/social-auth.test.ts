// TC-2304: the Google/Apple popup signs in inside its own window, so the opener tab's Better Auth session store
// never hears about it. The helper must refresh that store itself, once, after the popup resolves, so every
// caller (register, login, embedded sign-in) shows the signed-in view without a reload.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { signInWithSocialPopup, type SocialPopupDependencies } from './social-auth';

type Listener = Parameters<SocialPopupDependencies['addMessageListener']>[0];

function harness() {
  const calls: string[] = [];
  let listener: Listener | null = null;
  let poll: (() => void) | null = null;
  const popup = { closed: false, close() { popup.closed = true; calls.push('popup.close'); } };
  const deps: SocialPopupDependencies = {
    origin: 'https://openkey.so',
    open: () => popup,
    addMessageListener: (next) => { listener = next; },
    removeMessageListener: () => { listener = null; },
    setPoll: (next) => { poll = next; return 1; },
    clearPoll: () => { poll = null; },
    persistToken: (token) => { calls.push(`persist:${token}`); },
    refreshSession: () => { calls.push('refresh'); },
  };
  return {
    deps, calls, popup,
    send: (data: object, origin = 'https://openkey.so') => listener?.({ origin, source: popup, data }),
    closeWindow: () => { popup.closed = true; poll?.(); },
  };
}

describe('signInWithSocialPopup', () => {
  test('refreshes the opener\'s session once, after the token is saved, before the caller continues', async () => {
    const h = harness();
    const done = signInWithSocialPopup('google', h.deps).then((token) => { h.calls.push(`resolved:${token}`); return token; });
    h.send({ type: 'openkey:social:complete', sessionToken: 'tok' });
    expect(await done).toBe('tok');
    expect(h.calls).toEqual(['popup.close', 'persist:tok', 'refresh', 'resolved:tok']);
  });

  test.each([
    ['an error from the popup', (h: ReturnType<typeof harness>) => h.send({ type: 'openkey:social:error', message: 'no' })],
    ['the popup window being closed', (h: ReturnType<typeof harness>) => h.closeWindow()],
  ])('does not refresh the session after %s', async (_label: string, trigger: (h: ReturnType<typeof harness>) => void) => {
    const h = harness();
    const done = signInWithSocialPopup('google', h.deps).then(() => 'resolved', () => 'rejected');
    trigger(h);
    expect(await done).toBe('rejected');
    expect(h.calls).not.toContain('refresh');
  });

  test('a message from another origin or without a token is ignored and refreshes nothing', async () => {
    const h = harness();
    const done = signInWithSocialPopup('google', h.deps);
    h.send({ type: 'openkey:social:complete', sessionToken: 'stolen' }, 'https://evil.example');
    h.send({ type: 'openkey:social:complete' });
    expect(h.calls).toEqual([]);
    h.send({ type: 'openkey:social:complete', sessionToken: 'real' });
    expect(await done).toBe('real');
    expect(h.calls.filter((c) => c === 'refresh')).toHaveLength(1);
  });
});
