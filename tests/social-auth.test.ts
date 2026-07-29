import { describe, expect, test } from 'bun:test';

import {
  signInWithSocialPopup,
  type SocialPopupDependencies,
  type SocialProviderId,
} from '../apps/web/src/lib/social-auth';

function popupHarness(options: { blocked?: boolean } = {}) {
  const calls: string[] = [];
  const popup = {
    closed: false,
    close() {
      this.closed = true;
      calls.push('close');
    },
    location: { href: '' },
  };
  let listener: ((event: any) => void) | undefined;
  let poll: (() => void) | undefined;
  let selectedProvider: SocialProviderId | undefined;
  let persisted = '';

  const dependencies: SocialPopupDependencies = {
    origin: 'https://openkey.test',
    open: () => {
      calls.push('open');
      return options.blocked ? null : popup;
    },
    addMessageListener: (value) => { listener = value; },
    removeMessageListener: () => { calls.push('remove-listener'); },
    setPoll: (value) => {
      poll = value;
      return 1;
    },
    clearPoll: () => { calls.push('clear-poll'); },
    persistToken: (token) => { persisted = token; },
    begin: async (provider, callbackURL) => {
      calls.push('begin');
      selectedProvider = provider;
      expect(callbackURL).toBe('https://openkey.test/auth/social/callback');
      return { data: { url: `https://accounts.example.test/${provider}` } };
    },
  };

  return {
    calls,
    dependencies,
    listener: () => listener!,
    poll: () => poll!,
    popup,
    selectedProvider: () => selectedProvider,
    persisted: () => persisted,
  };
}

describe('social popup sign-in', () => {
  test('reports popup blocking before starting provider authorization', async () => {
    const harness = popupHarness({ blocked: true });
    await expect(signInWithSocialPopup('google', harness.dependencies))
      .rejects.toThrow('blocked the Google sign-in window');
    expect(harness.calls).toEqual(['open']);
  });

  test('opens synchronously, selects Google or Apple, and validates origin and source', async () => {
    for (const provider of ['google', 'apple'] as const) {
      const harness = popupHarness();
      const completion = signInWithSocialPopup(provider, harness.dependencies);
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(harness.calls.slice(0, 2)).toEqual(['open', 'begin']);
      expect(harness.selectedProvider()).toBe(provider);
      expect(harness.popup.location.href).toBe(`https://accounts.example.test/${provider}`);

      harness.listener()({
        origin: 'https://evil.test',
        source: harness.popup,
        data: { type: 'openkey:social:complete', sessionToken: 'evil' },
      });
      harness.listener()({
        origin: 'https://openkey.test',
        source: {},
        data: { type: 'openkey:social:complete', sessionToken: 'wrong-source' },
      });
      expect(harness.persisted()).toBe('');
      expect(harness.popup.closed).toBe(false);

      harness.listener()({
        origin: 'https://openkey.test',
        source: harness.popup,
        data: { type: 'openkey:social:complete', sessionToken: `${provider}-token` },
      });
      expect(await completion).toBe(`${provider}-token`);
      expect(harness.persisted()).toBe(`${provider}-token`);
      expect(harness.popup.closed).toBe(true);
    }
  });

  test('reports provider popup cancellation and removes listeners', async () => {
    const harness = popupHarness();
    const completion = signInWithSocialPopup('apple', harness.dependencies);
    await Promise.resolve();
    harness.popup.closed = true;
    harness.poll()();

    await expect(completion).rejects.toThrow('Apple sign-in was cancelled');
    expect(harness.calls).toContain('remove-listener');
    expect(harness.calls).toContain('clear-poll');
  });
});
