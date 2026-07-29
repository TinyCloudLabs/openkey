import { describe, expect, test } from 'bun:test';

import {
  safeSocialAuthorizationUrl,
  signInWithSocialPopup,
  socialPopupStartUrl,
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
  };
  let listener: ((event: any) => void) | undefined;
  let poll: (() => void) | undefined;
  let openedURL = '';
  let persisted = '';

  const dependencies: SocialPopupDependencies = {
    origin: 'https://openkey.test',
    open: (url) => {
      calls.push('open');
      openedURL = url;
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
  };

  return {
    calls,
    dependencies,
    listener: () => listener!,
    poll: () => poll!,
    popup,
    openedURL: () => openedURL,
    persisted: () => persisted,
  };
}

describe('social popup sign-in', () => {
  test('reports popup blocking before starting provider authorization', async () => {
    const harness = popupHarness({ blocked: true });
    await expect(signInWithSocialPopup('google', harness.dependencies))
      .rejects.toThrow('blocked the Google sign-in window');
    expect(harness.calls).toEqual(['open']);
    expect(harness.openedURL()).toBe(
      'https://openkey.test/auth/social/callback?provider=google',
    );
  });

  test('opens synchronously, selects Google or Apple, and validates origin and source', async () => {
    for (const provider of ['google', 'apple'] as const) {
      const harness = popupHarness();
      const completion = signInWithSocialPopup(provider, harness.dependencies);

      expect(harness.calls[0]).toBe('open');
      expect(harness.openedURL()).toBe(
        `https://openkey.test/auth/social/callback?provider=${provider}`,
      );

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

  test('accepts authorization URLs only from the selected provider', () => {
    expect(safeSocialAuthorizationUrl(
      'https://accounts.google.com/o/oauth2/v2/auth?client_id=google',
      'google',
    )).toContain('https://accounts.google.com/o/oauth2/v2/auth');
    expect(safeSocialAuthorizationUrl(
      'https://appleid.apple.com/auth/authorize?client_id=apple',
      'apple',
    )).toContain('https://appleid.apple.com/auth/authorize');
    expect(safeSocialAuthorizationUrl('https://evil.test/oauth', 'google')).toBeNull();
    expect(safeSocialAuthorizationUrl(
      'https://accounts.google.com/o/oauth2/v2/auth',
      'apple',
    )).toBeNull();
    expect(socialPopupStartUrl('apple', 'https://openkey.test'))
      .toBe('https://openkey.test/auth/social/callback?provider=apple');
  });
});
