// Signing out without agreeing to the Terms: it tells whoever sent the account there that the answer is
// no, then signs out. Telling the requester no never stands in the way of leaving.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { declineTerms, disconnectHref, optionsHref, originOfTermsPage, termsOrigin, termsPageFor, termsPageFrom, type TermsOrigin } from './terms-leave';

const API = 'https://api.openkey.test';
const SIGNED = 'response_type=code&client_id=app-1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=s&exp=1&sig=abc';
const APPROVAL_ID = 'abcdefghijklmnopqrstuvwxyz';

type Answer = [number, unknown] | 'network';
function fetchBy(answers: Record<string, Answer>) {
  const calls: Array<{ path: string; init?: RequestInit }> = [];
  const impl = (async (url: string, init?: RequestInit) => {
    const path = url.slice(API.length);
    calls.push({ path, init });
    const answer = answers[path] ?? [200, {}];
    if (answer === 'network') throw new TypeError('Failed to fetch');
    return new Response(JSON.stringify(answer[1]), { status: answer[0], headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { impl, calls, paths: () => calls.map((call) => call.path) };
}

function memoryStorage(entries: Record<string, string> = {}) {
  const map = new Map(Object.entries(entries));
  return { getItem: (key: string) => map.get(key) ?? null, removeItem: (key: string) => { map.delete(key); }, map };
}

function deps(fetchImpl: typeof fetch, storage = memoryStorage()) {
  let signedOut = 0;
  return {
    deps: { apiBase: API, fetch: fetchImpl, storage, signOut: async () => { signedOut += 1; } },
    signOuts: () => signedOut,
  };
}

describe('termsOrigin', () => {
  test('the sign-in page’s own signed authorize query is an OAuth request', () => {
    expect(termsOrigin(`?${SIGNED}`, null)).toEqual({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: null });
  });

  test('a consent screen sent here keeps its signed query; a native request is named too', () => {
    const returnTo = `/oauth/consent?${SIGNED}&tinycloud_request=req-9`;
    expect(termsOrigin(`?returnTo=${encodeURIComponent(returnTo)}`, returnTo))
      .toEqual({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: 'req-9' });
  });

  test('an approval link and a device sign-in are found from where the account was going', () => {
    expect(termsOrigin('', `/a/${APPROVAL_ID}`)).toEqual({ kind: 'approval', requestId: APPROVAL_ID });
    expect(termsOrigin('', '/delegate?did=x&deviceTransactionId=dt-1&deviceUserCode=ABCD'))
      .toEqual({ kind: 'device', transactionId: 'dt-1' });
  });

  test.each([
    ['no return path', null],
    ['an ordinary page', '/dashboard/settings'],
    ['a consent screen with no signature', '/oauth/consent?client_id=app-1'],
    ['a malformed approval id', '/a/NOT-AN-ID'],
    ['another origin', 'https://elsewhere.test/a/abcdefghijklmnopqrstuvwxyz'],
    ['a protocol-relative path', '//elsewhere.test/delegate?deviceTransactionId=dt-1'],
  ])('%s is no request', (_name: string, returnTo: string | null) => {
    expect(termsOrigin('', returnTo)).toEqual({ kind: 'none' });
  });
});

describe('Other options and Disconnect apps', () => {
  test('they keep the standalone Terms for the same request, sign-in included', () => {
    const oauthTerms = termsPageFor(`?${SIGNED}&redirect=%2Fx`, null);
    expect(oauthTerms).toBe(`/auth/terms?${SIGNED}`);
    expect(termsPageFor('', `/a/${APPROVAL_ID}`)).toBe(`/auth/terms?returnTo=${encodeURIComponent(`/a/${APPROVAL_ID}`)}`);
    expect(termsPageFor('', null)).toBe('/auth/terms');
    expect(optionsHref(oauthTerms)).toBe(`/auth/terms/options?returnTo=${encodeURIComponent(oauthTerms)}`);
    expect(disconnectHref(oauthTerms)).toBe(`/auth/terms/leave?returnTo=${encodeURIComponent(oauthTerms)}`);
  });

  test('the request is found again from the Terms they keep', () => {
    const approvalTerms = termsPageFor('', `/a/${APPROVAL_ID}`);
    expect(termsPageFrom(approvalTerms)).toBe(approvalTerms);
    expect(originOfTermsPage(termsPageFrom(approvalTerms))).toEqual({ kind: 'approval', requestId: APPROVAL_ID });
    expect(originOfTermsPage(`/auth/terms?${SIGNED}&tinycloud_request=req-9`)).toEqual({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: 'req-9' });
    expect(originOfTermsPage('/auth/terms')).toEqual({ kind: 'none' });
  });

  test.each([null, '/dashboard', '/auth/terms/leave?returnTo=%2Fauth%2Fterms', '/auth/termsx', '//evil.test/auth/terms', 'https://evil.test/auth/terms'])(
    'they go back only to the Terms (%s goes to the plain Terms)',
    (returnTo: string | null) => expect(termsPageFrom(returnTo)).toBe('/auth/terms'),
  );
});

describe('declineTerms', () => {
  test('an OAuth request is denied first, then the account signs out, and the app’s answer is where to go', async () => {
    const api = fetchBy({ '/api/auth/oauth2/consent': [200, { url: 'https://app.test/cb?error=access_denied&state=s' }] });
    const { deps: d, signOuts } = deps(api.impl);
    const result = await declineTerms({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: null }, d);

    expect(api.paths()).toEqual(['/api/auth/oauth2/consent']);
    expect(JSON.parse(String(api.calls[0]!.init?.body))).toEqual({ accept: false, oauth_query: SIGNED });
    expect(api.calls.every((call) => call.init?.method === 'POST' && call.init?.credentials === 'include')).toBe(true);
    expect(result).toEqual({ redirect: 'https://app.test/cb?error=access_denied&state=s' });
    expect(signOuts()).toBe(1);
  });

  test('a native request is denied before the consent', async () => {
    const api = fetchBy({ '/api/auth/oauth2/consent': [200, { redirect: 'com.app.example:/cb?error=access_denied' }] });
    const result = await declineTerms({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: 'req 9' }, deps(api.impl).deps);
    expect(api.paths()).toEqual(['/api/oauth/tinycloud/requests/req%209/deny', '/api/auth/oauth2/consent']);
    expect(result.redirect).toBe('com.app.example:/cb?error=access_denied');
  });

  test('an unsafe redirect from the consent answer is not followed', async () => {
    const api = fetchBy({ '/api/auth/oauth2/consent': [200, { url: 'javascript:alert(1)' }] });
    expect(await declineTerms({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: null }, deps(api.impl).deps)).toEqual({ redirect: null });
  });

  test('an approval link is declined with its kept reference, which is then forgotten', async () => {
    const api = fetchBy({});
    const storage = memoryStorage({ [`openkey.approval.${APPROVAL_ID}`]: '#tv1.secret' });
    const { deps: d, signOuts } = deps(api.impl, storage);
    const result = await declineTerms({ kind: 'approval', requestId: APPROVAL_ID }, d);

    expect(api.paths()).toEqual([`/api/approval-requests/${APPROVAL_ID}/deny`]);
    expect(JSON.parse(String(api.calls[0]!.init?.body))).toEqual({ reference: `/a/${APPROVAL_ID}#tv1.secret` });
    expect(storage.map.size).toBe(0);
    expect(result).toEqual({ redirect: null });
    expect(signOuts()).toBe(1);
  });

  test('an approval link this tab no longer holds is left alone', async () => {
    const api = fetchBy({});
    const { deps: d, signOuts } = deps(api.impl);
    await declineTerms({ kind: 'approval', requestId: APPROVAL_ID }, d);
    expect(api.paths()).toEqual([]);
    expect(signOuts()).toBe(1);
  });

  test('a device sign-in is denied', async () => {
    const api = fetchBy({});
    await declineTerms({ kind: 'device', transactionId: 'dt/1' }, deps(api.impl).deps);
    expect(api.paths()).toEqual(['/api/device-authorizations/dt%2F1/deny']);
  });

  test('with no request, the account only signs out', async () => {
    const api = fetchBy({});
    const { deps: d, signOuts } = deps(api.impl);
    expect(await declineTerms({ kind: 'none' }, d)).toEqual({ redirect: null });
    expect(api.paths()).toEqual([]);
    expect(signOuts()).toBe(1);
  });

  test.each<[string, Answer]>([
    ['refused', [500, { error: 'deny_failed' }]],
    ['unreachable', 'network'],
  ])('a deny that is %s still lets the account leave', async (_name: string, answer: Answer) => {
    const origins: Array<[TermsOrigin, string]> = [
      [{ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: 'req-9' }, '/api/oauth/tinycloud/requests/req-9/deny'],
      [{ kind: 'device', transactionId: 'dt-1' }, '/api/device-authorizations/dt-1/deny'],
      [{ kind: 'approval', requestId: APPROVAL_ID }, `/api/approval-requests/${APPROVAL_ID}/deny`],
    ];
    for (const [origin, denyPath] of origins) {
      const api = fetchBy({ [denyPath]: answer, '/api/auth/oauth2/consent': answer });
      const { deps: d, signOuts } = deps(api.impl, memoryStorage({ [`openkey.approval.${APPROVAL_ID}`]: '#tv1.secret' }));
      expect(await declineTerms(origin, d)).toEqual({ redirect: null });
      expect(signOuts()).toBe(1);
    }
  });

  test('a sign-out that fails is reported, and no app redirect is taken', async () => {
    const api = fetchBy({ '/api/auth/oauth2/consent': [200, { url: 'https://app.test/cb?error=access_denied' }] });
    const d = { apiBase: API, fetch: api.impl, storage: memoryStorage(), signOut: async () => { throw new Error('offline'); } };
    await expect(declineTerms({ kind: 'oauth', oauthQuery: SIGNED, nativeRequestId: null }, d)).rejects.toThrow('offline');
  });
});
