import { describe, expect, test } from 'bun:test';
import { makeSignature } from 'better-auth/crypto';
import { signedReviewerQuery } from '../services/reviewer-auth';
import { authoritativeQuery, matchesAuthoritativeQuery } from '../services/native-delegation/par';

const SECRET = 'oauth-signed-query-test-secret-0123456789';

// The provider's signParams (@better-auth/oauth-provider 1.6.35): envelope, the sorted `ba_param` list (itself
// included), a signature over the entries sorted by key then value, then `sig`.
async function sign(entries: [string, string][], names?: string[]): Promise<URLSearchParams> {
  const params = new URLSearchParams(entries);
  params.set('exp', String(Math.floor(Date.now() / 1000) + 600));
  params.set('ba_iat', String(Date.now()));
  for (const name of names ?? [...new Set([...params.keys(), 'ba_param'])].sort()) params.append('ba_param', name);
  const canonical = new URLSearchParams([...params].sort(([ka, va], [kb, vb]) => (ka < kb ? -1 : ka > kb ? 1 : va < vb ? -1 : va > vb ? 1 : 0)));
  params.set('sig', await makeSignature(canonical.toString(), SECRET));
  return params;
}

const reviewerEntries: [string, string][] = [
  ['response_type', 'code'], ['client_id', 'client-1'], ['redirect_uri', 'https://chatgpt.com/cb'],
  ['scope', 'openid email tinycloud:mcp'], ['state', 'state-1'], ['code_challenge', 'challenge'],
  ['code_challenge_method', 'S256'], ['resource', 'https://mcp.tinycloud.xyz/chatgpt/mcp'],
];

describe('signedReviewerQuery accepts only the canonical signed form', () => {
  test('the provider form, in any entry order', async () => {
    const signed = await sign(reviewerEntries);
    expect((await signedReviewerQuery(signed.toString(), SECRET))?.get('state')).toBe('state-1');
    const reordered = new URLSearchParams([...signed].reverse());
    expect(await signedReviewerQuery(reordered.toString(), SECRET)).not.toBeNull();
  });

  test('a tampered parameter', async () => {
    const signed = await sign(reviewerEntries);
    signed.set('redirect_uri', 'https://evil.example/cb');
    expect(await signedReviewerQuery(signed.toString(), SECRET)).toBeNull();
  });

  test('an extra unsigned parameter, appended or listed in ba_param after signing', async () => {
    const appended = await sign(reviewerEntries);
    appended.append('prompt', 'none');
    expect(await signedReviewerQuery(appended.toString(), SECRET)).toBeNull();
    const listed = new URLSearchParams(appended);
    listed.append('ba_param', 'prompt');
    expect(await signedReviewerQuery(listed.toString(), SECRET)).toBeNull();
  });

  test('a duplicated parameter, even signed, in either order', async () => {
    const duplicate = await sign([...reviewerEntries, ['state', 'state-2']]);
    expect(await signedReviewerQuery(duplicate.toString(), SECRET)).toBeNull();
    const reordered = new URLSearchParams([...duplicate].reverse());
    expect(await signedReviewerQuery(reordered.toString(), SECRET)).toBeNull();
  });

  test('a ba_param list that repeats or omits a name, even signed', async () => {
    const names = [...new Set([...reviewerEntries.map(([key]) => key), 'exp', 'ba_iat', 'ba_param'])].sort();
    expect(await signedReviewerQuery((await sign(reviewerEntries, [...names, 'state'])).toString(), SECRET)).toBeNull();
    expect(await signedReviewerQuery((await sign(reviewerEntries, names.filter((name) => name !== 'state'))).toString(), SECRET)).toBeNull();
    expect(await signedReviewerQuery((await sign(reviewerEntries, names)).toString(), SECRET)).not.toBeNull();
  });

  test('a second signature', async () => {
    const signed = await sign(reviewerEntries);
    signed.append('sig', signed.get('sig')!);
    expect(await signedReviewerQuery(signed.toString(), SECRET)).toBeNull();
  });
});

describe('matchesAuthoritativeQuery binds a native continuation to its PAR row', () => {
  const row = {
    id: 'request-1', clientId: 'native-client', redirectUri: 'xyz.tinycloud.exo://openkey/callback', state: 'state-1',
    scopes: ['openid', 'email', 'tinycloud:delegation'], codeChallenge: 'challenge', loginMethod: 'email',
  };
  const expected = authoritativeQuery(row);

  test('the signed continuation and the unsigned authorize query both match', async () => {
    expect(matchesAuthoritativeQuery(await sign([...expected]), expected)).toBe(true);
    expect(matchesAuthoritativeQuery(new URLSearchParams(expected), expected)).toBe(true);
  });

  test('a tampered parameter', async () => {
    const signed = await sign([...expected]);
    signed.set('scope', 'openid email tinycloud:delegation tinycloud:session');
    expect(matchesAuthoritativeQuery(signed, expected)).toBe(false);
  });

  test('an extra unsigned parameter', async () => {
    const signed = await sign([...expected]);
    signed.append('resource', 'https://mcp.tinycloud.xyz/mcp');
    expect(matchesAuthoritativeQuery(signed, expected)).toBe(false);
    const listed = await sign([...expected], [...new Set([...expected.keys(), 'exp', 'ba_iat', 'ba_param'])].sort());
    listed.append('ba_param', 'resource');
    expect(matchesAuthoritativeQuery(listed, expected)).toBe(false);
  });

  test('a duplicated parameter, in either order', async () => {
    const duplicate = await sign([...expected, ['state', 'state-2']]);
    expect(matchesAuthoritativeQuery(duplicate, expected)).toBe(false);
    expect(matchesAuthoritativeQuery(new URLSearchParams([...duplicate].reverse()), expected)).toBe(false);
    const unsigned = new URLSearchParams([['state', 'state-2'], ...expected]);
    expect(matchesAuthoritativeQuery(unsigned, expected)).toBe(false);
  });
});
