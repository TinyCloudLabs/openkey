// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { hasSignResult, hasText, readReply, ServerRefusalError, ServerReplyError, SERVER_REPLY_BODY, SERVER_REPLY_TITLE, terminalRefusal } from './server-reply';

const reply = (body: string, init: ResponseInit = { status: 200 }) => new Response(body, init);
const needsToken = (body: Record<string, unknown>) => hasText(body, 'token');

async function failure(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('the reply was accepted');
}

describe('the words shown when a reply cannot be read', () => {
  test('has the approved title and carries no status', () => {
    expect(SERVER_REPLY_TITLE).toBe("OpenKey couldn't finish this request");
    expect(SERVER_REPLY_TITLE + SERVER_REPLY_BODY).not.toMatch(/HTTP|<status>|\d{3}/);
  });
});

describe('readReply', () => {
  test('returns a JSON object that has the fields', async () => {
    await expect(readReply(reply('{"token":"t","extra":1}'), needsToken, 'x')).resolves.toEqual({ token: 't', extra: 1 });
  });

  test.each([
    ['an empty body', ''],
    ['text that is not JSON', 'not json'],
    ['an object without the fields', '{}'],
    ['a field that is empty', '{"token":""}'],
    ['a field that is not text', '{"token":7}'],
    ['an array', '[{"token":"t"}]'],
    ['null', 'null'],
    ['a string', '"token"'],
  ])('a 200 with %s is an unreadable reply that carries the status only', async (_name: string, body: string) => {
    const error = await failure(readReply(reply(body), needsToken, 'x'));
    expect(error).toBeInstanceOf(ServerReplyError);
    expect(error).toMatchObject({ status: 200, message: 'unreadable server reply (HTTP 200)' });
  });

  test('a 2xx other than 200 is read the same way', async () => {
    const error = await failure(readReply(reply('', { status: 204 }), needsToken, 'x'));
    expect(error).toMatchObject({ status: 204 });
  });

  test('a refusal keeps the server\'s own text', async () => {
    const error = await failure(readReply(reply('{"error":"This request is not allowed"}', { status: 403 }), needsToken, 'x'));
    expect(error).not.toBeInstanceOf(ServerReplyError);
    expect(error).toMatchObject({ message: 'This request is not allowed' });
  });

  test('a refusal without JSON uses the fallback, and one without text the status', async () => {
    expect(await failure(readReply(reply('', { status: 502 }), needsToken, 'prepare failed'))).toMatchObject({ message: 'prepare failed' });
    expect(await failure(readReply(reply('{}', { status: 500 }), needsToken, 'x'))).toMatchObject({ message: 'HTTP 500' });
  });
});

describe('hasSignResult', () => {
  const grant = { service: 'tinycloud.kv', space: 'space', path: 'notes/', actions: ['tinycloud.kv/get'] };
  const signed = { signature: '0xsig', address: '0xaddr', signedMessage: 'bytes', selectedActionKeys: ['key'], permissions: [grant] };

  test('a signature with its address, bytes, selected keys and grants is readable, including empty lists', () => {
    expect(hasSignResult(signed)).toBe(true);
    expect(hasSignResult({ ...signed, selectedActionKeys: [], permissions: [] })).toBe(true);
  });

  test.each([
    ['no selectedActionKeys', { ...signed, selectedActionKeys: undefined }],
    ['no permissions', { ...signed, permissions: undefined }],
    ['selectedActionKeys of the wrong type', { ...signed, selectedActionKeys: 'key' }],
    ['a selected key that is not text', { ...signed, selectedActionKeys: [1] }],
    ['permissions of the wrong type', { ...signed, permissions: grant }],
    ['a permission that is not an object', { ...signed, permissions: [null] }],
    ['a permission without a path', { ...signed, permissions: [{ ...grant, path: undefined }] }],
    ['a permission whose actions are not text', { ...signed, permissions: [{ ...grant, actions: [1] }] }],
    ['no signature', { ...signed, signature: '' }],
  ] as Array<[string, Record<string, unknown>]>)('%s is not readable', (_label: string, body: Record<string, unknown>) => {
    expect(hasSignResult(body)).toBe(false);
  });
});

// TC-2291: a definite refusal keeps its code and status so the widget can tell the app; anything else stays a plain error.
describe('readReply with a definite refusal', () => {
  const refusal = (code: string, status = 403) => reply(JSON.stringify({ error: 'server words', code }), { status });

  test.each(['app_key_grant_refused', 'key_delete_not_grantable', 'invalid_siwe_recap'])('%s throws a ServerRefusalError with the status, code and the server\'s words', async (code: string) => {
    const error = await failure(readReply(refusal(code, code === 'invalid_siwe_recap' ? 400 : 403), needsToken, 'x'));
    expect(error).toBeInstanceOf(ServerRefusalError);
    expect(error).toMatchObject({ code, message: 'server words', status: code === 'invalid_siwe_recap' ? 400 : 403 });
  });

  test.each([
    ['an unknown code', refusal('something_else')],
    ['a server error carrying a refusal code', refusal('app_key_grant_refused', 503)],
    ['no code', reply(JSON.stringify({ error: 'server words' }), { status: 403 })],
    ['a body that is not JSON', reply('nope', { status: 403 })],
  ])('%s stays a plain Error', async (_label: string, response: Response) => {
    const error = await failure(readReply(response, needsToken, 'fallback'));
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ServerRefusalError);
  });
});

// TC-2457: a refusal that cannot change on retry is told apart from a temporary failure by the server's `code`.
describe('terminal refusals', () => {
  const refusal = (code: string | undefined, status = 403) =>
    readReply(reply(JSON.stringify({ error: 'The server said no.', ...(code ? { code } : {}) }), { status }), needsToken, 'fallback');

  test.each([
    ['app_key_grant_refused', 403],
    ['key_delete_not_grantable', 403],
    ['invalid_siwe_recap', 400],
  ])('%s is terminal and keeps the server text', async (code: string, status: number) => {
    const error = await failure(refusal(code, status));
    const terminal = terminalRefusal(error);
    expect(terminal).not.toBeNull();
    expect(terminal?.text).toBe('The server said no.');
    expect(terminal?.hostMessage).toMatch(/^[A-Z_]+$/);
  });

  test('each terminal code reports a different identifier to the host', async () => {
    const seen = new Set<string>();
    for (const code of ['app_key_grant_refused', 'key_delete_not_grantable', 'invalid_siwe_recap']) {
      seen.add(terminalRefusal(await failure(refusal(code)))!.hostMessage);
    }
    expect(seen.size).toBe(3);
  });

  test.each([
    ['a 500 with no code', undefined, 500],
    ['a 503 with a refusal code', 'app_key_grant_refused', 503],
    ['a 403 with another code', 'something_else', 403],
    ['a rate limit', 'rate_limited', 429],
  ])('%s is not terminal', async (_name: string, code: string | undefined, status: number) => {
    expect(terminalRefusal(await failure(refusal(code, status)))).toBeNull();
  });

  test('anything that is not a reply error is not terminal', () => {
    for (const value of [null, undefined, 'app_key_grant_refused', { code: 'app_key_grant_refused' }, new Error('plain'), new ServerReplyError(200)]) {
      expect(terminalRefusal(value)).toBeNull();
    }
  });

  test('an error from the API client that carries the code is terminal too', () => {
    const error = Object.assign(new Error('Not listed.'), { code: 'app_key_grant_refused', status: 403 });
    expect(terminalRefusal(error)?.text).toBe('Not listed.');
  });
});
