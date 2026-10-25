// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { hasText, readReply, ServerReplyError, SERVER_REPLY_BODY, SERVER_REPLY_TITLE } from './server-reply';

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
  test('are the approved title and body, and carry no status', () => {
    expect(SERVER_REPLY_TITLE).toBe("OpenKey couldn't finish this request");
    expect(SERVER_REPLY_BODY).toBe(
      "OpenKey couldn't read the server's reply, so nothing was approved. Please try again. If it keeps happening, contact the app.",
    );
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
