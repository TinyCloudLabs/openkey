// A refused deletion because billing could not cancel the plan has its own owner-facing message,
// distinct from the generic 503 "busy" one.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { DeletionError, deleteAccount } from './account-deletion';

const API = 'https://api.openkey.test';

function answer(status: number, body: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch;
}

async function failureOf(status: number, body: unknown): Promise<DeletionError> {
  try {
    await deleteAccount(API, answer(status, body));
  } catch (error) {
    if (error instanceof DeletionError) return error;
    throw error;
  }
  throw new Error('deleteAccount did not fail');
}

describe('account deletion refused by billing', () => {
  test('the API refusal body maps to the billing message, not the busy one', async () => {
    const error = await failureOf(503, { error: 'billing_unavailable', code: 'billing_unavailable' });
    expect(error.message).toBe("OpenKey couldn't reach billing to cancel your plan, so nothing was deleted. Try again in a few minutes.");
    expect(error.code).toBe('billing_unavailable');
    expect(error.status).toBe(503);
  });

  test('any other 503 keeps the generic busy message', async () => {
    const error = await failureOf(503, { error: 'unavailable' });
    expect(error.message).toBe('OpenKey is busy right now. Try again in a moment.');
    expect(error.code).toBeNull();
  });
});
