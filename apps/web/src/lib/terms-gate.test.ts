// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { Window } from 'happy-dom';
import { get } from 'svelte/store';
import { checkTerms, type TermsCheck, type TermsStatus } from './terms';
import { createTermsGate } from './terms-gate';

// The check reads the page's credential: a top-level window here, so the browser's cookie session.
const win = new Window({ url: 'https://openkey.so/' });
Object.assign(globalThis, { window: win, sessionStorage: win.sessionStorage });

const STATUS: TermsStatus = {
  version: '2026-11-01', effective: '2026-11-01', whatChanged: null, privacyChanged: false, requiresAcceptance: true, previouslyAccepted: false,
};

const reply = (status: number, body: unknown) => (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

describe('checkTerms', () => {
  test('reads an account that has agreed, one that owes the Terms and a signed-out credential', async () => {
    expect(await checkTerms(reply(200, { ...STATUS, requiresAcceptance: false }))).toEqual({ state: 'accepted' });
    expect(await checkTerms(reply(200, STATUS))).toEqual({ state: 'required', status: STATUS });
    expect(await checkTerms(reply(401, { error: 'unauthorized' }))).toEqual({ state: 'signed-out' });
  });

  test('an answer it cannot read is a failed check, never an account that has agreed', async () => {
    expect(await checkTerms(reply(404, { error: 'not_found' }))).toEqual({ state: 'failed' });
    expect(await checkTerms(reply(500, {}))).toEqual({ state: 'failed' });
    expect(await checkTerms(reply(200, { current: null }))).toEqual({ state: 'failed' });
    expect(await checkTerms((async () => { throw new TypeError('offline'); }) as unknown as typeof fetch)).toEqual({ state: 'failed' });
  });

  test('an answer that never comes is a failed check once the deadline passes', async () => {
    const hung = ((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init.signal!.addEventListener('abort', () => reject(init.signal!.reason));
    })) as unknown as typeof fetch;
    expect(await checkTerms(hung, 20)).toEqual({ state: 'failed' });
  });
});

// Each check waits for the test to answer it; awaiting the answered check lets the gate's own continuation run first.
function deferredChecks() {
  const checks: Array<PromiseWithResolvers<TermsCheck>> = [];
  const check = () => {
    checks.push(Promise.withResolvers<TermsCheck>());
    return checks.at(-1)!.promise;
  };
  const answer = async (index: number, result: TermsCheck) => {
    checks[index]!.resolve(result);
    await checks[index]!.promise;
  };
  return { check, checks, answer };
}

// A build with a Terms release, and one without.
const releaseOn = () => true;
const releaseOff = () => false;

describe('the Terms gate', () => {
  test('a signed-in account is checked, then given the Terms, and Agree opens the page', async () => {
    const { check, checks, answer } = deferredChecks();
    const gate = createTermsGate(check, releaseOn);
    gate.follow('user_1');
    expect(get(gate).phase).toBe('checking');
    await answer(0, { state: 'required', status: STATUS });
    expect(get(gate)).toEqual({ phase: 'required', status: STATUS });
    gate.agreed();
    expect(get(gate).phase).toBe('open');
  });

  test('moving between pages with the same account reads nothing again', async () => {
    const { check, checks, answer } = deferredChecks();
    const gate = createTermsGate(check, releaseOn);
    gate.follow('user_1');
    await answer(0, { state: 'accepted' });
    gate.follow('user_1');
    expect(checks).toHaveLength(1);
    expect(get(gate).phase).toBe('open');
  });

  test('an answer for an account that has since signed out is ignored', async () => {
    const { check, checks, answer } = deferredChecks();
    const gate = createTermsGate(check, releaseOn);
    gate.follow('user_1');
    gate.follow('user_2');
    void answer(1, { state: 'required', status: STATUS });
    await answer(0, { state: 'accepted' });
    expect(get(gate).phase).toBe('required');
  });

  test('a refused call reads the status again and gives the Terms when they are owed', async () => {
    const { check, checks, answer } = deferredChecks();
    const gate = createTermsGate(check, releaseOn);
    gate.follow('user_1');
    await answer(0, { state: 'accepted' });
    gate.recheck();
    expect(get(gate).phase).toBe('checking');
    await answer(1, { state: 'required', status: STATUS });
    expect(get(gate).phase).toBe('required');
  });

  test('a credential that signs no one in resets the gate and tells the page', async () => {
    const { check, checks, answer } = deferredChecks();
    const gate = createTermsGate(check, releaseOn);
    let signedOut = 0;
    gate.follow('token_1', () => { signedOut++; });
    await answer(0, { state: 'signed-out' });
    expect(get(gate).phase).toBe('idle');
    expect(signedOut).toBe(1);
  });
});

describe('the Terms gate in a build with no Terms release', () => {
  test('a signed-in account opens the page without reading the status', () => {
    const { check, checks } = deferredChecks();
    const gate = createTermsGate(check, releaseOff);
    gate.follow('user_1');
    expect(get(gate).phase).toBe('open');
    expect(checks).toHaveLength(0);
  });

  test('a refused call reads the status and gives the Terms in place', async () => {
    const { check, checks, answer } = deferredChecks();
    const gate = createTermsGate(check, releaseOff);
    gate.follow('user_1');
    gate.recheck();
    expect(checks).toHaveLength(1);
    await answer(0, { state: 'required', status: STATUS });
    expect(get(gate)).toEqual({ phase: 'required', status: STATUS });
  });
});
