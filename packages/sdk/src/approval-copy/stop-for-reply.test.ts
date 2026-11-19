// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { KNOWN_REPLY_CODES, approvalStop, stopForReply, type ReplyInput, type StopView } from './index';

describe('approval reply Stop content', () => {
  const cases: [ReplyInput, StopView['id'], string][] = [
    [{ status: 401 }, 'S22', 'HTTP 401 · session_required'],
    [{ status: 409, code: 'approval_in_progress' }, 'S24', 'HTTP 409 · approval_in_progress'],
    [{ status: 409, code: 'request_binding' }, 'S14', 'HTTP 409 · request_binding'],
    [{ status: 409, code: 'renewal_already_signed', renewalChangeable: true }, 'renewalLength', 'HTTP 409 · renewal_already_signed'],
    [{ status: 409, code: 'renewal_already_signed' }, 'S14', 'HTTP 409 · renewal_already_signed'],
    [{ status: 409, code: 'handoff_consumed' }, 'S13', 'HTTP 409 · handoff_consumed'],
    [{ status: 410 }, 'S13', 'HTTP 410'],
    [{ status: 429, phase: 'claim', code: 'rate_limited' }, 'S23', 'HTTP 429 · rate_limited'],
    [{ status: 404, phase: 'load' }, 'S5', 'HTTP 404'],
    [{ status: 410, phase: 'load', code: 'expired' }, 'S4', 'HTTP 410 · expired'],
    [{ status: 503, phase: 'load', code: 'internal_error' }, 'S6', 'HTTP 503 · request_load_failed'],
    [{ status: 400, phase: 'load', code: 'binding_mismatch' }, 'S7', 'HTTP 400 · binding_mismatch'],
    [{ status: 400, code: 'invalid_siwe_recap' }, 'S11', 'HTTP 400 · invalid_siwe_recap'],
    [{ status: 403, code: 'key_delete_not_grantable' }, 'S21', 'HTTP 403 · key_delete_not_grantable'],
    [{ status: 404, code: 'key_not_found' }, 'S25', 'HTTP 404 · key_not_found'],
    [{ status: 404 }, 'S26', 'HTTP 404'],
    [{ status: 500, code: 'internal_error' }, 'S26', 'HTTP 500 · internal_error'],
    [{ status: 400, code: 'invalid_permissions\n' }, 'S26', 'HTTP 400'],
    [{ status: 400, code: 'constructor' }, 'S26', 'HTTP 400 · constructor'],
    [{ status: 200, code: 'reply_unreadable' }, 'S27', 'HTTP 200 · reply_unreadable'],
    [{}, 'S26', ''],
  ];
  for (const [reply, id, support] of cases) {
    test(`${id} for ${JSON.stringify(reply)}`, () => {
      const stop = stopForReply(reply);
      expect(stop.id).toBe(id);
      expect(stop.support).toBe(support);
      expect(stop.body).not.toBe('');
    });
  }

  test('every known code has content and a placement', () => {
    for (const code of KNOWN_REPLY_CODES) {
      const stop = stopForReply({
        status: 400, code, permissionsEditable: true, expiryChangeable: true,
        values: { email: 'owner@example.test', keyName: 'Key 1' },
      });
      expect(stop.id).not.toBe('S26');
      expect(stop.body).not.toMatch(/\{\w+\}/);
      expect(stop.support).toMatch(/^HTTP 400 · [A-Za-z0-9_-]+$/);
      if (stop.placement === 'page') {
        expect(stop.title).not.toBe('');
        expect(stop.buttons.length).toBeGreaterThan(0);
      }
    }
  });

  test('only S19 has a separate developer detail and it is capped', () => {
    const detail = '<div>'.repeat(100);
    expect(stopForReply({ status: 400, code: 'invalid_permissions', detail })).toMatchObject({
      id: 'S19', placement: 'page', support: 'HTTP 400 · invalid_permissions', detail: detail.slice(0, 300),
      buttons: ['copy-details', 'close'],
    });
    expect(stopForReply({ status: 403, code: 'app_key_grant_refused', detail }).detail).toBeUndefined();
  });

  test('local stops use known values and the exact approved copy', () => {
    const missing = approvalStop('S17', { values: { email: 'owner@example.test', wanted: 'wants 0x2222…2222' } });
    expect(missing.body).toEndWith('A key can only share its own data, so there is nothing to approve here yet.');
    expect(missing.support).toBe('wallet_not_on_account · wants 0x2222…2222');
    expect(stopForReply({ status: 500 }).body).toBe('OpenKey doesn’t have a better explanation yet. Try again. If it happens twice, send us the line below and we’ll find it.');
    expect(stopForReply({ status: 410, code: 'handoff_expired', phase: 'claim', preparedSignIn: true }).body)
      .toBe('This sign-in was open for 5 minutes and ran out. Run the command again.');
    expect(approvalStop('S25', { fixedKey: true })).toMatchObject({
      body: 'Start again from the app or command.',
      buttons: ['close'],
    });
  });
});
