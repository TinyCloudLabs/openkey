#!/usr/bin/env bun

/**
 * Exercises the candidate's public Better Auth email-OTP endpoints.  The
 * caller supplies a disposable, pre-cutover PostgreSQL candidate and starts
 * the API with TEE_MODE=development; that mode reserves 000000 for this
 * exact smoke address, so no mail provider or production credential is used.
 */
const api = process.argv[2];
if (!api) throw new Error('Usage: bun run scripts/candidate-otp-session-smoke.ts http://127.0.0.1:PORT');

const email = 'test@openkey.dev';
const send = await fetch(`${api}/api/auth/email-otp/send-verification-otp`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email, type: 'sign-in' }),
});
if (!send.ok || (await send.json() as { success?: boolean }).success !== true) {
  throw new Error(`OTP request failed: ${send.status}`);
}

const verify = await fetch(`${api}/api/auth/sign-in/email-otp`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email, otp: '000000' }),
});
const session = await verify.json() as { token?: string; user?: { email?: string; id?: string } };
if (!verify.ok || !session.token || session.user?.email !== email || !session.user.id || !verify.headers.get('set-auth-token')) {
  throw new Error(`OTP verification did not create an authenticated session: ${verify.status}`);
}
process.stdout.write(`${JSON.stringify({
  publicOtpRequest: true,
  publicOtpVerification: true,
  authenticatedSession: true,
  userId: session.user.id,
})}\n`);
