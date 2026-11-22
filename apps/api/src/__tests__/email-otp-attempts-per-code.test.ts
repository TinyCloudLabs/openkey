import { describe, expect, test } from 'bun:test';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { emailOTP } from 'better-auth/plugins';
import { signInCodeStorage } from '../services/email-code-storage';

const ORIGIN = 'https://api.test';
const EMAIL = 'attempts@example.test';

/** Better Auth with the sign-in code settings auth.ts uses, including its hashed code storage. */
function authWithOpenKeyCodes() {
  const codes: string[] = [];
  const auth = betterAuth({
    baseURL: `${ORIGIN}/api/auth`,
    secret: 'better-auth-secret-that-is-long-enough-for-a-runtime-test',
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    logger: { disabled: true },
    plugins: [emailOTP({
      sendVerificationOTP: async ({ otp }) => { codes.push(otp); },
      otpLength: 6,
      expiresIn: 300,
      resendStrategy: 'rotate',
      storeOTP: signInCodeStorage,
    })],
  });
  const post = (path: string, body: Record<string, string>) => auth.handler(new Request(`${ORIGIN}/api/auth${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN },
    body: JSON.stringify(body),
  }));
  const issueCode = async () => {
    expect((await post('/email-otp/send-verification-otp', { email: EMAIL, type: 'sign-in' })).status).toBe(200);
    return codes.at(-1)!;
  };
  const signIn = (otp: string) => post('/sign-in/email-otp', { email: EMAIL, otp });
  return { issueCode, signIn };
}

function wrongCode(code: string): string {
  return code === '000000' ? '111111' : '000000';
}

describe('wrong-code attempts on one sign-in code', () => {
  test('the right code signs in with the hashed code storage', async () => {
    const { issueCode, signIn } = authWithOpenKeyCodes();
    const code = await issueCode();
    expect((await signIn(code)).status).toBe(200);
  });

  test('the fourth wrong code is refused and the code then stops working', async () => {
    const { issueCode, signIn } = authWithOpenKeyCodes();
    const code = await issueCode();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const refused = await signIn(wrongCode(code));
      expect(refused.status).toBe(400);
      expect((await refused.json()).code).toBe('INVALID_OTP');
    }
    const fourth = await signIn(wrongCode(code));
    expect(fourth.status).toBe(403);
    expect((await fourth.json()).code).toBe('TOO_MANY_ATTEMPTS');
    expect((await signIn(code)).status).not.toBe(200);
  });

  test('after three wrong codes the right code is refused', async () => {
    const { issueCode, signIn } = authWithOpenKeyCodes();
    const code = await issueCode();
    for (let attempt = 0; attempt < 3; attempt += 1) expect((await signIn(wrongCode(code))).status).toBe(400);
    const right = await signIn(code);
    expect(right.status).toBe(403);
    expect((await right.json()).code).toBe('TOO_MANY_ATTEMPTS');
  });
});
