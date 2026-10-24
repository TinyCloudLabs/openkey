import { afterAll, afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { emailOTP } from 'better-auth/plugins';
import { emailOtpDelivery, type EmailSender, type SendResult } from '../services/email-otp-delivery';

// TC-1954: no real home or tool home is touched; everything lives in one temp dir.
const sandbox = mkdtempSync('/var/tmp/tc1954.');
process.env.HOME = sandbox;
process.env.BUN_INSTALL_CACHE_DIR = sandbox;
expect(homedir().startsWith('/var/tmp/tc1954.')).toBe(true);
afterAll(() => rmSync(sandbox, { recursive: true, force: true }));

const ADDRESS = 'canary-address@example.test';
const OTP = '482913';
const PROVIDER_MESSAGE = 'canary-provider-message';
const SEND_PATH = 'https://api.test/api/auth/email-otp/send-verification-otp';

const emitted: string[] = [];
const stdoutWrite = process.stdout.write;
beforeEach(() => {
  emitted.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array) => { emitted.push(String(chunk)); return true; }) as typeof process.stdout.write;
});
afterEach(() => {
  process.stdout.write = stdoutWrite;
});

function records(): Array<Record<string, unknown>> {
  return emitted.flatMap((chunk) => chunk.split('\n')).filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
}

function senderReturning(result: unknown | (() => never)) {
  const calls: Array<{ to: string; html: string }> = [];
  const sender: EmailSender = {
    emails: {
      async send(message) {
        calls.push(message);
        if (typeof result === 'function') return (result as () => never)();
        return result as SendResult;
      },
    },
  };
  return { sender, calls };
}

function authWith(resend: EmailSender | null, isDev = false) {
  const delivery = emailOtpDelivery(resend, isDev);
  return betterAuth({
    baseURL: 'https://api.test/api/auth',
    secret: 'better-auth-secret-that-is-long-enough-for-a-runtime-test',
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    logger: { disabled: true },
    plugins: [
      emailOTP({ sendVerificationOTP: delivery.sendVerificationOTP, generateOTP: () => OTP }),
      delivery.plugin,
    ],
  });
}

function requestCode(auth: { handler(request: Request): Promise<Response> }): Promise<Response> {
  return auth.handler(new Request(SEND_PATH, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://api.test' },
    body: JSON.stringify({ email: ADDRESS, type: 'sign-in' }),
  }));
}

describe('sign-in email delivery', () => {
  test('a provider error fails the request and logs the provider error name and status only', async () => {
    const { sender, calls } = senderReturning({
      data: null,
      error: { name: 'validation_error', statusCode: 422, message: PROVIDER_MESSAGE },
    });

    const response = await requestCode(authWith(sender));
    const body = await response.json();

    expect(calls).toHaveLength(1);
    expect(response.status).toBe(502);
    expect(body.success).toBeUndefined();
    expect(body.code).toBe('EMAIL_DELIVERY_FAILED');
    expect(body.message).toBe("We couldn't send your code. Please try again in a few minutes.");

    const failure = records().filter((record) => record.event === 'otp_delivery_failed');
    expect(failure).toHaveLength(1);
    expect(failure[0]).toMatchObject({ level: 'error', error_name: 'validation_error', status: 422 });
    expect(Object.keys(failure[0]!).sort()).toEqual(['error_name', 'event', 'level', 'request_id', 'status', 'ts']);
    const everything = emitted.join('') + JSON.stringify(body);
    for (const secret of [ADDRESS, OTP, PROVIDER_MESSAGE]) expect(everything).not.toContain(secret);
  });

  test('a provider error name outside the known set is logged as other', async () => {
    const { sender } = senderReturning({
      data: null,
      error: { name: ADDRESS, statusCode: null, message: PROVIDER_MESSAGE },
    });

    const response = await requestCode(authWith(sender));

    expect(response.status).toBe(502);
    const failure = records().find((record) => record.event === 'otp_delivery_failed');
    expect(failure).toMatchObject({ error_name: 'other' });
    expect(failure).not.toHaveProperty('status');
    expect(emitted.join('')).not.toContain(ADDRESS);
  });

  test('a send that throws fails the request the same way', async () => {
    const { sender } = senderReturning(() => { throw new Error(`${PROVIDER_MESSAGE} ${ADDRESS}`); });

    const response = await requestCode(authWith(sender));

    expect(response.status).toBe(502);
    expect((await response.json()).code).toBe('EMAIL_DELIVERY_FAILED');
    expect(records().some((record) => record.event === 'otp_delivery_failed')).toBe(true);
    expect(emitted.join('')).not.toContain(ADDRESS);
    expect(emitted.join('')).not.toContain(PROVIDER_MESSAGE);
  });

  test('a successful send answers success and writes no failure log', async () => {
    const { sender, calls } = senderReturning({ data: { id: 'email-id' }, error: null });

    const response = await requestCode(authWith(sender));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ success: true });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.to).toBe(ADDRESS);
    expect(calls[0]!.html).toContain(OTP);
    expect(records().some((record) => record.event === 'otp_delivery_failed')).toBe(false);
  });

  test('without a Resend key the request answers success; development logs that delivery is unconfigured', async () => {
    const development = await requestCode(authWith(null, true));
    expect(development.status).toBe(200);
    expect(await development.json()).toEqual({ success: true });
    expect(records().filter((record) => record.event === 'otp_delivery_unconfigured')).toHaveLength(1);

    emitted.length = 0;
    const other = await requestCode(authWith(null, false));
    expect(other.status).toBe(200);
    expect(records()).toEqual([]);
  });
});
