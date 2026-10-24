import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import { log, logOtpDeliveryFailed } from '../log';

export type SendResult = { error: { name?: unknown; statusCode?: unknown } | null };
export type EmailSender = {
  emails: { send(message: { from: string; to: string; subject: string; html: string }): Promise<SendResult> };
};

export const EMAIL_DELIVERY_FAILED_CODE = 'EMAIL_DELIVERY_FAILED';
export const EMAIL_DELIVERY_FAILED_MESSAGE = "We couldn't send your code. Please try again in a few minutes.";

/**
 * Sends the sign-in code through Resend. Better Auth awaits the sender but does not pass a
 * thrown error on to the route, so a failed send is recorded against the request and the
 * plugin's after-hook answers it with a 502.
 */
export function emailOtpDelivery(resend: EmailSender | null, isDev: boolean) {
  const failedRequests = new WeakSet<object>();

  return {
    async sendVerificationOTP(
      { email, otp }: { email: string; otp: string; type: string },
      ctx?: { request?: Request; headers?: Headers } | null,
    ): Promise<void> {
      if (!resend) {
        if (isDev) log('warn', 'otp_delivery_unconfigured');
        return;
      }

      let failure: SendResult['error'];
      try {
        ({ error: failure } = await resend.emails.send({
          from: 'OpenKey <noreply@openkey.so>',
          to: email,
          subject: 'Verify your OpenKey email',
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #1a1a1a; margin-bottom: 24px;">Your verification code</h2>
              <p style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; margin: 32px 0; text-align: center;">${otp}</p>
              <p style="color: #666; font-size: 14px;">This code expires in 5 minutes.</p>
              <p style="color: #888; font-size: 12px; margin-top: 24px;">If you didn't request this, you can safely ignore this email.</p>
            </div>
          `,
        }));
      } catch {
        failure = {};
      }
      if (!failure) return;

      logOtpDeliveryFailed(failure);
      const request = ctx?.request ?? ctx?.headers;
      if (request) failedRequests.add(request);
    },
    plugin: {
      id: 'openkey-email-otp-delivery',
      hooks: {
        after: [{
          matcher: (ctx) => ctx.path?.startsWith('/email-otp/') ?? false,
          handler: createAuthMiddleware(async (ctx) => {
            const request = ctx.request ?? ctx.headers;
            if (request && failedRequests.delete(request)) {
              throw new APIError('BAD_GATEWAY', {
                code: EMAIL_DELIVERY_FAILED_CODE,
                message: EMAIL_DELIVERY_FAILED_MESSAGE,
              });
            }
          }),
        }],
      },
    } satisfies BetterAuthPlugin,
  };
}
