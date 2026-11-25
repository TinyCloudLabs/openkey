// OpenKey's own account setup page (/widget/account-setup): the owner sets their account up on TinyCloud hosting.
//
// Every route is for a cookie session from an OpenKey browser origin: a bearer token or another site's Origin is
// refused before anything is read. Until the setup is built, every route answers ACCOUNT_SETUP_UNAVAILABLE and writes
// nothing.
import { Hono, type Context } from 'hono';
import { requireSession, type SessionContext } from '../middleware/session';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';

export const ACCOUNT_SETUP_UNAVAILABLE = {
  error: "Account setup isn't available here. Finish setup in TinyCloud One.",
  code: 'ACCOUNT_SETUP_UNAVAILABLE',
} as const;

export const accountSetupRouter = new Hono<SessionContext>();

accountSetupRouter.use('*', async (c, next) => {
  const rejected = rejectNonBrowserControlRequest(c);
  if (rejected) return rejected;
  await next();
});
accountSetupRouter.use('*', requireSession);

const unavailable = (c: Context<SessionContext>) => c.json(ACCOUNT_SETUP_UNAVAILABLE, 503);

accountSetupRouter.post('/prepare', unavailable);
accountSetupRouter.post('/:id/passkey', unavailable);
accountSetupRouter.post('/:id/email-code', unavailable);
accountSetupRouter.post('/:id/approve', unavailable);
accountSetupRouter.post('/:id/finish', unavailable);
