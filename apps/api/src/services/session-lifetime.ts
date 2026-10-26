/**
 * Web sign-in session lengths, in seconds, shared by `auth.ts` (`session.expiresIn`
 * and `session.updateAge`) and the code that extends a session on an MCP refresh.
 * The 30-day limit is `WEB_SESSION_ABSOLUTE_CAP_SECONDS` in `session-cap.ts`.
 */

import { WEB_SESSION_ABSOLUTE_CAP_SECONDS } from './session-cap';

/** How long a web session lasts from sign-in and from each renewal (`session.expiresIn`). */
export const SESSION_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 7;

/** How old a session must be before a web use renews it (`session.updateAge`). */
export const SESSION_UPDATE_AGE_SECONDS = 60 * 60 * 24;

/**
 * A new MCP connection needs a sign-in younger than this (the 30-day cap minus a
 * 7-day margin, so 23 days). A connection can be extended only up to the cap after
 * sign-in, so approving one on an older sign-in would leave it less than a week.
 */
export const MCP_AUTHORIZE_MAX_SESSION_AGE_SECONDS = WEB_SESSION_ABSOLUTE_CAP_SECONDS - 7 * 60 * 60 * 24;
