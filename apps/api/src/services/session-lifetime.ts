/**
 * Web sign-in session lengths, in seconds, shared by `auth.ts` (`session.expiresIn`
 * and `session.updateAge`) and the code that extends a session on an MCP refresh.
 * The 30-day limit is `WEB_SESSION_ABSOLUTE_CAP_SECONDS` in `session-cap.ts`.
 */

/** How long a web session lasts from sign-in and from each renewal (`session.expiresIn`). */
export const SESSION_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 7;

/** How old a session must be before a web use renews it (`session.updateAge`). */
export const SESSION_UPDATE_AGE_SECONDS = 60 * 60 * 24;
