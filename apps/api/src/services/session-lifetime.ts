/**
 * Web sign-in session lengths, in seconds, shared by the code that extends a
 * session on an MCP refresh. `session.expiresIn` and `session.updateAge` in
 * `auth.ts` are these values; a test compares them with the live auth options.
 */

/** How long a web session lasts from sign-in and from each renewal (`session.expiresIn`). */
export const SESSION_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 7;

/** How old a session must be before a web use renews it (`session.updateAge`). */
export const SESSION_UPDATE_AGE_SECONDS = 60 * 60 * 24;

/**
 * The most a session may live, counted from the sign-in that created it. The
 * one definition of the 30-day limit: the web cap (`services/session-cap.ts`,
 * #362) takes it from here, or this re-exports it once that file lands.
 */
export const WEB_SESSION_ABSOLUTE_CAP_SECONDS = 60 * 60 * 24 * 30;
