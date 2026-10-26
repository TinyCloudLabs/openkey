# Web session lifetime

An OpenKey web sign-in session lasts 7 days. Using it after it is a day old extends it by 7 days from that use, so a session that is used regularly keeps going.

A web session ends at most 30 days after the sign-in that created it, however often it is used. The limit is `WEB_SESSION_ABSOLUTE_CAP_SECONDS` in `apps/api/src/services/session-cap.ts`, applied by a Better Auth `databaseHooks.session.update.before` hook in `apps/api/src/auth.ts`.

- A refresh moves the session's expiry to 7 days from now, or to 30 days after the session was created, whichever is earlier.
- A session that is already more than 30 days old is not extended. Its expiry is set to the 30-day mark, which has passed, so the next use finds it expired and it is removed like any expired session. The use that finds it still gets its response, and the cookie is not given a positive lifetime.
- Signing in again creates a new session with a new creation time, so it has its own 7 days and its own 30 days.
- The cookie's lifetime follows the session on `/api/auth/get-session`: a young session's cookie has the usual 7 days, and a session close to its cap has a cookie that ends with it. On every other route, including the routes that require a session (such as `/api/account`), the database row decides: the session's expiry is capped the same way there, but the response sets no new cookie.

Sessions created before this applied are covered too: the first refresh after it applies cuts a session older than 30 days to its 30-day mark.

The hook reads the session being refreshed from Better Auth's request context (`context.context.session`), because the update itself carries only the changed fields. If that session or its creation time is missing, the cap cannot be applied, so the session is ended: its expiry is set to now and `session_cap_unapplied` is logged. The update is not refused, because a refused update makes `/api/auth/get-session` answer 401 and the routes that require a session answer 500 while the row stays; an ended session is a plain "not signed in" for every caller. A change in Better Auth that hides the creation time therefore ends sessions at their next refresh and does not extend them without a cap. The real-auth test `session-cap-web.test.ts` fails first.

The session cookie cache must stay off unless the cap is applied there too. The cap runs on the database refresh; a cookie cache answers from the cookie and refreshes its own copy, which this hook does not see. `session-cap-web.test.ts` checks that `session.cookieCache` is not enabled.
