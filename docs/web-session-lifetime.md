# Web session lifetime

An OpenKey web sign-in session lasts 7 days. Using it after it is a day old extends it by 7 days from that use, so a session that is used regularly keeps going.

A web session ends at most 30 days after the sign-in that created it, however often it is used. The limit is `WEB_SESSION_ABSOLUTE_CAP_SECONDS` in `apps/api/src/services/session-cap.ts`, applied by a Better Auth `databaseHooks.session.update.before` hook in `apps/api/src/auth.ts`.

- A refresh moves the session's expiry to 7 days from now, or to 30 days after the session was created, whichever is earlier.
- A session that is already more than 30 days old is not extended. Its expiry is set to the 30-day mark, which has passed, so the next use finds it expired and it is removed like any expired session. The use that finds it still gets its response, and the cookie is not given a positive lifetime.
- Signing in again creates a new session with a new creation time, so it has its own 7 days and its own 30 days.
- The cookie's lifetime follows the session: a young session's cookie has the usual 7 days, and a session close to its cap has a cookie that ends with it.

Sessions created before this applied are covered too: the first refresh after it applies cuts a session older than 30 days to its 30-day mark.

The hook reads the session being refreshed from Better Auth's request context (`context.context.session`), because the update itself carries only the changed fields. If that session or its creation time is missing, the refresh is refused and `session_cap_unapplied` is logged, so a change in Better Auth that hides the creation time ends sessions at refresh and does not extend them without a cap. The real-auth test `session-cap-web.test.ts` fails first.
