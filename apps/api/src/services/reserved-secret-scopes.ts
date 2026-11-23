// The keys of the secrets space that belong to TinyChat's bot history, and the check the secrets list, write and
// delete use to leave them alone.
//
// Source of truth: `@tinycloud/sdk-services` 3.14.0-beta.17, `src/secrets/paths.ts` (shipped as `dist/index.js`):
// `BOT_HISTORY_SCOPE`, `BOT_HISTORY_KEY_PATH` (exported) and the canonical form in `canonicalizeSecretScope`.
// `apps/api` depends on node-sdk 2.11.0, whose sdk-services has the same canonical form but no bot-history scope
// or key constant, so the values are copied here and `reserved-secret-scopes.test.ts` pins the literals. A change
// to the SDK's values needs the same change here.
const SECRET_KEY_PREFIX = 'secrets/';
const SCOPED_SECRET_KEY_PREFIX = 'secrets/scoped/';

export const BOT_HISTORY_SCOPE = 'tinychat-bot-history';
export const BOT_HISTORY_KEY_PATH = `${SCOPED_SECRET_KEY_PREFIX}${BOT_HISTORY_SCOPE}/bot-history`;

/** A scope in the SDK's canonical form: trimmed, lowercase, every other character a `-`, runs of `-` collapsed, none at either end. */
export function canonicalSecretScope(scope: string): string {
  return scope
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * True for a vault key (`secrets/...`) in the bot-history scope or beneath it, in any spelling the SDK reads as
 * that scope (`Tinychat-Bot-History`, `TINYCHAT_BOT HISTORY`).
 */
export function isReservedSecretKey(key: string): boolean {
  const [root, scoped, scope] = key.split('/');
  return (
    `${root}/` === SECRET_KEY_PREFIX &&
    scoped?.toLowerCase() === 'scoped' &&
    scope !== undefined &&
    canonicalSecretScope(scope) === BOT_HISTORY_SCOPE
  );
}
