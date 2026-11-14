// TC-2928: `/api/keys/:keyId/sign` refuses a message that grants encryption `decrypt` or `key.create` outside `apps/`
// unless the verified requesting origin is first-party (TC-2247, apps/api/src/routes/keys.ts). The sign pages check the
// same rule before offering Approve, so the owner is not asked to approve a request the server will refuse. Only a clear
// match refuses here; anything else is left to the server, which still enforces the rule.
import { isAppsKeyResource, isFirstPartyEncryptionOrigin, KEY_RESOURCE_PREFIX } from '@openkey/capability-review';
import { parseSIWE } from './siwe-parser';

/** The approved owner-facing sentence for this refusal; TC-2291 gives the server's refusal the same sentence. */
export const ENCRYPTION_OUTSIDE_APPS_TEXT = "This site can't ask for that access, so OpenKey didn't approve this request.";

/** Would the signing route refuse `message` from `origin` as an encryption grant outside `apps/`? */
export function refusesEncryptionOutsideApps(message: string, origin: string): boolean {
  if (isFirstPartyEncryptionOrigin(origin)) return false;
  return (parseSIWE(message)?.recap ?? []).some(
    ({ resource, abilities }) =>
      resource.slice(0, KEY_RESOURCE_PREFIX.length).toLowerCase() === KEY_RESOURCE_PREFIX &&
      !isAppsKeyResource(resource) &&
      abilities.some(({ action }) => {
        const name = action.slice(action.lastIndexOf('/') + 1).toLowerCase();
        return name === 'decrypt' || name === 'key.create';
      }),
  );
}
