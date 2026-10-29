import {
  appKeyIdentity,
  appKeyNotGrantableStatements,
  type CapabilityReviewModel,
} from '@openkey/capability-review';

const ROUTINE_APP_KEY_ABILITIES = new Set([
  'encryption/key.create',
  'tinycloud.encryption/key.create',
  'encryption/decrypt',
  'tinycloud.encryption/decrypt',
]);

/** Return the app identity only for routine, manifest-scoped sign-in grants. */
export function routineSignInIdentity(model: CapabilityReviewModel) {
  if (
    model.protocol !== 'tinycloud-siwe-recap' ||
    model.parseWarnings.length > 0 ||
    model.requester.domainWarning ||
    model.requester.originWarning ||
    model.permissions.length === 0
  ) {
    return null;
  }

  const identity = appKeyIdentity(model);
  if (!identity) return null;

  return model.permissions.every(
    (grant) =>
      grant.family === 'app-keys' &&
      !grant.resourceService &&
      grant.path === '' &&
      grant.space.endsWith(`/apps/${identity.appId}/`) &&
      grant.actions.length > 0 &&
      grant.actions.every((action) => ROUTINE_APP_KEY_ABILITIES.has(action.ability)) &&
      appKeyNotGrantableStatements(grant).length === 0,
  )
    ? identity
    : null;
}
