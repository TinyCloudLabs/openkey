import {
  grantReachesSecretDataOrDecryption,
  sensitiveCallout,
  type CapabilityGrant,
  type CapabilityReviewModel,
} from '@openkey/capability-review';

const READ_VERBS = new Set(['get', 'list', 'read', 'peek', 'metadata']);
const WRITE_VERBS = new Set(['put', 'post', 'write', 'delete', 'del', 'update']);
const OWN_DATA_FAMILIES = new Set<CapabilityGrant['family']>([
  'own-app-data', 'public-data', 'bootstrap-kv', 'bootstrap-sql', 'bootstrap-capabilities', 'bootstrap-delegation',
]);

const verbOf = (ability: string) => ability.slice(ability.indexOf('/') + 1);

export interface NativeAccessSummary {
  /** One plain sentence about what the app will be able to do. */
  sentence: string;
  /** Extra lines that must not be hidden behind Details: sensitive or out-of-scope access. */
  warnings: string[];
}

/**
 * Plain-language summary of the grants currently selected. It is derived from
 * the verified capability model, never from caller metadata, and stays
 * conservative: anything beyond reading and saving the app's own data is
 * called out and left to the Details list.
 */
export function nativeAccessSummary(
  model: CapabilityReviewModel,
  selection: ReadonlySet<string>,
  appName: string,
): NativeAccessSummary {
  const selected = model.permissions.flatMap((grant) => {
    const actions = grant.actions.filter((action) => selection.has(action.id));
    return actions.length > 0 ? [{ ...grant, actions }] : [];
  });

  let reads = false;
  let writes = false;
  let other = false;
  for (const grant of selected) {
    if (grant.family === 'bootstrap-capabilities') continue;
    for (const action of grant.actions) {
      const verb = verbOf(action.ability);
      if (READ_VERBS.has(verb)) reads = true;
      else if (WRITE_VERBS.has(verb)) writes = true;
      else other = true;
    }
  }

  const verbs = reads && writes ? 'read and save' : reads ? 'read' : writes ? 'save' : null;
  const sentence = verbs
    ? `${appName} will be able to ${verbs} your ${appName} data.`
    : `${appName} will be able to use your TinyCloud space.`;

  const warnings: string[] = [];
  const sensitive = selected.filter(grantReachesSecretDataOrDecryption).length;
  if (sensitive > 0) warnings.push(sensitiveCallout(sensitive));
  else if (other || selected.some((grant) => !OWN_DATA_FAMILIES.has(grant.family))) {
    warnings.push(`It also asks for access beyond ${appName}'s own data. Check Details before allowing.`);
  }
  return { sentence, warnings };
}
