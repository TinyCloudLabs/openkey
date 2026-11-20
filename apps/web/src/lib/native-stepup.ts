import type { ServerPermissionOption } from './delegate-review-selection';

/** The framed TinyCloud One apps a step-up can name, by the app id the API validates. Anything else shows its raw id. */
const STEP_UP_APP_NAMES: Record<string, string> = {
  'xyz.tinycloud.explorer': 'Explorer',
  'xyz.tinycloud.account': 'Account',
  'xyz.tinycloud.courier': 'Courier',
};

export const stepUpAppName = (appId: string): string => (Object.hasOwn(STEP_UP_APP_NAMES, appId) ? STEP_UP_APP_NAMES[appId] : appId);

/** A space the step-up reaches, as the prepare response lists it (`space` is the short name, `spaceId` the full id). */
export interface StepUpSpace { space: string; spaceId: string }

/** The prepare response of a step-up, with the fields its screen reads. */
export interface StepUpPreview {
  kind: 'STEPUP';
  client: { name: string; organization?: string | null };
  tinycloudHost: string;
  redirectScheme: string;
  stepUp: { grantId: string; appId: string };
  spaces: StepUpSpace[];
  permissionOptions: ServerPermissionOption[];
  /** The user removed this app's step-up earlier; allowing it now re-activates it. */
  reactivation?: boolean;
}

/**
 * Only an explicit `kind: 'STEPUP'` is a step-up, and only one that names its app and spaces can be shown. The kind
 * is never inferred from `stepUp` or `spaces`: a preview that carries them under another kind is not this screen's.
 */
export function isStepUpPreview<T extends { kind?: string; stepUp?: { appId?: unknown }; spaces?: unknown }>(preview: T): preview is T & StepUpPreview {
  return preview.kind === 'STEPUP' && typeof preview.stepUp?.appId === 'string' && Array.isArray(preview.spaces);
}

export interface StepUpAccessItem {
  /** `kv/applications/`: the service and path, as the permission option names them. */
  resource: string;
  /** Plain words for the actions, in the order the API lists them. */
  actions: string[];
  readOnly: boolean;
}

export interface StepUpSpaceAccess { space: string; spaceId: string; items: StepUpAccessItem[] }

export interface StepUpAccess {
  spaces: StepUpSpaceAccess[];
  /** Every capability is a read: nothing here lets the app change or delete data. */
  readOnly: boolean;
}

const READ_ACTIONS: Record<string, true> = { get: true, list: true, metadata: true, read: true, schema: true };
const ACTION_WORDS: Record<string, string> = { get: 'read', read: 'read', list: 'list', metadata: 'see details', schema: 'see structure' };

/**
 * What a step-up adds, grouped by space, from the prepare response's `spaces` and `permissionOptions`. Option keys
 * are `service\0space\0path`. The capabilities read every delegation carries is plumbing, not access, so it is not
 * listed. A step-up is all-or-nothing, so every option is shown and none can be switched off.
 */
export function stepUpAccess(spaces: readonly StepUpSpace[], options: readonly ServerPermissionOption[]): StepUpAccess {
  const groups = new Map<string, StepUpSpaceAccess>();
  for (const { space, spaceId } of spaces) groups.set(spaceId, { space, spaceId, items: [] });
  let readOnly = true;
  for (const option of options) {
    const [service = '', spaceId = '', path = ''] = option.key.split('\0');
    const short = service.slice(service.lastIndexOf('.') + 1);
    if (short === 'capabilities') continue;
    let group = groups.get(spaceId);
    if (!group) {
      group = { space: spaceId.slice(spaceId.lastIndexOf(':') + 1), spaceId, items: [] };
      groups.set(spaceId, group);
    }
    const verbs = option.actions.map((action) => action.ability.slice(action.ability.indexOf('/') + 1));
    const itemReadOnly = verbs.every((verb) => Object.hasOwn(READ_ACTIONS, verb));
    if (!itemReadOnly) readOnly = false;
    group.items.push({
      resource: path ? `${short}/${path}` : short,
      actions: [...new Set(verbs.map((verb) => (Object.hasOwn(ACTION_WORDS, verb) ? ACTION_WORDS[verb] : verb)))],
      readOnly: itemReadOnly,
    });
  }
  return { spaces: [...groups.values()], readOnly };
}
