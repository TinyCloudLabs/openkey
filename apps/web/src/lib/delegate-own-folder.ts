/**
 * A request that names no permissions gets only its own folder (TC-3443).
 * /api/delegate/prepare says so with `ownFolderOnly: true`, and the approval
 * screen shows this line.
 */
export const OWN_FOLDER_ONLY_LINE = "This app didn't say what it needs, so it only gets its own folder.";

/** The approval line for a /prepare response, or null when the request named its permissions. */
export function ownFolderOnlyLine(prepareResponse: { ownFolderOnly?: unknown } | null | undefined): string | null {
  return prepareResponse?.ownFolderOnly === true ? OWN_FOLDER_ONLY_LINE : null;
}
