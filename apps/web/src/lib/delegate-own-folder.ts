/**
 * A request that names no permissions gets only its own folder (TC-3443).
 * /api/delegate/prepare says so with `ownFolderOnly: true`, and the approval
 * screen shows one of these lines. `ownFolderShared: true` means the folder is
 * one other apps like it can also use (no requester origin, or a host that
 * can't be read); the server decides that, the page doesn't.
 */
export const OWN_FOLDER_ONLY_LINE = "This app didn't say what it needs, so it only gets its own folder.";
export const OWN_FOLDER_SHARED_LINE = "This app didn't say what it needs or where it's from, so it only gets a folder that other apps like it can also use.";

/** The approval line for a /prepare response, or null when the request named its permissions. */
export function ownFolderOnlyLine(prepareResponse: { ownFolderOnly?: unknown; ownFolderShared?: unknown } | null | undefined): string | null {
  if (prepareResponse?.ownFolderOnly !== true) return null;
  return prepareResponse.ownFolderShared === true ? OWN_FOLDER_SHARED_LINE : OWN_FOLDER_ONLY_LINE;
}
