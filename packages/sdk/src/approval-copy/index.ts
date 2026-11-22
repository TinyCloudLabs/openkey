// Every user-facing text of the approval pages, with the table that decides which reason a reply means.
// Pure TypeScript: no DOM, no framework, no dependencies.
export { fill } from './fill';
export type { FillValues } from './fill';
export {
  APPROVAL_EXPIRY,
  CLOSE_TAB,
  CODE,
  DEVICE,
  DONE,
  FRAME,
  LOADER,
  ONE_SECRET,
  POPUP_WINDOW,
  REVOKE_REVIEW,
  SIGN_IN,
  STOP_PARTS,
  TAB_KEPT_OPEN,
  codeDestinationWord,
} from './strings';
export type { CodeDestination } from './strings';
export { KNOWN_REPLY_CODES, STOPS, approvalStop, safeCode, stopForReply, stopForSdkError, supportLine } from './stops';
export type { InlineLines, ReplyInput, SdkErrorOutcome, Stop, StopButton, StopContext, StopId, StopSupport, StopView } from './stops';
