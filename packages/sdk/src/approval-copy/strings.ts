// Every user-facing text of the approval pages that is not a reason for stopping (those are in stops.ts).
// Pure data: no DOM, no framework. `{name}` marks a value the page fills in with `fill()`.

/** The frame every approval page shares. */
export const FRAME = {
  brand: 'OpenKey',
  progress: 'Progress',
  steps: {
    signIn: 'Sign in',
    review: 'Review',
    last: {
      agent: 'Back to your agent',
      terminal: 'Back to your terminal',
      code: 'Paste the code',
    },
  },
  /** The step where the page stopped: `{step}` is the step's own label. */
  stopped: '{step} · stopped',
  signOut: 'Sign out',
  footer: 'Protected by TEE hardware security',
} as const;

/** The loader, from first paint until there is something to read. */
export const LOADER = {
  heading: 'Opening your request',
  phases: {
    link: 'Checking the link',
    session: 'Checking your OpenKey account',
    keys: 'Loading your keys',
    prepare: 'Preparing the request',
    request: 'Loading the request',
  },
} as const;

export const CLOSE_TAB = 'Close this tab';
export const TAB_KEPT_OPEN = 'Your browser kept this tab open. Close it from your browser.';

/** The sign-in card and the states that replace it. `{provider}` is Google or Apple. */
export const SIGN_IN = {
  eyebrow: 'Access request',
  heading: 'Sign in to review this request',
  line: 'Signing in doesn’t approve anything. You review the request next.',
  email: 'Continue with email',
  google: 'Continue with Google',
  apple: 'Continue with Apple',
  passkey: 'Use a passkey instead',
  /** The label of a social button while its window is opening. */
  connecting: 'Connecting to {provider}…',
  passkeyBusy: 'Signing in…',
  newToOpenKey: 'New to OpenKey?',
  createAccount: 'Create an account',
  recover: 'Recover account',
  /** Prepared sign-in and revoke only. */
  cancel: 'Cancel this request',
  popupOpen: {
    heading: 'Finish signing in with {provider}',
    line: '{provider} opened in a small window. This page is waiting and will carry on by itself when you’re done.',
    status: 'Waiting for {provider}…',
    show: 'Show the {provider} window again',
    other: 'Sign in another way',
  },
  popupBlocked: 'Your browser blocked the {provider} sign-in window. Allow popups, then try again.',
  popupCancelled: '{provider} sign-in was cancelled. Your request is still here.',
  /** Prepared sign-in and revoke, after signing in inside the same tab. */
  signedIn: {
    heading: 'You’re signed in',
    line: 'Carry on to review the request. Nothing is approved until you say so.',
    review: 'Review the request',
    cancel: 'Cancel this request',
  },
  /** After a 401 on prepare or approve. */
  signedOutPartway: {
    heading: 'You were signed out',
    line: 'Your OpenKey session ended before the approval went through. Sign in again and you’ll come straight back to this request.',
  },
} as const;

/** Pages that end with nothing left to copy. `{requester}` is the requesting app or command. */
export const DONE = {
  approved: {
    heading: 'Approved. Go back to your agent.',
    line: 'Your approval was sent to {requester}. There is nothing to copy. If your agent is still waiting, tell it you approved.',
  },
  declined: {
    heading: 'Declined. Nothing was shared.',
    line: '{requester} has been told no. If that was a mistake, ask your agent to send the request again.',
  },
  cancelled: {
    heading: 'Cancelled. Nothing was approved.',
    line: 'To try again, run the command again.',
  },
  signedIn: {
    heading: 'Signed in. Go back to your terminal.',
    line: '{requester} has your sign-in. There is nothing to copy.',
  },
  signed: {
    heading: 'Signed. Go back to your terminal.',
    line: 'Your terminal has your signature and will finish revoking the permission.',
  },
  receipt: {
    access: 'Access',
    ends: 'Ends',
    signedWith: 'Signed with',
    sentTo: 'Sent to',
    permission: 'Permission',
    permissions: { one: '{n} permission', other: '{n} permissions' },
    inSpace: '{permissions} in {space}',
    /** Loopback callback · registered app callback · device link · short link. */
    sentToValues: {
      terminalThisDevice: 'Your terminal, this device',
      host: '{host}',
      terminalThatShowedCode: 'The terminal that showed the code',
      requester: '{requester}',
    },
  },
} as const;

/** Where a pasted code goes. Only the terminal has wording today. */
export type CodeDestination = 'terminal' | 'tinycloud-one';

/** The word the code page puts in place of `{destination}`. */
export function codeDestinationWord(destination: CodeDestination = 'terminal'): string {
  // The tinycloud.one wording is added with that copy; until then both read as a terminal.
  void destination;
  return 'terminal';
}

/** The code page. Fill `{destination}` with `codeDestinationWord()`. */
export const CODE = {
  eyebrow: 'Approved · one step left',
  eyebrowRevoke: 'Signed · one step left',
  headingShort: 'Paste this code into your {destination}',
  headingFull: 'Paste this into your {destination}',
  line: '{requester} is waiting for it.',
  lineNotReached: 'OpenKey couldn’t reach your {destination} by itself. Paste this code there instead.',
  lineNoShortCode: 'OpenKey couldn’t make a short code, so here is the full one. It works the same way.',
  lineRevoke: 'Your {destination} needs it to finish revoking the permission.',
  hintShort: 'Click the code to copy',
  hintShortPhone: 'Tap the code to copy',
  hintFull: 'Click to copy all {n} characters',
  hintCopied: 'Copied. Now paste it in your {destination}.',
  timer: 'Valid for {time}',
  timerNoClock: 'Use within 5 minutes',
  worksOnce: 'Works once',
  copy: 'Copy code',
  copyFull: 'Copy full code',
  copied: 'Copied',
  warning: 'Only paste it into a {destination} you started yourself. Nobody from OpenKey or TinyCloud will ask for it.',
  warningShort: 'Only paste it into a {destination} you started yourself.',
  useFull: 'Use the full delegation code instead',
  copyFailed: 'Couldn’t copy. Select the code and copy it by hand.',
  expired: {
    eyebrow: 'Approved, but not delivered',
    heading: 'This code ran out of time',
    line: 'Codes last 5 minutes and this one wasn’t used, so no access was handed over. Run the command again to get a new request.',
    box: 'Expired',
  },
} as const;

/** /device. */
export const DEVICE = {
  eyebrow: 'Sign-in request from a device',
  headingCode: 'Does your terminal show this code?',
  codeLabel: 'Code {first}, {second}',
  asksLabel: 'What it asks for',
  yesSignedOut: 'Yes, it matches. Sign in to review',
  yesSignedIn: 'Yes, it matches. Review the request',
  no: 'No, it’s different',
  advanced: 'Advanced details',
  noHeading: 'Stopped. Nothing was approved.',
  noLine: 'The code here didn’t match your terminal, so this request may have been started by someone else. It has been left unanswered and will expire by itself.',
  noClose: CLOSE_TAB,
  noMisread: 'I misread it, show the code again',
  headingNoCode: 'Enter the code from your terminal',
  lineNoCode: 'Eight letters and numbers. Capitals don’t matter.',
  find: 'Find the request',
  lookingUp: 'Looking for the request…',
  notFound: 'No request has that code. Check the terminal, or run the command again for a new one.',
  loadFailed: 'Couldn’t load this request. OpenKey’s server didn’t answer. Nothing has changed.',
  tryAgain: 'Try again',
} as const;

/** The small Google or Apple window. `{provider}` is Google or Apple. */
export const POPUP_WINDOW = {
  working: {
    connecting: 'Connecting to {provider}…',
    completing: 'Completing sign-in…',
    creating: 'Creating your account…',
    line: 'This window will close by itself.',
  },
  done: {
    heading: 'Signed in',
    line: 'This window will close. Go back to the other one.',
  },
  failed: { heading: '{provider} sign-in didn’t finish' },
  lost: {
    heading: 'This window lost its link to OpenKey',
    line: 'Close it and press the sign-in button again.',
  },
  close: 'Close this window',
} as const;

/** The revoke page. Its own words are kept; the eyebrow and one row are new. */
export const REVOKE_REVIEW = {
  eyebrow: 'Request from your terminal',
  heading: 'Revoke this permission',
  warning: 'This cannot be undone.',
  fullId: 'Full permission ID',
  matchId: 'Match the full permission ID with the one shown by your CLI.',
  rows: {
    owner: 'Owner address',
    signingWith: 'Signing with',
    expires: 'Signature expires',
  },
  fold: 'Exact message to sign',
  cancel: 'Cancel',
  revoke: 'Revoke',
} as const;

/** The parts a stop page is built from. */
export const STOP_PARTS = {
  /** The marker above the heading. S13 reads `markerNew`. */
  marker: 'Nothing was approved',
  markerNew: 'Nothing new was approved',
  linkAsks: 'The link asks for',
  accountHas: 'This account has',
  youChose: 'You chose',
  found: 'What OpenKey found',
  supportLabel: 'Details for support',
  copy: 'Copy',
  copied: 'Copied',
  buttons: {
    close: CLOSE_TAB,
    tryAgain: 'Try again',
    copyDetails: 'Copy details for the developer',
    copiedDetails: 'Copied',
    switchAccount: 'Switch account',
    linkWallet: 'Link wallet {short}',
    chooseAnotherKey: 'Choose another key',
    startAgain: 'Start again from the app',
    enterCode: 'Enter the code',
  },
} as const;
