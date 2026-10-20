// Decides when the CLI approval screen shows the browser-prompt how-to.
// Only the loopback sign-in has the browser local-network prompt and a
// callback that can fail over to the paste code. The device flow and the
// no-callback flow never reach the callback, and the pre-callback steps
// (POST /api/delegate, external wallet signing) run before it exists.
export interface LoopbackHintState {
  delegating: boolean;
  approvedCallback: string | null;
  deviceTransactionId: string;
  // True only while the loopback POST to the CLI is in flight.
  callbackInFlight: boolean;
  pasteCode: string;
}

export function shouldShowLoopbackHint(state: LoopbackHintState): boolean {
  return (
    state.delegating &&
    state.callbackInFlight &&
    state.approvedCallback !== null &&
    state.deviceTransactionId === '' &&
    state.pasteCode === ''
  );
}
